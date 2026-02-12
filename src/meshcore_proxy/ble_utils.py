"""Linux BLE utilities for MeshCore proxy.

Provides USB adapter auto-detection, GATT capability testing, MeshCore device
scanning with RSSI sorting and name pinning, HCI adapter reset for stale
BlueZ state recovery, and device blacklisting.

These features are critical for headless SBC deployments (Raspberry Pi, Orange Pi)
where BLE adapters may fail silently and BlueZ can enter stale states.
"""

import glob
import logging
import os
import subprocess
from typing import Optional

from bleak import BleakScanner

logger = logging.getLogger(__name__)

NUS_SERVICE = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"

SCAN_TIMEOUT = 15
INPROGRESS_RESET_THRESHOLD = 3
NOTIFY_FAIL_THRESHOLD = 2


def find_usb_bt_adapters() -> list[str]:
    """Find all USB Bluetooth adapters (not built-in UART ones).

    Scans sysfs for hciX devices with DRIVER=btusb, which identifies
    USB-connected Bluetooth adapters. Built-in UART adapters (e.g., BCM43438
    on Raspberry Pi) use different drivers and are excluded.

    Returns list of hciX names (e.g., ['hci0', 'hci1']).
    """
    adapters = []
    for hci_path in sorted(glob.glob("/sys/class/bluetooth/hci*")):
        name = os.path.basename(hci_path)
        if ":" in name:
            continue  # skip sub-devices like hci1:64
        uevent_path = os.path.join(hci_path, "device", "uevent")
        try:
            with open(uevent_path) as f:
                uevent = f.read()
            if "DRIVER=btusb" in uevent:
                adapters.append(name)
                logger.info("Found USB BT adapter: %s", name)
        except (FileNotFoundError, PermissionError):
            continue
    return adapters


async def find_gatt_capable_adapter(adapters: list[str]) -> Optional[str]:
    """Test each adapter for GATT capability with a short BLE scan.

    Returns the first adapter that can successfully perform a BLE scan,
    or None if no adapter passes.
    """
    for name in adapters:
        logger.info("Testing GATT capability of %s...", name)
        try:
            devices = await BleakScanner.discover(timeout=5, adapter=name)
            logger.info("GATT check passed: %s discovered %d device(s)", name, len(devices))
            return name
        except Exception as e:
            logger.warning("GATT check failed for %s: %s", name, e)
    return None


async def scan_for_meshcore(
    adapter: str,
    timeout: int = SCAN_TIMEOUT,
    blacklist: Optional[set[str]] = None,
    preferred_name: Optional[str] = None,
) -> tuple[Optional[str], Optional[str]]:
    """Scan for MeshCore BLE devices.

    Returns (address, name) of the best candidate, or (None, None).
    If preferred_name is set, only that device is returned.
    Otherwise picks strongest RSSI, skipping blacklisted addresses.
    """
    logger.info("Scanning for MeshCore devices (%ds timeout)...", timeout)
    devices = await BleakScanner.discover(
        timeout=timeout, adapter=adapter, return_adv=True
    )
    meshcore_devices = []
    for d, adv in devices.values():
        name = d.name or adv.local_name or ""
        if name.startswith("MeshCore"):
            if blacklist and d.address in blacklist:
                logger.info("  Skipping blacklisted: %s (%s) RSSI=%s", name, d.address, adv.rssi)
                continue
            meshcore_devices.append((d.address, name, adv.rssi))
            logger.info("  Found: %s (%s) RSSI=%s", name, d.address, adv.rssi)

    if not meshcore_devices:
        logger.warning("No MeshCore devices found")
        return None, None

    # If preferred name is set, filter to that device only
    if preferred_name:
        preferred = [d for d in meshcore_devices if d[1] == preferred_name]
        if preferred:
            addr, name, rssi = preferred[0]
            logger.info("Selected (preferred): %s (%s) RSSI=%s", name, addr, rssi)
            return addr, name
        logger.warning(
            'Preferred device "%s" not found, available: %s',
            preferred_name,
            [d[1] for d in meshcore_devices],
        )
        return None, None

    # Sort by RSSI (strongest first) and return best candidate
    meshcore_devices.sort(key=lambda x: x[2], reverse=True)
    addr, name, rssi = meshcore_devices[0]
    logger.info("Selected: %s (%s) RSSI=%s", name, addr, rssi)
    return addr, name


def reset_hci_adapter(adapter: str) -> bool:
    """Reset an HCI adapter to clear stale BlueZ state.

    This is needed when BlueZ enters an InProgress loop where
    BLE scan/connect operations fail with 'InProgress' errors
    repeatedly. A reset clears the internal state machine.
    """
    logger.warning("Resetting %s to clear stale BlueZ state...", adapter)
    try:
        subprocess.run(["hciconfig", adapter, "reset"], timeout=5, check=True)
        logger.info("%s reset OK, waiting for re-init...", adapter)
        return True
    except Exception as e:
        logger.error("%s reset failed: %s", adapter, e)
        return False
