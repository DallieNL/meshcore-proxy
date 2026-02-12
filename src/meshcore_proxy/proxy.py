"""MeshCore TCP Proxy implementation.

Supports Serial, BLE (via meshcore library), and direct BLE (via raw bleak)
connections. Direct BLE mode adds auto-scanning, adapter detection, device
name pinning, HCI reset recovery, and device blacklisting for headless
SBC deployments.
"""

import asyncio
import json
import logging
import os
import struct
import sys
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

# bleak and ble_utils are optional — only needed for direct BLE mode
try:
    from bleak import BleakClient, BleakScanner

    from .ble_utils import (
        INPROGRESS_RESET_THRESHOLD,
        NOTIFY_FAIL_THRESHOLD,
        find_gatt_capable_adapter,
        find_usb_bt_adapters,
        reset_hci_adapter,
        scan_for_meshcore,
    )

    HAS_BLEAK = True
except ImportError:
    HAS_BLEAK = False
    BleakClient = None
    BleakScanner = None
    INPROGRESS_RESET_THRESHOLD = 3
    NOTIFY_FAIL_THRESHOLD = 2
from .decoder import decode_command, decode_response, format_decoded

logger = logging.getLogger(__name__)

# Try importing meshcore for serial and library-based BLE
try:
    from meshcore.serial_cx import SerialConnection
    from meshcore.packets import PacketType
except ImportError:
    # Fall back to submodule path for development
    submodule_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "..", "meshcore_py", "src"
    )
    sys.path.insert(0, os.path.abspath(submodule_path))
    from meshcore.serial_cx import SerialConnection
    from meshcore.packets import PacketType

# BLEConnection is optional — direct BLE mode doesn't need it
try:
    from meshcore.ble_cx import BLEConnection
except ImportError:
    BLEConnection = None

# Nordic UART Service UUIDs
NUS_SERVICE = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
NUS_TX = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"  # Notify (radio → proxy)
NUS_RX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"  # Write  (proxy → radio)

HEALTH_CHECK_INTERVAL = 30
RECONNECT_BASE_DELAY = 5
RECONNECT_MAX_DELAY = 120


class EventLogLevel(Enum):
    """Event logging verbosity levels."""

    OFF = "off"
    SUMMARY = "summary"
    VERBOSE = "verbose"


# Map response packet types to human-readable names for logging
RESPONSE_TYPE_NAMES = {v.value: v.name for v in PacketType}

# Map command codes to human-readable names
# These are the first byte of outgoing packets (client -> radio)
COMMAND_TYPE_NAMES = {
    0x01: "CMD_APPSTART",
    0x02: "CMD_SEND_MSG",
    0x03: "CMD_SEND_CHAN_MSG",
    0x04: "CMD_GET_CONTACTS",
    0x05: "CMD_GET_TIME",
    0x06: "CMD_SET_TIME",
    0x07: "CMD_SEND_ADVERT",
    0x08: "CMD_SET_NAME",
    0x09: "CMD_UPDATE_CONTACT",
    0x0A: "CMD_GET_MSG",
    0x0B: "CMD_SET_RADIO",
    0x0C: "CMD_SET_TX_POWER",
    0x0D: "CMD_RESET_PATH",
    0x0E: "CMD_SET_COORDS",
    0x0F: "CMD_REMOVE_CONTACT",
    0x10: "CMD_SHARE_CONTACT",
    0x11: "CMD_EXPORT_CONTACT",
    0x12: "CMD_IMPORT_CONTACT",
    0x13: "CMD_REBOOT",
    0x14: "CMD_GET_BATTERY",
    0x15: "CMD_SET_TUNING",
    0x16: "CMD_DEVICE_QUERY",
    0x17: "CMD_EXPORT_PRIVATE_KEY",
    0x18: "CMD_IMPORT_PRIVATE_KEY",
    0x1A: "CMD_SEND_LOGIN",
    0x1B: "CMD_SEND_STATUS_REQ",
    0x1D: "CMD_SEND_LOGOUT",
    0x1F: "CMD_GET_CHANNEL",
    0x20: "CMD_SET_CHANNEL",
    0x21: "CMD_SIGN_START",
    0x22: "CMD_SIGN_DATA",
    0x23: "CMD_SIGN_FINISH",
    0x24: "CMD_SEND_TRACE",
    0x25: "CMD_SET_DEVICE_PIN",
    0x26: "CMD_SET_OTHER_PARAMS",
    0x27: "CMD_GET_TELEMETRY",
    0x28: "CMD_GET_CUSTOM_VARS",
    0x29: "CMD_SET_CUSTOM_VAR",
    0x32: "CMD_BINARY_REQ",
    0x33: "CMD_FACTORY_RESET",
    0x34: "CMD_PATH_DISCOVERY",
    0x36: "CMD_SET_FLOOD_SCOPE",
    0x37: "CMD_SEND_CONTROL_DATA",
    0x38: "CMD_GET_STATS",
    0x39: "CMD_REQUEST_ADVERT",
}


@dataclass
class TCPClient:
    """Represents a connected TCP client."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    addr: tuple

    # Frame parsing state (same as meshcore_py TCP connection)
    frame_started: bool = False
    frame_size: int = 0
    header: bytes = b""
    inframe: bytes = b""


class MeshCoreProxy:
    """TCP proxy for MeshCore companion radios.

    Connects to a MeshCore radio via Serial or BLE and exposes it
    to remote clients via TCP. Supports three connection modes:

    1. Serial: via meshcore SerialConnection (--serial /dev/ttyUSB0)
    2. BLE (library): via meshcore BLEConnection (--ble AA:BB:CC:DD:EE:FF)
    3. BLE (direct): via raw bleak with auto-scan (--ble auto)

    Direct BLE mode adds resilience features for headless deployments:
    - Auto-scan for MeshCore devices by RSSI
    - Device name pinning (--ble-name MeshCore-MyDevice)
    - USB Bluetooth adapter auto-detection
    - HCI reset on stale BlueZ InProgress loops
    - Device blacklisting after repeated notify failures
    - Periodic health checks
    """

    def __init__(
        self,
        serial_port: Optional[str] = None,
        ble_address: Optional[str] = None,
        baud_rate: int = 115200,
        ble_pin: str = "123456",
        ble_name: Optional[str] = None,
        ble_adapter: str = "auto",
        tcp_host: str = "0.0.0.0",
        tcp_port: int = 5000,
        event_log_level: EventLogLevel = EventLogLevel.OFF,
        event_log_json: bool = False,
    ):
        self.serial_port = serial_port
        self.ble_address = ble_address
        self.baud_rate = baud_rate
        self.ble_pin = ble_pin
        self.ble_name = ble_name
        self.ble_adapter = ble_adapter
        self.tcp_host = tcp_host
        self.tcp_port = tcp_port
        self.event_log_level = event_log_level
        self.event_log_json = event_log_json

        # Radio connection state
        self._radio_connection: Optional[Any] = None
        self._ble_client: Optional[BleakClient] = None  # direct BLE mode
        self._tcp_server: Optional[asyncio.Server] = None
        self._clients: dict[tuple, TCPClient] = {}
        self._is_ble = False
        self._is_direct_ble = False  # True = raw bleak, False = meshcore BLEConnection
        self._is_running = False
        self._radio_connected = False

        # BLE resilience state (direct mode only)
        self._resolved_adapter: Optional[str] = None
        self._blacklisted_addrs: set[str] = set()
        self._inprogress_count = 0
        self._notify_fail_count = 0
        self._last_ble_rx = 0.0

    # ── Adapter Resolution ──────────────────────────────────────────────

    async def _resolve_adapter(self) -> str:
        """Resolve BLE adapter, auto-detecting USB adapters if needed."""
        if self._resolved_adapter:
            return self._resolved_adapter

        if self.ble_adapter != "auto":
            self._resolved_adapter = self.ble_adapter
            return self._resolved_adapter

        usb_adapters = find_usb_bt_adapters()
        if not usb_adapters:
            # Fall back to hci0 on non-Linux or when sysfs isn't available
            logger.warning("No USB BT adapter found via sysfs, falling back to hci0")
            self._resolved_adapter = "hci0"
            return self._resolved_adapter

        adapter = await find_gatt_capable_adapter(usb_adapters)
        if not adapter:
            raise ConnectionError(
                f"No GATT-capable adapter found among: {usb_adapters}"
            )
        self._resolved_adapter = adapter
        return self._resolved_adapter

    # ── Event Logging ───────────────────────────────────────────────────

    def _log_event(
        self,
        direction: str,
        packet_type: int,
        payload: bytes,
    ) -> None:
        """Log a MeshCore event based on configured verbosity."""
        if self.event_log_level == EventLogLevel.OFF:
            return

        if direction == "TO_RADIO":
            type_name = COMMAND_TYPE_NAMES.get(
                packet_type, f"CMD_UNKNOWN(0x{packet_type:02x})"
            )
            decoded = decode_command(packet_type, payload)
        else:
            type_name = RESPONSE_TYPE_NAMES.get(
                packet_type, f"RESP_UNKNOWN(0x{packet_type:02x})"
            )
            decoded = decode_response(packet_type, payload)

        decoded_str = format_decoded(decoded) if decoded else ""

        if self.event_log_json:
            log_data = {
                "direction": direction,
                "packet_type": type_name,
                "packet_type_raw": packet_type,
            }
            if decoded:
                log_data["decoded"] = decoded
            if self.event_log_level == EventLogLevel.VERBOSE:
                log_data["payload_hex"] = payload.hex()
                log_data["payload_len"] = len(payload)
            print(json.dumps(log_data), flush=True)
        else:
            arrow = "->" if direction == "TO_RADIO" else "<-"
            if self.event_log_level == EventLogLevel.SUMMARY:
                if decoded_str:
                    print(f"{arrow} {type_name}: {decoded_str}", flush=True)
                else:
                    print(f"{arrow} {type_name}", flush=True)
            else:  # VERBOSE
                if decoded_str:
                    print(f"{arrow} {type_name}: {decoded_str}", flush=True)
                    print(
                        f"   [{len(payload)} bytes]: {payload.hex()}", flush=True
                    )
                else:
                    print(
                        f"{arrow} {type_name} [{len(payload)} bytes]: {payload.hex()}",
                        flush=True,
                    )

    # ── TCP Framing ─────────────────────────────────────────────────────

    def _frame_payload(self, payload: bytes) -> bytes:
        """Frame a payload for TCP transmission (0x3c + 2-byte size + payload)."""
        size = len(payload)
        return b"\x3c" + size.to_bytes(2, byteorder="little") + payload

    def _parse_tcp_frame(self, client: TCPClient, data: bytes) -> list[bytes]:
        """Parse incoming TCP data into complete frames."""
        payloads = []
        offset = 0

        while offset < len(data):
            remaining = data[offset:]

            if not client.frame_started:
                header_needed = 3 - len(client.header)
                if len(remaining) >= header_needed:
                    client.header = client.header + remaining[:header_needed]
                    client.frame_started = True
                    client.frame_size = int.from_bytes(
                        client.header[1:], byteorder="little"
                    )
                    offset += header_needed
                else:
                    client.header = client.header + remaining
                    break
            else:
                frame_needed = client.frame_size - len(client.inframe)
                if len(remaining) >= frame_needed:
                    client.inframe = client.inframe + remaining[:frame_needed]
                    payloads.append(client.inframe)
                    client.frame_started = False
                    client.header = b""
                    client.inframe = b""
                    offset += frame_needed
                else:
                    client.inframe = client.inframe + remaining
                    break

        return payloads

    # ── Radio RX/TX ─────────────────────────────────────────────────────

    async def _handle_radio_rx(self, payload: bytes) -> None:
        """Handle data received from the radio — forward to all TCP clients."""
        if not self._radio_connected or not payload:
            return

        self._last_ble_rx = time.monotonic()
        packet_type = payload[0] if payload else 0
        self._log_event("FROM_RADIO", packet_type, payload)

        framed = self._frame_payload(payload)
        disconnected = []

        for addr, client in self._clients.items():
            try:
                client.writer.write(framed)
                await client.writer.drain()
            except Exception as e:
                logger.warning("Failed to forward to client %s: %s", addr, e)
                disconnected.append(addr)

        for addr in disconnected:
            await self._remove_client(addr)

    def _on_ble_notify(self, sender: Any, data: bytes) -> None:
        """BLE notification callback (direct mode) — schedule async handler."""
        asyncio.get_event_loop().create_task(self._handle_radio_rx(bytes(data)))

    async def _send_to_radio(self, payload: bytes) -> None:
        """Send a payload to the radio."""
        if not self._radio_connected:
            logger.error("Radio not connected")
            return

        try:
            packet_type = payload[0] if payload else 0
            self._log_event("TO_RADIO", packet_type, payload)

            if self._is_direct_ble:
                if self._ble_client and self._ble_client.is_connected:
                    await self._ble_client.write_gatt_char(
                        NUS_RX, payload, response=True
                    )
                else:
                    raise ConnectionError("BLE client not connected")
            elif self._radio_connection:
                await self._radio_connection.send(payload)
        except Exception as e:
            logger.error("Failed to send to radio: %s", e)
            await self._handle_radio_disconnect(str(e))

    # ── TCP Client Handling ─────────────────────────────────────────────

    async def _remove_client(self, addr: tuple) -> None:
        """Remove a client and close its connection."""
        if addr in self._clients:
            client = self._clients.pop(addr)
            try:
                client.writer.close()
                await client.writer.wait_closed()
            except Exception:
                pass
            logger.info("Client disconnected: %s", addr)

    async def _handle_tcp_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a TCP client connection."""
        addr = writer.get_extra_info("peername")
        logger.info("Client connected: %s", addr)

        client = TCPClient(reader=reader, writer=writer, addr=addr)
        self._clients[addr] = client

        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break

                payloads = self._parse_tcp_frame(client, data)
                for payload in payloads:
                    await self._send_to_radio(payload)

        except asyncio.CancelledError:
            pass
        except ConnectionResetError:
            logger.debug("Client %s connection reset", addr)
        except Exception as e:
            logger.error("Error handling client %s: %s", addr, e)
        finally:
            await self._remove_client(addr)

    # ── Radio Connection ────────────────────────────────────────────────

    async def _handle_radio_disconnect(self, reason: Optional[str] = None) -> None:
        """Handle radio disconnection."""
        if self._radio_connected:
            self._radio_connected = False
            if reason:
                logger.warning("Radio disconnected: %s", reason)
            else:
                logger.warning("Radio disconnected.")

    async def _connect_radio_serial(self) -> None:
        """Connect via serial using meshcore SerialConnection."""
        logger.info("Connecting to radio via serial: %s", self.serial_port)
        self._radio_connection = SerialConnection(self.serial_port, self.baud_rate)
        self._is_ble = False
        self._is_direct_ble = False

        class ReaderAdapter:
            def __init__(self, handler: Callable):
                self._handler = handler

            async def handle_rx(self, data: bytes) -> None:
                await self._handler(data)

        self._radio_connection.set_reader(ReaderAdapter(self._handle_radio_rx))
        self._radio_connection.set_disconnect_callback(self._handle_radio_disconnect)

        result = await self._radio_connection.connect()
        if result is None:
            raise ConnectionError("Failed to connect to radio via serial")
        logger.info("Connected to radio: %s", result)
        self._radio_connected = True

    async def _connect_radio_ble_library(self) -> None:
        """Connect via BLE using meshcore BLEConnection (explicit MAC)."""
        if BLEConnection is None:
            raise ImportError("meshcore BLEConnection not available")

        logger.info("Connecting to radio via BLE (library): %s", self.ble_address)
        self._radio_connection = BLEConnection(
            address=self.ble_address,
            pin=self.ble_pin if self.ble_pin else None,
        )
        self._is_ble = True
        self._is_direct_ble = False

        class ReaderAdapter:
            def __init__(self, handler: Callable):
                self._handler = handler

            async def handle_rx(self, data: bytes) -> None:
                await self._handler(data)

        self._radio_connection.set_reader(ReaderAdapter(self._handle_radio_rx))
        self._radio_connection.set_disconnect_callback(self._handle_radio_disconnect)

        result = await self._radio_connection.connect()
        if result is None:
            raise ConnectionError("Failed to connect to radio via BLE")
        logger.info("Connected to radio: %s", result)
        self._radio_connected = True

    async def _connect_radio_ble_direct(self) -> None:
        """Connect via raw bleak with auto-scan, adapter detection, and resilience.

        This is the direct BLE mode used when --ble auto is specified.
        It bypasses meshcore's BLEConnection and manages bleak directly,
        enabling features like auto-scanning, name pinning, HCI reset,
        and device blacklisting.
        """
        if not HAS_BLEAK:
            raise ImportError(
                "bleak is required for --ble auto mode. Install with: pip install bleak"
            )
        adapter = await self._resolve_adapter()

        # Scan for device if address is not set (auto mode)
        if not self.ble_address:
            addr, name = await scan_for_meshcore(
                adapter,
                blacklist=self._blacklisted_addrs,
                preferred_name=self.ble_name,
            )
            if not addr:
                raise ConnectionError("No MeshCore device found during scan")
            self.ble_address = addr
            logger.info("Auto-resolved BLE address: %s (%s)", addr, name)

        # Disconnect previous client if any
        if self._ble_client:
            try:
                await self._ble_client.disconnect()
            except Exception:
                pass
            self._ble_client = None

        logger.info(
            "Connecting to BLE %s via %s (direct mode)...",
            self.ble_address,
            adapter,
        )
        self._ble_client = BleakClient(
            self.ble_address, timeout=20, adapter=adapter
        )
        await self._ble_client.connect()
        logger.info("BLE connected: %s", self._ble_client.is_connected)

        await self._ble_client.start_notify(NUS_TX, self._on_ble_notify)
        logger.info("BLE notifications enabled on NUS TX")

        self._is_ble = True
        self._is_direct_ble = True
        self._radio_connected = True
        self._last_ble_rx = time.monotonic()
        self._inprogress_count = 0
        self._notify_fail_count = 0

    async def _connect_radio(self) -> None:
        """Connect to the MeshCore radio using the appropriate method."""
        if self.serial_port:
            await self._connect_radio_serial()
        elif self._is_direct_ble or self.ble_address == "auto":
            self._is_direct_ble = True
            if self.ble_address == "auto":
                self.ble_address = None  # trigger scan
            await self._connect_radio_ble_direct()
        elif self.ble_address:
            await self._connect_radio_ble_library()
        else:
            raise ValueError("No connection method specified")

    # ── Health Check ────────────────────────────────────────────────────

    async def _health_check(self) -> None:
        """Periodically check BLE connection health (direct mode only)."""
        while self._is_running:
            await asyncio.sleep(HEALTH_CHECK_INTERVAL)
            if not self._is_direct_ble or not self._radio_connected:
                continue
            try:
                if self._ble_client and not self._ble_client.is_connected:
                    logger.warning("Health check: BLE client reports not connected")
                    await self._handle_radio_disconnect("health check failed")
            except Exception as e:
                logger.error("Health check error: %s", e)
                await self._handle_radio_disconnect(str(e))

    # ── TCP Server ──────────────────────────────────────────────────────

    async def _start_tcp_server(self) -> None:
        """Start the TCP server."""
        self._tcp_server = await asyncio.start_server(
            self._handle_tcp_client,
            self.tcp_host,
            self.tcp_port,
        )
        addrs = ", ".join(
            str(sock.getsockname()) for sock in self._tcp_server.sockets
        )
        logger.info("TCP server listening on %s", addrs)

    # ── Main Run Loop ───────────────────────────────────────────────────

    async def run(self) -> None:
        """Run the proxy with reconnection and resilience."""
        self._is_running = True
        conn_type = "serial" if self.serial_port else "BLE"
        conn_target = self.serial_port or self.ble_address or "auto-scan"
        logger.info("Starting MeshCore Proxy (%s: %s)...", conn_type, conn_target)

        await self._start_tcp_server()

        # Start health check for direct BLE mode
        health_task = asyncio.create_task(self._health_check())

        reconnect_delay = RECONNECT_BASE_DELAY

        try:
            while self._is_running:
                if not self._radio_connected:
                    try:
                        await self._connect_radio()
                        reconnect_delay = RECONNECT_BASE_DELAY
                    except Exception as e:
                        err_str = str(e)

                        # Handle InProgress loops (direct BLE mode)
                        if self._is_direct_ble and "InProgress" in err_str:
                            self._inprogress_count += 1
                            logger.warning(
                                "InProgress error #%d/%d",
                                self._inprogress_count,
                                INPROGRESS_RESET_THRESHOLD,
                            )
                            if self._inprogress_count >= INPROGRESS_RESET_THRESHOLD:
                                self._inprogress_count = 0
                                if self._resolved_adapter:
                                    reset_hci_adapter(self._resolved_adapter)
                                    await asyncio.sleep(3)
                                reconnect_delay = RECONNECT_BASE_DELAY
                                continue
                        else:
                            self._inprogress_count = 0

                        # Track notify/connect failures — blacklist after threshold
                        if self._is_direct_ble:
                            self._notify_fail_count += 1
                            if (
                                self._notify_fail_count >= NOTIFY_FAIL_THRESHOLD
                                and self.ble_address
                            ):
                                logger.warning(
                                    "Blacklisting %s after %d failures",
                                    self.ble_address,
                                    self._notify_fail_count,
                                )
                                self._blacklisted_addrs.add(self.ble_address)
                                self._notify_fail_count = 0
                                self.ble_address = None  # re-scan next attempt
                                if len(self._blacklisted_addrs) > 5:
                                    logger.info("Clearing device blacklist")
                                    self._blacklisted_addrs.clear()

                        logger.error(
                            "Failed to connect to radio: %s. Retrying in %ds...",
                            e,
                            reconnect_delay,
                        )
                        await asyncio.sleep(reconnect_delay)
                        reconnect_delay = min(
                            reconnect_delay * 2, RECONNECT_MAX_DELAY
                        )
                else:
                    await asyncio.sleep(1)
        except asyncio.CancelledError:
            logger.info("Run cancelled, stopping...")
        finally:
            health_task.cancel()
            try:
                await health_task
            except asyncio.CancelledError:
                pass
            await self.stop()
            logger.info("Proxy run loop stopped.")

    async def stop(self) -> None:
        """Stop the proxy."""
        if not self._is_running:
            return

        logger.info("Stopping MeshCore Proxy...")
        self._is_running = False

        for addr in list(self._clients.keys()):
            await self._remove_client(addr)

        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()

        # Disconnect radio
        if self._is_direct_ble and self._ble_client:
            try:
                await self._ble_client.disconnect()
            except Exception:
                pass
        elif self._radio_connection and self._radio_connected:
            try:
                await self._radio_connection.disconnect()
            except Exception:
                pass

        self._radio_connected = False
