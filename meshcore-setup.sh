#!/bin/bash
# ============================================================================
# MeshCore Setup Script
# Interactive installer for MeshCore BLE proxy + packet capture
# Supports Raspberry Pi, Orange Pi, and other Linux SBCs
# ============================================================================
set -euo pipefail

# Detect the real user (not root when run via sudo)
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~${REAL_USER}")
INSTALL_DIR="${REAL_HOME}"
CAPTURE_DIR="${REAL_HOME}/.meshcore-packet-capture"
BLE_PROXY_SCRIPT="${INSTALL_DIR}/meshcore-ble-proxy.py"
BLE_PROXY_SERVICE="meshcore-ble-proxy"
CAPTURE_SERVICE="meshcore-capture"
TCP_PROXY_SERVICE="meshcore-tcp-proxy"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }
header() { echo -e "\n${CYAN}${BOLD}=== $* ===${NC}\n"; }

# ============================================================================
# Step 0a: Install dependencies
# ============================================================================
header "Step 0: Installing Dependencies"

# System packages
MISSING_PKGS=()
dpkg -l bluez &>/dev/null || MISSING_PKGS+=(bluez)
dpkg -l python3-venv &>/dev/null || MISSING_PKGS+=(python3-venv)
dpkg -l mosquitto &>/dev/null || MISSING_PKGS+=(mosquitto)
dpkg -l mosquitto-clients &>/dev/null || MISSING_PKGS+=(mosquitto-clients)

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    info "Installing system packages: ${MISSING_PKGS[*]}"
    sudo apt-get update -qq
    sudo apt-get install -y -qq "${MISSING_PKGS[@]}"
else
    info "System packages OK (bluez, python3-venv, mosquitto)"
fi

# Grant the service user permission to reset BLE adapters without sudo
# hciconfig requires CAP_NET_ADMIN; sudoers rule allows passwordless access
SUDOERS_FILE="/etc/sudoers.d/meshcore-hciconfig"
if [ ! -f "$SUDOERS_FILE" ]; then
    info "Adding sudoers rule for hciconfig (BLE adapter reset)..."
    echo "${REAL_USER} ALL=(root) NOPASSWD: /usr/bin/hciconfig" | sudo tee "$SUDOERS_FILE" > /dev/null
    sudo chmod 0440 "$SUDOERS_FILE"
else
    info "sudoers rule for hciconfig already exists"
fi

# Python: bleak (system-wide, avoids venv dbus-fast issues)
if ! python3 -c "import bleak" 2>/dev/null; then
    info "Installing bleak (BLE library)..."
    sudo pip3 install --break-system-packages bleak 2>/dev/null || sudo pip3 install bleak
else
    info "bleak already installed"
fi

# Packet capture venv
if [ -d "${CAPTURE_DIR}" ] && [ ! -d "${CAPTURE_DIR}/venv" ]; then
    info "Creating packet capture venv..."
    python3 -m venv "${CAPTURE_DIR}/venv"
fi
if [ -d "${CAPTURE_DIR}/venv" ] && [ -f "${CAPTURE_DIR}/requirements.txt" ]; then
    info "Installing packet capture dependencies..."
    "${CAPTURE_DIR}/venv/bin/pip" install -q -r "${CAPTURE_DIR}/requirements.txt" 2>/dev/null || true
fi

# ============================================================================
# Step 0b: Disable existing services
# ============================================================================
header "Step 0b: Disabling existing services"

for svc in "$BLE_PROXY_SERVICE" "$CAPTURE_SERVICE" "$TCP_PROXY_SERVICE"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        info "Stopping $svc..."
        sudo systemctl stop "$svc"
    fi
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        info "Disabling $svc..."
        sudo systemctl disable "$svc"
    fi
done
info "Existing services stopped and disabled."

# ============================================================================
# Step 1: BLE Adapter Detection
# ============================================================================
header "Step 1: BLE Adapter Detection"

ADAPTER=""
ADAPTER_LIST=()

# Scan sysfs for USB Bluetooth adapters (btusb driver = USB dongle, not built-in UART)
for hci_path in /sys/class/bluetooth/hci*; do
    [ -d "$hci_path" ] || continue
    name=$(basename "$hci_path")
    # Skip sub-devices like hci1:64
    [[ "$name" == *:* ]] && continue
    uevent="${hci_path}/device/uevent"
    if [ -f "$uevent" ] && grep -q 'DRIVER=btusb' "$uevent" 2>/dev/null; then
        # Get adapter MAC from hciconfig (sysfs address file may not exist on all kernels)
        addr=$(hciconfig "$name" 2>/dev/null | grep -oP 'BD Address: \K[0-9A-F:]+' || echo "unknown")
        info "Found USB BT adapter: ${name} (${addr})"
        ADAPTER_LIST+=("$name")
    fi
done

if [ ${#ADAPTER_LIST[@]} -eq 0 ]; then
    error "No USB Bluetooth adapter found!"
    error "A USB BLE 5.x adapter is required (built-in adapters often cannot do GATT)."
    error "Plug in a USB BLE adapter and try again."
    exit 1
fi

if [ ${#ADAPTER_LIST[@]} -eq 1 ]; then
    ADAPTER="${ADAPTER_LIST[0]}"
    info "Using adapter: ${ADAPTER}"
else
    echo "Multiple USB BT adapters found:"
    for i in "${!ADAPTER_LIST[@]}"; do
        echo "  $((i+1))) ${ADAPTER_LIST[$i]}"
    done
    while true; do
        read -rp "Select adapter [1]: " choice
        choice="${choice:-1}"
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#ADAPTER_LIST[@]} ]; then
            ADAPTER="${ADAPTER_LIST[$((choice-1))]}"
            break
        fi
        echo "Invalid choice."
    done
    info "Using adapter: ${ADAPTER}"
fi

# Verify GATT capability with a quick scan
info "Verifying GATT capability (10s timeout)..."
GATT_OK=$(timeout 15 python3 -c "
import asyncio, signal
from bleak import BleakScanner
signal.alarm(12)
async def test():
    try:
        devs = await asyncio.wait_for(BleakScanner.discover(timeout=5, adapter='${ADAPTER}'), timeout=10)
        print(f'OK:{len(devs)}')
    except asyncio.TimeoutError:
        print('FAIL:scan timed out')
    except Exception as e:
        print(f'FAIL:{e}')
asyncio.run(test())
" 2>&1 || echo "FAIL:process timed out")

if [[ "$GATT_OK" == OK:* ]]; then
    count="${GATT_OK#OK:}"
    info "GATT OK - adapter can scan (found ${count} nearby devices)"
else
    warn "GATT check failed: ${GATT_OK}"
    info "Resetting adapter and retrying..."
    sudo hciconfig "${ADAPTER}" reset
    sleep 3
    sudo hciconfig "${ADAPTER}" up
    sleep 2
    GATT_OK=$(timeout 15 python3 -c "
import asyncio, signal
from bleak import BleakScanner
signal.alarm(12)
async def test():
    try:
        devs = await asyncio.wait_for(BleakScanner.discover(timeout=5, adapter='${ADAPTER}'), timeout=10)
        print(f'OK:{len(devs)}')
    except asyncio.TimeoutError:
        print('FAIL:scan timed out')
    except Exception as e:
        print(f'FAIL:{e}')
asyncio.run(test())
" 2>&1 || echo "FAIL:process timed out")
    if [[ "$GATT_OK" == OK:* ]]; then
        count="${GATT_OK#OK:}"
        info "GATT OK after reset (found ${count} nearby devices)"
    else
        error "GATT capability check failed after reset: ${GATT_OK}"
        error "The adapter cannot perform BLE scans. Try a different adapter."
        exit 1
    fi
fi

# ============================================================================
# Step 2: BLE Scan & Device Selection
# ============================================================================
header "Step 2: BLE Device Scan"

info "Scanning for MeshCore devices (15 seconds)..."

# Run BLE scan and capture MeshCore devices
SCAN_RESULT=$(timeout 25 python3 -c "
import asyncio, signal
from bleak import BleakScanner
signal.alarm(22)

async def scan():
    devices = await asyncio.wait_for(
        BleakScanner.discover(timeout=15, adapter='${ADAPTER}', return_adv=True),
        timeout=20
    )
    meshcore = []
    for d, adv in devices.values():
        name = d.name or adv.local_name or ''
        if name.startswith('MeshCore'):
            meshcore.append(f'{d.address}|{name}|{adv.rssi}')
    meshcore.sort(key=lambda x: int(x.split('|')[2]), reverse=True)
    for m in meshcore:
        print(m)
asyncio.run(scan())
" 2>&1)

if [ $? -ne 0 ] && [ -z "$SCAN_RESULT" ]; then
    warn "BLE scan timed out. Resetting adapter and retrying..."
    sudo hciconfig "${ADAPTER}" reset
    sleep 3
    sudo hciconfig "${ADAPTER}" up
    sleep 2
    SCAN_RESULT=$(timeout 25 python3 -c "
import asyncio, signal
from bleak import BleakScanner
signal.alarm(22)

async def scan():
    devices = await asyncio.wait_for(
        BleakScanner.discover(timeout=15, adapter='${ADAPTER}', return_adv=True),
        timeout=20
    )
    meshcore = []
    for d, adv in devices.values():
        name = d.name or adv.local_name or ''
        if name.startswith('MeshCore'):
            meshcore.append(f'{d.address}|{name}|{adv.rssi}')
    meshcore.sort(key=lambda x: int(x.split('|')[2]), reverse=True)
    for m in meshcore:
        print(m)
asyncio.run(scan())
" 2>&1)
fi

# Parse results
DEVICES=()
DEVICE_ADDRS=()
DEVICE_NAMES=()
while IFS= read -r line; do
    [[ "$line" == *"|"* ]] || continue
    addr=$(echo "$line" | cut -d'|' -f1)
    name=$(echo "$line" | cut -d'|' -f2)
    rssi=$(echo "$line" | cut -d'|' -f3)
    DEVICES+=("${name} (${addr}) RSSI=${rssi}")
    DEVICE_ADDRS+=("$addr")
    DEVICE_NAMES+=("$name")
done <<< "$SCAN_RESULT"

if [ ${#DEVICES[@]} -eq 0 ]; then
    error "No MeshCore devices found!"
    error "Make sure your MeshCore radio is powered on and in BLE range."
    exit 1
fi

echo ""
echo "MeshCore devices found:"
for i in "${!DEVICES[@]}"; do
    echo "  $((i+1))) ${DEVICES[$i]}"
done
echo ""

while true; do
    read -rp "Select device [1]: " choice
    choice="${choice:-1}"
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#DEVICES[@]} ]; then
        BLE_ADDR="${DEVICE_ADDRS[$((choice-1))]}"
        BLE_NAME="${DEVICE_NAMES[$((choice-1))]}"
        break
    fi
    echo "Invalid choice."
done

info "Selected: ${BLE_NAME} (${BLE_ADDR})"

# ============================================================================
# Step 3: BLE PIN & Pairing
# ============================================================================
header "Step 3: BLE Pairing PIN"

read -rp "Enter BLE pairing PIN [123456]: " BLE_PIN
BLE_PIN="${BLE_PIN:-123456}"
info "PIN set to: ${BLE_PIN}"

# Attempt pairing
info "Pairing with ${BLE_NAME} (${BLE_ADDR})..."

# Get adapter MAC from hciconfig (sysfs address file doesn't exist on all kernels)
ADAPTER_MAC=$(hciconfig "${ADAPTER}" 2>/dev/null | grep -oP 'BD Address: \K[0-9A-F:]+' || echo "")
if [ -z "$ADAPTER_MAC" ]; then
    warn "Could not determine adapter MAC address"
    ADAPTER_MAC="UNKNOWN"
fi
info "Adapter MAC: ${ADAPTER_MAC}"

BOND_DIR="/var/lib/bluetooth/${ADAPTER_MAC}/${BLE_ADDR}"

# Remove existing bond if present
if [ -d "$BOND_DIR" ]; then
    warn "Removing existing bond for ${BLE_ADDR}..."
    sudo rm -rf "$BOND_DIR"
    sudo systemctl restart bluetooth
    sleep 2
fi

# Pair using bluetoothctl with the PIN
info "Pairing via bluetoothctl (PIN: ${BLE_PIN})..."
set +e  # Disable exit-on-error for pairing (bluetoothctl returns non-zero often)
PAIR_RESULT=$(timeout 35 bash -c '
    {
        sleep 1
        echo "select '"${ADAPTER_MAC}"'"
        sleep 1
        echo "remove '"${BLE_ADDR}"'"
        sleep 2
        echo "scan on"
        sleep 8
        echo "scan off"
        sleep 1
        echo "pair '"${BLE_ADDR}"'"
        sleep 3
        echo "'"${BLE_PIN}"'"
        sleep 5
        echo "trust '"${BLE_ADDR}"'"
        sleep 2
        echo "disconnect '"${BLE_ADDR}"'"
        sleep 1
        echo "quit"
    } | bluetoothctl 2>&1
' 2>&1)
PAIR_EXIT=$?
set -e  # Re-enable exit-on-error

# Check if pairing succeeded
if echo "$PAIR_RESULT" | grep -q "Pairing successful"; then
    info "Pairing successful!"
elif [ -d "$BOND_DIR" ]; then
    info "Bond file exists - pairing appears successful."
else
    warn "Pairing may not have succeeded (exit=$PAIR_EXIT)."
    echo "$PAIR_RESULT" | grep -iE "(pair|fail|error|passkey|pin|success|bond)" | head -10 || true
    echo ""
    read -rp "Continue anyway? [y/N]: " cont
    if [[ ! "$cont" =~ ^[yY] ]]; then
        error "Aborting. Fix pairing and re-run the script."
        exit 1
    fi
fi

# ============================================================================
# Step 3b: Probe device for node name & configure BLE
# ============================================================================
header "Step 3b: Reading Device Info"

info "Connecting to device to read node name..."
set +e
DEVICE_NODE_NAME=$(timeout 20 python3 -c "
import asyncio, struct

NUS_TX = '6e400003-b5a3-f393-e0a9-e50e24dcca9e'
NUS_RX = '6e400002-b5a3-f393-e0a9-e50e24dcca9e'

async def probe():
    from bleak import BleakClient
    responses = []

    def on_notify(sender, data):
        responses.append(bytes(data))

    client = BleakClient('${BLE_ADDR}', adapter='${ADAPTER}', timeout=15)
    try:
        await client.connect()
        await client.start_notify(NUS_TX, on_notify)

        # Send CMD_APPSTART: type=0x01, version=0x03, app='setup '
        appstart = bytes([0x01, 0x03]) + b'setup '
        await client.write_gatt_char(NUS_RX, appstart, response=True)
        await asyncio.sleep(3)

        # Parse SELF_INFO (type=0x05) from responses
        for resp in responses:
            if len(resp) > 10 and resp[0] == 0x05:
                # SELF_INFO: type(1) + version(1) + pubkey(32) + lat(4) + lon(4) + name...
                # Name starts after the fixed fields, null-terminated
                name_start = 42  # typical offset
                name_bytes = resp[name_start:]
                # Find null terminator or end
                name = ''
                for b in name_bytes:
                    if b == 0 or b > 127:
                        break
                    if 32 <= b <= 126:
                        name += chr(b)
                if name and len(name) >= 2:
                    print(f'NAME:{name.strip()}')
                    break
        else:
            # Fallback: scan all responses for longest ASCII string
            for resp in responses:
                if resp[0] == 0x05:
                    best = ''
                    current = ''
                    for b in resp[2:]:
                        if 32 <= b <= 126:
                            current += chr(b)
                        else:
                            if len(current) > len(best) and len(current) >= 3:
                                best = current
                            current = ''
                    if len(current) > len(best) and len(current) >= 3:
                        best = current
                    if best:
                        print(f'NAME:{best.strip()}')
                        break

        await client.stop_notify(NUS_TX)
        await client.disconnect()
    except Exception as e:
        print(f'ERROR:{e}')
        try:
            await client.disconnect()
        except:
            pass

asyncio.run(probe())
" 2>&1)
PROBE_EXIT=$?
set -e

NODE_NAME=""
if [[ "$DEVICE_NODE_NAME" == *"NAME:"* ]]; then
    NODE_NAME=$(echo "$DEVICE_NODE_NAME" | grep "^NAME:" | head -1 | sed 's/^NAME://')
    info "Device node name: ${NODE_NAME}"
else
    warn "Could not read node name from device."
    if [[ "$DEVICE_NODE_NAME" == *"ERROR:"* ]]; then
        warn "$(echo "$DEVICE_NODE_NAME" | grep "^ERROR:")"
    fi
fi

# ============================================================================
# Step 3c: Update BLE name and PIN on device
# ============================================================================
header "Step 3c: Configure Device BLE Settings"

NEW_BLE_PIN="426842"
info "Setting device BLE PIN to ${NEW_BLE_PIN}..."

# If we got a node name, offer to set it as BLE name too
NEW_BLE_NAME=""
if [ -n "$NODE_NAME" ]; then
    info "Node name from device: ${NODE_NAME}"
    read -rp "Set BLE advertisement name to match node name '${NODE_NAME}'? [Y/n]: " SET_BLE_NAME
    SET_BLE_NAME="${SET_BLE_NAME:-Y}"
    if [[ "$SET_BLE_NAME" =~ ^[yY] ]]; then
        NEW_BLE_NAME="$NODE_NAME"
    fi
fi

if [ -z "$NEW_BLE_NAME" ]; then
    read -rp "Enter BLE advertisement name (leave blank to skip): " NEW_BLE_NAME
fi

set +e
CONFIG_RESULT=$(timeout 25 python3 -c "
import asyncio, struct

NUS_TX = '6e400003-b5a3-f393-e0a9-e50e24dcca9e'
NUS_RX = '6e400002-b5a3-f393-e0a9-e50e24dcca9e'

async def configure():
    from bleak import BleakClient
    client = BleakClient('${BLE_ADDR}', adapter='${ADAPTER}', timeout=15)
    try:
        await client.connect()

        def on_notify(sender, data):
            pass
        await client.start_notify(NUS_TX, on_notify)

        # Send APPSTART first to establish session
        appstart = bytes([0x01, 0x03]) + b'setup '
        await client.write_gatt_char(NUS_RX, appstart, response=True)
        await asyncio.sleep(2)

        ble_name = '${NEW_BLE_NAME}'
        if ble_name:
            # CMD_SET_NAME (0x08): type + name bytes
            name_cmd = bytes([0x08]) + ble_name.encode('utf-8')
            await client.write_gatt_char(NUS_RX, name_cmd, response=True)
            print(f'SET_NAME:{ble_name}')
            await asyncio.sleep(1)

        # CMD_SET_BLE_PIN (0x0B): type + 4-byte LE pin
        pin = int('${NEW_BLE_PIN}')
        pin_cmd = bytes([0x0b]) + struct.pack('<I', pin)
        await client.write_gatt_char(NUS_RX, pin_cmd, response=True)
        print(f'SET_PIN:${NEW_BLE_PIN}')
        await asyncio.sleep(1)

        # CMD_REBOOT (0x13) to apply changes
        reboot_cmd = bytes([0x13])
        await client.write_gatt_char(NUS_RX, reboot_cmd, response=True)
        print('REBOOT:sent')
        await asyncio.sleep(1)

        await client.stop_notify(NUS_TX)
        await client.disconnect()
        print('OK')
    except Exception as e:
        print(f'ERROR:{e}')
        try:
            await client.disconnect()
        except:
            pass

asyncio.run(configure())
" 2>&1)
CONFIG_EXIT=$?
set -e

if echo "$CONFIG_RESULT" | grep -q "^OK"; then
    info "Device configured! PIN set to ${NEW_BLE_PIN}."
    if [ -n "$NEW_BLE_NAME" ]; then
        info "BLE name set to '${NEW_BLE_NAME}' (applies after reboot)."
        # Update BLE_NAME for service config
        BLE_NAME="MeshCore-${NEW_BLE_NAME}"
    fi
    info "Device is rebooting..."
    sleep 5  # Wait for device to reboot
else
    warn "Device configuration may have failed:"
    echo "$CONFIG_RESULT" | head -5 || true
    echo ""
    warn "You can change PIN and name manually later."
fi

# Re-pair with new PIN after reboot
if echo "$CONFIG_RESULT" | grep -q "^OK"; then
    info "Re-pairing with new PIN (${NEW_BLE_PIN})..."
    # Remove old bond
    if [ -d "$BOND_DIR" ]; then
        sudo rm -rf "$BOND_DIR"
    fi
    sudo systemctl restart bluetooth
    sleep 3

    set +e
    PAIR2_RESULT=$(timeout 35 bash -c '
        {
            sleep 1
            echo "select '"${ADAPTER_MAC}"'"
            sleep 1
            echo "scan on"
            sleep 10
            echo "scan off"
            sleep 1
            echo "pair '"${BLE_ADDR}"'"
            sleep 3
            echo "'"${NEW_BLE_PIN}"'"
            sleep 5
            echo "trust '"${BLE_ADDR}"'"
            sleep 2
            echo "disconnect '"${BLE_ADDR}"'"
            sleep 1
            echo "quit"
        } | bluetoothctl 2>&1
    ' 2>&1)
    set -e

    if echo "$PAIR2_RESULT" | grep -q "Pairing successful" || [ -d "$BOND_DIR" ]; then
        info "Re-paired with new PIN ${NEW_BLE_PIN}!"
        BLE_PIN="$NEW_BLE_PIN"
    else
        warn "Re-pairing with new PIN may have failed."
        warn "If the proxy can't connect, pair manually: bluetoothctl pair ${BLE_ADDR} (PIN: ${NEW_BLE_PIN})"
    fi
fi

# ============================================================================
# Step 4: TCP Proxy Service
# ============================================================================
header "Step 4: TCP Proxy Configuration"

read -rp "Enable TCP proxy service? [Y/n]: " ENABLE_PROXY
ENABLE_PROXY="${ENABLE_PROXY:-Y}"

TCP_PORT=5000
if [[ "$ENABLE_PROXY" =~ ^[yY] ]]; then
    read -rp "TCP proxy port [5000]: " TCP_PORT
    TCP_PORT="${TCP_PORT:-5000}"
    info "TCP proxy will listen on port ${TCP_PORT}"
fi

# ============================================================================
# Step 5: LetsMesh.net Setup
# ============================================================================
header "Step 5: LetsMesh.net Integration"

echo "LetsMesh.net provides a cloud-based mesh network analyzer."
echo "Packets are published via MQTT over WebSocket with JWT auth."
echo "The device signs JWT tokens on-device (no private key leaves the radio)."
echo ""
read -rp "Enable LetsMesh.net integration? [Y/n]: " ENABLE_LETSMESH
ENABLE_LETSMESH="${ENABLE_LETSMESH:-Y}"

LETSMESH_SERVER="mqtt-us-v1.letsmesh.net"
LETSMESH_PORT=443
IATA=""
ORIGIN=""

if [[ "$ENABLE_LETSMESH" =~ ^[yY] ]]; then
    echo ""
    echo "IATA code: 3-letter airport/location code for MQTT topic prefix."
    echo "Find yours at: https://www.iata.org/en/publications/directories/code-search/"
    echo ""
    while [ -z "$IATA" ]; do
        read -rp "IATA code (required, e.g. LAX, AMS, JFK): " IATA
        IATA=$(echo "$IATA" | tr '[:lower:]' '[:upper:]')
        if [ ${#IATA} -ne 3 ]; then
            warn "IATA code must be exactly 3 characters."
            IATA=""
        fi
    done

    # Origin name: use node name if we got it, otherwise ask
    if [ -n "$NODE_NAME" ]; then
        ORIGIN="MeshCore-${NODE_NAME}"
        info "Origin name (from device): ${ORIGIN}"
        read -rp "Use this origin name? [Y/n]: " USE_ORIGIN
        USE_ORIGIN="${USE_ORIGIN:-Y}"
        if [[ ! "$USE_ORIGIN" =~ ^[yY] ]]; then
            ORIGIN=""
        fi
    fi

    if [ -z "$ORIGIN" ]; then
        echo ""
        echo "Enter your node name (MeshCore- prefix will be added automatically)."
        read -rp "Node name: " input_name
        if [ -n "$input_name" ]; then
            ORIGIN="MeshCore-${input_name}"
        else
            ORIGIN="MeshCore-$(hostname)"
        fi
    fi

    info "LetsMesh: ${LETSMESH_SERVER}:${LETSMESH_PORT}, IATA=${IATA}, Origin=${ORIGIN}"
fi

# ============================================================================
# Step 6: MQTT Configuration
# ============================================================================
header "Step 6: Local MQTT Configuration"

echo "Local MQTT publishes mesh packets to a local broker (e.g., for Prometheus/Grafana)."
echo "Mosquitto is installed on this host (localhost:1883)."
echo ""
read -rp "Enable local MQTT? [y/N]: " ENABLE_MQTT
ENABLE_MQTT="${ENABLE_MQTT:-N}"

MQTT_HOST="localhost"
MQTT_PORT=1883
MQTT_USER=""
MQTT_PASS=""

if [[ "$ENABLE_MQTT" =~ ^[yY] ]]; then
    read -rp "MQTT broker host [localhost]: " MQTT_HOST
    MQTT_HOST="${MQTT_HOST:-localhost}"
    read -rp "MQTT broker port [1883]: " MQTT_PORT
    MQTT_PORT="${MQTT_PORT:-1883}"
    read -rp "MQTT username (blank for anonymous): " MQTT_USER
    if [ -n "$MQTT_USER" ]; then
        read -rsp "MQTT password: " MQTT_PASS
        echo ""
    fi
    info "MQTT: ${MQTT_HOST}:${MQTT_PORT} (user: ${MQTT_USER:-anonymous})"
fi

# ============================================================================
# Step 7: Write Configuration
# ============================================================================
header "Step 7: Writing Configuration"

# --- BLE Proxy Service ---
if [[ "$ENABLE_PROXY" =~ ^[yY] ]]; then
    info "Writing BLE proxy service..."
    sudo tee /etc/systemd/system/${BLE_PROXY_SERVICE}.service > /dev/null << SVCEOF
[Unit]
Description=MeshCore BLE-to-TCP Proxy
After=bluetooth.target
Wants=bluetooth.target

[Service]
Type=simple
User=${REAL_USER}
ExecStart=/usr/bin/python3 ${BLE_PROXY_SCRIPT} --adapter ${ADAPTER} --ble-addr ${BLE_ADDR} --ble-name ${BLE_NAME} --port ${TCP_PORT}
Restart=on-failure
RestartSec=30
Environment=PYTHONUNBUFFERED=1
StandardOutput=journal
StandardError=journal

# Allow hciconfig reset without root (CAP_NET_ADMIN for HCI adapter control)
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
SVCEOF
    info "BLE proxy service written."
fi

# --- Packet Capture .env.local ---
NEED_CAPTURE=false
if [[ "$ENABLE_LETSMESH" =~ ^[yY] ]] || [[ "$ENABLE_MQTT" =~ ^[yY] ]]; then
    NEED_CAPTURE=true
fi

if [ "$NEED_CAPTURE" = true ]; then
    info "Writing packet capture config (.env.local)..."
    mkdir -p "$CAPTURE_DIR"

    cat > "${CAPTURE_DIR}/.env.local" << ENVEOF
# MeshCore Packet Capture Configuration
# Generated by meshcore-setup.sh on $(date -Iseconds)

# Connection to BLE proxy
PACKETCAPTURE_CONNECTION_TYPE=tcp
PACKETCAPTURE_TCP_HOST=localhost
PACKETCAPTURE_TCP_PORT=${TCP_PORT}

# Location
PACKETCAPTURE_IATA=${IATA}
PACKETCAPTURE_ORIGIN=${ORIGIN:-MeshCore-$(hostname)}

# Logging
PACKETCAPTURE_LOG_LEVEL=INFO
ENVEOF

    # MQTT Broker 1: Local
    if [[ "$ENABLE_MQTT" =~ ^[yY] ]]; then
        cat >> "${CAPTURE_DIR}/.env.local" << ENVEOF

# Broker 1: Local MQTT
PACKETCAPTURE_MQTT1_ENABLED=true
PACKETCAPTURE_MQTT1_SERVER=${MQTT_HOST}
PACKETCAPTURE_MQTT1_PORT=${MQTT_PORT}
PACKETCAPTURE_MQTT1_TRANSPORT=tcp
PACKETCAPTURE_MQTT1_USE_TLS=false
PACKETCAPTURE_MQTT1_USE_AUTH_TOKEN=false
ENVEOF
        if [ -n "$MQTT_USER" ]; then
            cat >> "${CAPTURE_DIR}/.env.local" << ENVEOF
PACKETCAPTURE_MQTT1_USERNAME=${MQTT_USER}
PACKETCAPTURE_MQTT1_PASSWORD=${MQTT_PASS}
ENVEOF
        fi
    else
        cat >> "${CAPTURE_DIR}/.env.local" << ENVEOF

# Broker 1: Disabled
PACKETCAPTURE_MQTT1_ENABLED=false
ENVEOF
    fi

    # MQTT Broker 2: LetsMesh
    if [[ "$ENABLE_LETSMESH" =~ ^[yY] ]]; then
        cat >> "${CAPTURE_DIR}/.env.local" << ENVEOF

# Broker 2: LetsMesh.net
PACKETCAPTURE_MQTT2_ENABLED=true
PACKETCAPTURE_MQTT2_SERVER=${LETSMESH_SERVER}
PACKETCAPTURE_MQTT2_PORT=${LETSMESH_PORT}
PACKETCAPTURE_MQTT2_TRANSPORT=websockets
PACKETCAPTURE_MQTT2_USE_TLS=true
PACKETCAPTURE_MQTT2_USE_AUTH_TOKEN=true
PACKETCAPTURE_MQTT2_TOKEN_AUDIENCE=${LETSMESH_SERVER}

# Auth: on-device JWT signing via BLE proxy
PACKETCAPTURE_AUTH_TOKEN_METHOD=device
ENVEOF
    else
        cat >> "${CAPTURE_DIR}/.env.local" << ENVEOF

# Broker 2: Disabled
PACKETCAPTURE_MQTT2_ENABLED=false
ENVEOF
    fi

    # Broker 3: Always disabled
    cat >> "${CAPTURE_DIR}/.env.local" << ENVEOF

# Broker 3: Disabled
PACKETCAPTURE_MQTT3_ENABLED=false
ENVEOF

    # Private key reference (if exists)
    for keyfile in "${CAPTURE_DIR}"/*_private_key.hex; do
        if [ -f "$keyfile" ]; then
            cat >> "${CAPTURE_DIR}/.env.local" << ENVEOF

# Device identity (Python fallback for JWT signing)
PACKETCAPTURE_PRIVATE_KEY_FILE=${keyfile}
ENVEOF
            break
        fi
    done

    info "Packet capture config written to ${CAPTURE_DIR}/.env.local"
fi

# --- Packet Capture Service ---
if [ "$NEED_CAPTURE" = true ]; then
    info "Writing packet capture service..."
    sudo tee /etc/systemd/system/${CAPTURE_SERVICE}.service > /dev/null << SVCEOF
[Unit]
Description=MeshCore Packet Capture
After=time-sync.target network.target ${BLE_PROXY_SERVICE}.service mosquitto.service
Wants=time-sync.target ${BLE_PROXY_SERVICE}.service

[Service]
User=${REAL_USER}
WorkingDirectory=${CAPTURE_DIR}
ExecStart=${CAPTURE_DIR}/venv/bin/python3 ${CAPTURE_DIR}/packet_capture.py
KillMode=process
Restart=always
RestartSec=30
Type=exec
MemoryMax=256M
CPUQuota=30%
StandardOutput=journal
StandardError=journal
SyslogIdentifier=meshcore-capture

[Install]
WantedBy=multi-user.target
SVCEOF
    info "Packet capture service written."
fi

# ============================================================================
# Step 8: Enable and Start Services
# ============================================================================
header "Step 8: Enabling Services"

sudo systemctl daemon-reload

if [[ "$ENABLE_PROXY" =~ ^[yY] ]]; then
    info "Enabling and starting ${BLE_PROXY_SERVICE}..."
    sudo systemctl enable "$BLE_PROXY_SERVICE"
    sudo systemctl start "$BLE_PROXY_SERVICE"
    sleep 3
    if systemctl is-active --quiet "$BLE_PROXY_SERVICE"; then
        info "${BLE_PROXY_SERVICE} is running!"
    else
        warn "${BLE_PROXY_SERVICE} failed to start. Check: journalctl -u ${BLE_PROXY_SERVICE} -n 20"
    fi
fi

if [ "$NEED_CAPTURE" = true ]; then
    info "Waiting 5s for BLE proxy to establish connection..."
    sleep 5
    info "Enabling and starting ${CAPTURE_SERVICE}..."
    sudo systemctl enable "$CAPTURE_SERVICE"
    sudo systemctl start "$CAPTURE_SERVICE"
    sleep 3
    if systemctl is-active --quiet "$CAPTURE_SERVICE"; then
        info "${CAPTURE_SERVICE} is running!"
    else
        warn "${CAPTURE_SERVICE} failed to start. Check: journalctl -u ${CAPTURE_SERVICE} -n 20"
    fi
fi

# ============================================================================
# Summary
# ============================================================================
header "Setup Complete"

echo -e "${BOLD}Configuration Summary:${NC}"
echo "  User:           ${REAL_USER}"
echo "  BLE Adapter:    ${ADAPTER} (${ADAPTER_MAC})"
echo "  BLE Device:     ${BLE_NAME} (${BLE_ADDR})"
echo "  BLE PIN:        ${BLE_PIN}"
if [ -n "$NODE_NAME" ]; then
    echo "  Node Name:      ${NODE_NAME}"
fi
echo ""

if [[ "$ENABLE_PROXY" =~ ^[yY] ]]; then
    echo -e "  TCP Proxy:      ${GREEN}ENABLED${NC} (port ${TCP_PORT})"
else
    echo -e "  TCP Proxy:      ${RED}DISABLED${NC}"
fi

if [[ "$ENABLE_LETSMESH" =~ ^[yY] ]]; then
    echo -e "  LetsMesh.net:   ${GREEN}ENABLED${NC} (${LETSMESH_SERVER}, IATA=${IATA})"
else
    echo -e "  LetsMesh.net:   ${RED}DISABLED${NC}"
fi

if [[ "$ENABLE_MQTT" =~ ^[yY] ]]; then
    echo -e "  Local MQTT:     ${GREEN}ENABLED${NC} (${MQTT_HOST}:${MQTT_PORT})"
else
    echo -e "  Local MQTT:     ${RED}DISABLED${NC}"
fi

echo ""
echo -e "${BOLD}Service Status:${NC}"
for svc in "$BLE_PROXY_SERVICE" "$CAPTURE_SERVICE"; do
    status=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
    if [ "$status" = "active" ]; then
        echo -e "  ${svc}: ${GREEN}${status}${NC}"
    else
        echo -e "  ${svc}: ${RED}${status}${NC}"
    fi
done

echo ""
echo -e "${BOLD}Useful commands:${NC}"
echo "  journalctl -u ${BLE_PROXY_SERVICE} -f       # BLE proxy logs"
echo "  journalctl -u ${CAPTURE_SERVICE} -f          # Packet capture logs"
echo "  mosquitto_sub -h localhost -t 'meshcore/#' -v # MQTT messages"
echo ""
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo "  To connect a client:  meshcore-cli --tcp localhost:${TCP_PORT}"
echo "  Phone app:            TCP -> ${LOCAL_IP:-<this-host>}:${TCP_PORT}"
echo ""
