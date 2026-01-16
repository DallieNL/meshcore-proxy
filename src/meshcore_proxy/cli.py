"""Command-line interface for MeshCore Proxy."""

import argparse
import asyncio
import logging
import sys

from meshcore_proxy.proxy import EventLogLevel, MeshCoreProxy


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TCP proxy for MeshCore companion radios",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Connect via USB serial
  meshcore-proxy --serial /dev/ttyUSB0

  # Connect via BLE
  meshcore-proxy --ble 12:34:56:78:90:AB

  # With event logging
  meshcore-proxy --serial /dev/ttyUSB0 --log-events

  # Specify TCP port
  meshcore-proxy --serial /dev/ttyUSB0 --port 5000
        """,
    )

    # Connection type (mutually exclusive)
    conn_group = parser.add_mutually_exclusive_group(required=True)
    conn_group.add_argument(
        "--serial",
        metavar="PORT",
        help="Serial port path (e.g., /dev/ttyUSB0)",
    )
    conn_group.add_argument(
        "--ble",
        metavar="MAC",
        help="BLE device MAC address (e.g., 12:34:56:78:90:AB)",
    )

    # TCP server options
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="TCP server bind address (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="TCP server port (default: 5000)",
    )

    # Serial options
    parser.add_argument(
        "--baud",
        type=int,
        default=115200,
        help="Serial baud rate (default: 115200)",
    )

    # BLE options
    parser.add_argument(
        "--ble-pin",
        default="123456",
        help="BLE pairing PIN (default: 123456)",
    )

    # Event logging options (mutually exclusive)
    log_group = parser.add_mutually_exclusive_group()
    log_group.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-error output",
    )
    log_group.add_argument(
        "--log-events",
        action="store_true",
        help="Log event summaries (type, direction, basic info)",
    )
    log_group.add_argument(
        "--log-events-verbose",
        action="store_true",
        help="Log full decoded event details",
    )

    # Output format
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output event logs as JSON (for parsing)",
    )

    # Debug logging
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Determine event log level
    if args.quiet:
        event_log_level = EventLogLevel.OFF
    elif args.log_events_verbose:
        event_log_level = EventLogLevel.VERBOSE
    elif args.log_events:
        event_log_level = EventLogLevel.SUMMARY
    else:
        event_log_level = EventLogLevel.OFF

    # Configure logging
    if args.quiet:
        log_level = logging.ERROR
    elif args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Create proxy
    proxy = MeshCoreProxy(
        serial_port=args.serial,
        ble_address=args.ble,
        baud_rate=args.baud,
        ble_pin=args.ble_pin,
        tcp_host=args.host,
        tcp_port=args.port,
        event_log_level=event_log_level,
        event_log_json=args.json,
    )

    # Run
    try:
        asyncio.run(proxy.run())
    except KeyboardInterrupt:
        logging.info("Shutting down...")
        return 0
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
