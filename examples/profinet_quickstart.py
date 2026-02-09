#!/usr/bin/env python
"""
PROFINET Controller Quick Start Example

Minimal example showing how to:
1. Discover devices
2. Connect to an RTU
3. Exchange data

Usage:
    sudo python profinet_quickstart.py <interface> [device_name]

Example:
    sudo python profinet_quickstart.py eth0
    sudo python profinet_quickstart.py eth0 my-rtu
"""

import sys
import time
from pathlib import Path

# Add scapy to path if running from examples directory
sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.contrib.pnio_controller import PROFINETController


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    interface = sys.argv[1]
    device_filter = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"PROFINET Controller Quick Start")
    print(f"Interface: {interface}")
    print("-" * 50)

    # Create and start controller
    controller = PROFINETController(interface, station_name="QuickStart")
    controller.start()

    try:
        # Step 1: Discover devices
        print("\n[1/3] Discovering devices...")
        devices = controller.discover_devices(timeout=5.0, name_filter=device_filter)

        if not devices:
            print("ERROR: No devices found!")
            return

        print(f"Found {len(devices)} device(s):")
        for i, dev in enumerate(devices, 1):
            print(f"  {i}. {dev.name} ({dev.mac}) - IP: {dev.ip or 'N/A'}")

        # Step 2: Connect to first device
        device = devices[0]
        print(f"\n[2/3] Connecting to: {device.name}")

        if not controller.connect_device(device, input_size=32, output_size=32):
            print("ERROR: Connection failed!")
            return

        print("Connected successfully!")

        # Step 3: Exchange data
        print(f"\n[3/3] Exchanging data with {device.name}")

        # Send some output data
        output_data = b"\x01\x02\x03\x04\xAA\xBB\xCC\xDD"
        print(f"Sending: {output_data.hex()}")
        controller.write_output_data(device, output_data)

        # Wait a bit for response
        time.sleep(0.5)

        # Read input data
        input_data = controller.read_input_data(device)
        if input_data:
            print(f"Received: {input_data.hex()}")
        else:
            print("No input data received (device may not be sending)")

        print("\n" + "="*50)
        print("Quick start complete!")
        print("="*50)
        print("\nTips:")
        print("- Check device documentation for I/O data format")
        print("- Adjust input_size/output_size based on device config")
        print("- Use controller.register_input_callback() for async data")
        print("- See profinet_controller_demo.py for advanced usage")

    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        controller.stop()
        print("\nController stopped")


if __name__ == "__main__":
    main()
