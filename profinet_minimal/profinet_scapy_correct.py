#!/usr/bin/env python3
"""
PROFINET Controller using CORRECT Scapy patterns v1.0.1

Uses Scapy layers properly - matching the working packet structure exactly.

Version: 1.0.1
Date: 2026-02-09
"""

import sys
import argparse
from typing import List, Optional

try:
    from scapy.all import *
    from scapy.contrib.pnio import *
    from scapy.contrib.pnio_dcp import *
except ImportError:
    print("[ERROR] Scapy not installed. Run: pip3 install scapy")
    sys.exit(1)


class DCPDevice:
    """Discovered PROFINET device"""
    def __init__(self, mac_address, ip_address, device_name, vendor_id=None, device_id=None):
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.device_name = device_name
        self.vendor_id = vendor_id
        self.device_id = device_id

    def __repr__(self):
        return f"DCPDevice(name={self.device_name}, ip={self.ip_address}, mac={self.mac_address})"


def discover_devices(interface: str, timeout: float = 3.0) -> List[DCPDevice]:
    """
    Discover PROFINET devices using Scapy - CORRECT WAY

    Key: Override Scapy's defaults to match working packet exactly
    """
    print(f"[INFO] === DCP Discovery using Scapy v1.0.1 ===")

    controller_mac = get_if_hwaddr(interface)
    print(f"[INFO] Controller MAC: {controller_mac}")

    # Build DCP Identify using Scapy BUT with correct parameters
    # The working packet uses xid=0x12345678, NOT Scapy's default 0x01000001
    dcp_request = (
        Ether(dst="01:0e:cf:00:00:00", src=controller_mac) /
        ProfinetIO(frameID=0xFEFE) /  # DCP Identify Request
        ProfinetDCP(
            service_id=0x05,      # Identify
            service_type=0x00,    # Request
            xid=0x12345678,       # CRITICAL: Custom XID, not Scapy default!
            reserved=0x0001,      # Response delay
            dcp_data_length=4,    # Block length
            option=0xFF,          # All options
            sub_option=0xFF,      # All sub-options
            dcp_block_length=0    # No additional data
        )
    )

    # Remove padding that Scapy adds
    # Scapy auto-pads to 60 bytes, we want exactly 30
    dcp_request = Ether(bytes(dcp_request)[:30])

    print(f"[INFO] DCP frame size: {len(dcp_request)} bytes")
    print(f"[INFO] Hex dump:")
    hexdump(dcp_request)

    # Send and capture responses
    print(f"[INFO] ✓ Sending DCP Identify Request")

    responses = srp(
        dcp_request,
        iface=interface,
        timeout=timeout,
        verbose=0,
        multi=True
    )[0]

    devices = []

    for sent, received in responses:
        try:
            if not (ProfinetDCP in received):
                continue

            # Parse device info from DCP blocks
            device_name = None
            device_ip = None
            device_mac = received.src
            vendor_id = None
            device_id = None

            # Walk through layers to extract info
            layer = received
            while layer:
                # Device Name
                if isinstance(layer, DCPNameOfStationBlock):
                    if hasattr(layer, 'name_of_station'):
                        device_name = layer.name_of_station
                        if isinstance(device_name, bytes):
                            device_name = device_name.decode('utf-8', errors='ignore')

                # IP Address
                if isinstance(layer, (DCPIPBlock, DCPFullIPBlock)):
                    if hasattr(layer, 'ip'):
                        device_ip = layer.ip

                # Device ID
                if isinstance(layer, DCPDeviceIDBlock):
                    if hasattr(layer, 'vendor_id'):
                        vendor_id = layer.vendor_id
                    if hasattr(layer, 'device_id'):
                        device_id = layer.device_id

                layer = layer.payload if hasattr(layer, 'payload') and layer.payload else None

            if device_name and device_ip:
                device = DCPDevice(
                    mac_address=device_mac,
                    ip_address=device_ip,
                    device_name=device_name,
                    vendor_id=vendor_id,
                    device_id=device_id
                )
                devices.append(device)
                print(f"[INFO] ✓ Discovered: {device_name} @ {device_ip} ({device_mac})")

        except Exception as e:
            # Skip malformed responses
            continue

    print(f"[INFO] Discovery complete: found {len(devices)} device(s)")
    return devices


def main():
    parser = argparse.ArgumentParser(
        description='PROFINET Discovery using CORRECT Scapy patterns v1.0.1',
        epilog='Example: sudo python3 profinet_scapy_correct.py --interface enp0s3'
    )

    parser.add_argument('--interface', '-i', required=True,
                       help='Network interface (e.g., enp0s3, eth0)')
    parser.add_argument('--timeout', '-t', type=float, default=3.0,
                       help='Discovery timeout (default: 3.0s)')

    args = parser.parse_args()

    # Check root
    import os
    if os.geteuid() != 0:
        print("[ERROR] Root required")
        print("[ERROR] Run: sudo python3 profinet_scapy_correct.py ...")
        sys.exit(1)

    print(f"[INFO] === PROFINET DCP Discovery - Scapy Patterns v1.0.1 ===")
    print()

    devices = discover_devices(args.interface, timeout=args.timeout)

    if not devices:
        print("\n[ERROR] No devices found")
        sys.exit(1)

    print(f"\n[INFO] ✓✓✓ SUCCESS - Found {len(devices)} device(s) ✓✓✓")
    for dev in devices:
        print(f"[INFO]   {dev}")

    sys.exit(0)


if __name__ == '__main__':
    main()
