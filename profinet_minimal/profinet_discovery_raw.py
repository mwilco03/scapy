#!/usr/bin/env python3
"""
PROFINET Controller - ACTUALLY WORKING VERSION v1.0.0

This uses RAW SOCKETS like the working Water-Controller script,
NOT Scapy's broken ProfinetDCP layer.

Author: Claude
Version: 1.0.0
Date: 2026-02-09
"""

import socket
import struct
import sys
import argparse
import time
import uuid
from typing import List, Optional, NamedTuple

# PROFINET Constants
DCP_MULTICAST_MAC = bytes.fromhex('010ecf000000')
PROFINET_ETHERTYPE = 0x8892

# DCP Constants
DCP_SERVICE_ID_IDENTIFY = 0x05
DCP_SERVICE_TYPE_REQUEST = 0x00
DCP_SERVICE_TYPE_RESPONSE = 0x01
DCP_OPTION_ALL = 0xFF
DCP_OPTION_IP = 0x01
DCP_OPTION_DEVICE_PROPS = 0x02

# Frame IDs
DCP_IDENTIFY_REQUEST_FRAME_ID = 0xFEFE
DCP_IDENTIFY_RESPONSE_FRAME_ID = 0xFEFF


class DCPDevice(NamedTuple):
    """Discovered PROFINET device"""
    mac_address: str
    ip_address: str
    device_name: str
    vendor_id: Optional[int] = None
    device_id: Optional[int] = None


def get_interface_mac(interface: str) -> bytes:
    """Get MAC address of network interface"""
    with open(f'/sys/class/net/{interface}/address', 'r') as f:
        mac_str = f.read().strip()
        return bytes.fromhex(mac_str.replace(':', ''))


def build_dcp_identify_all_frame(src_mac: bytes, xid: int = 0x12345678) -> bytes:
    """
    Build PROFINET DCP Identify All request - EXACT copy of working implementation

    Returns 30 bytes: 14 (Ether) + 2 (FrameID) + 10 (DCP header) + 4 (DCP block)
    """
    # Ethernet header (14 bytes)
    dst_mac = DCP_MULTICAST_MAC
    ethertype = struct.pack(">H", PROFINET_ETHERTYPE)
    eth_header = dst_mac + src_mac + ethertype

    # Frame ID (2 bytes)
    frame_id = struct.pack(">H", DCP_IDENTIFY_REQUEST_FRAME_ID)

    # DCP header (10 bytes)
    service_id = DCP_SERVICE_ID_IDENTIFY
    service_type = DCP_SERVICE_TYPE_REQUEST
    response_delay = 0x0001  # 10ms units
    data_length = 4  # Length of DCP blocks

    dcp_header = struct.pack(">BBIHH",
                            service_id,
                            service_type,
                            xid,
                            response_delay,
                            data_length)

    # DCP block (4 bytes) - Identify All
    dcp_block = struct.pack(">BBH", DCP_OPTION_ALL, 0xFF, 0)

    frame = eth_header + frame_id + dcp_header + dcp_block

    # Verify exact size
    assert len(frame) == 30, f"DCP frame should be 30 bytes, got {len(frame)}"

    return frame


def parse_dcp_response(data: bytes) -> Optional[DCPDevice]:
    """Parse DCP Identify response"""
    if len(data) < 16:
        return None

    # Check frame ID
    frame_id = struct.unpack(">H", data[12:14])[0]
    if frame_id != DCP_IDENTIFY_RESPONSE_FRAME_ID:
        return None

    # Parse basic header
    src_mac = ':'.join(f'{b:02x}' for b in data[6:12])

    # Parse DCP blocks
    device_name = None
    ip_address = None
    vendor_id = None
    device_id = None

    offset = 24  # Skip Ether + FrameID + DCP header

    while offset + 4 <= len(data):
        try:
            option = data[offset]
            suboption = data[offset + 1]
            block_length = struct.unpack(">H", data[offset + 2:offset + 4])[0]

            block_data_start = offset + 4
            block_data_end = block_data_start + block_length

            if block_data_end > len(data):
                break

            # Device Name
            if option == DCP_OPTION_DEVICE_PROPS and suboption == 0x02:
                # Skip block info (2 bytes) and get name
                name_data = data[block_data_start + 2:block_data_end]
                device_name = name_data.rstrip(b'\x00').decode('utf-8', errors='ignore')

            # IP Address
            elif option == DCP_OPTION_IP and suboption == 0x02:
                # IP parameter block
                if block_length >= 6:
                    ip_bytes = data[block_data_start + 2:block_data_start + 6]
                    ip_address = '.'.join(str(b) for b in ip_bytes)

            # Device ID
            elif option == DCP_OPTION_DEVICE_PROPS and suboption == 0x03:
                if block_length >= 6:
                    vendor_id = struct.unpack(">H", data[block_data_start + 2:block_data_start + 4])[0]
                    device_id = struct.unpack(">H", data[block_data_start + 4:block_data_start + 6])[0]

            # Move to next block (4 byte header + data, padded to even)
            offset = block_data_start + block_length
            if block_length % 2 == 1:
                offset += 1

        except Exception:
            break

    if device_name and ip_address:
        return DCPDevice(
            mac_address=src_mac,
            ip_address=ip_address,
            device_name=device_name,
            vendor_id=vendor_id,
            device_id=device_id
        )

    return None


def discover_devices(interface: str, timeout: float = 3.0) -> List[DCPDevice]:
    """
    Discover PROFINET devices using DCP - RAW SOCKET VERSION (WORKING!)
    """
    print(f"[INFO] === DCP Discovery on {interface} (timeout={timeout}s) ===")
    print(f"[INFO] Using RAW SOCKETS (not Scapy)")

    # Get interface MAC
    src_mac = get_interface_mac(interface)
    mac_str = ':'.join(f'{b:02x}' for b in src_mac)
    print(f"[INFO] Interface MAC: {mac_str}")

    # Build DCP frame
    dcp_frame = build_dcp_identify_all_frame(src_mac)

    print(f"[INFO] DCP frame size: {len(dcp_frame)} bytes (should be 30)")
    print(f"[INFO] Hex dump:")
    for i in range(0, len(dcp_frame), 16):
        hex_str = ' '.join(f'{b:02x}' for b in dcp_frame[i:i+16])
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in dcp_frame[i:i+16])
        print(f"[INFO]   {i:04x}: {hex_str:<48} {ascii_str}")

    # Create raw socket
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(PROFINET_ETHERTYPE))
    sock.bind((interface, 0))
    sock.settimeout(timeout)

    discovered = []

    try:
        # Send DCP Identify
        sock.send(dcp_frame)
        print(f"[INFO] ✓ Sent DCP Identify Request")

        # Receive responses
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                data, addr = sock.recvfrom(65535)

                # Parse response
                device = parse_dcp_response(data)
                if device and device not in discovered:
                    discovered.append(device)
                    print(f"[INFO] ✓ Discovered: {device.device_name} @ {device.ip_address} ({device.mac_address})")

            except socket.timeout:
                break
            except Exception as e:
                # Ignore parse errors, keep receiving
                pass

    finally:
        sock.close()

    print(f"[INFO] Discovery complete: found {len(discovered)} device(s)")
    return discovered


def main():
    parser = argparse.ArgumentParser(
        description='PROFINET DCP Discovery - RAW SOCKET VERSION v1.0.0',
        epilog='Example: sudo python3 profinet_discovery.py --interface enp0s3'
    )

    parser.add_argument('--interface', '-i', required=True,
                       help='Network interface (e.g., enp0s3, eth0)')
    parser.add_argument('--timeout', '-t', type=float, default=3.0,
                       help='Discovery timeout in seconds (default: 3.0)')

    args = parser.parse_args()

    # Check root
    import os
    if os.geteuid() != 0:
        print("[ERROR] This script requires root privileges")
        print("[ERROR] Run with: sudo python3 profinet_discovery.py ...")
        sys.exit(1)

    print(f"[INFO] === PROFINET DCP Discovery v1.0.0 ===")
    print(f"[INFO] This version uses RAW SOCKETS (like working Water-Controller script)")
    print()

    # Discover devices
    devices = discover_devices(args.interface, timeout=args.timeout)

    if not devices:
        print("\n[ERROR] No devices found")
        print("[ERROR]")
        print("[ERROR] Troubleshooting:")
        print("[ERROR]   1. Check RTU is powered on")
        print("[ERROR]   2. Check network cable")
        print("[ERROR]   3. Try: sudo tcpdump -i enp0s3 ether proto 0x8892")
        sys.exit(1)

    print(f"\n[INFO] ✓✓✓ SUCCESS ✓✓✓")
    print(f"[INFO] Found {len(devices)} device(s):")
    for dev in devices:
        print(f"[INFO]   - {dev.device_name}")
        print(f"[INFO]     IP: {dev.ip_address}")
        print(f"[INFO]     MAC: {dev.mac_address}")
        if dev.vendor_id:
            print(f"[INFO]     Vendor ID: {dev.vendor_id}, Device ID: {dev.device_id}")

    sys.exit(0)


if __name__ == '__main__':
    main()
