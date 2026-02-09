#!/usr/bin/env python3
"""
Complete PROFINET Controller - DCP Discovery + RPC Connect + Cyclic I/O

Version: 2.0.0
Date: 2026-02-09

Features:
- DCP Discovery (WORKING - tested on rtu-ec3b)
- RPC Connect for AR establishment
- Cyclic I/O data exchange

Usage:
    sudo python3 profinet_controller_complete.py --interface enp0s3 --device rtu-ec3b
"""

import sys
import argparse
import struct
import uuid
import time
from typing import List, Optional

try:
    from scapy.all import *
except ImportError:
    print("[ERROR] Scapy not installed")
    sys.exit(1)


# ===== DCP Discovery (WORKING) =====

class DCPDevice:
    """Discovered PROFINET device"""
    def __init__(self, mac_address, ip_address, device_name, vendor_id=None, device_id=None):
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.device_name = device_name
        self.vendor_id = vendor_id
        self.device_id = device_id

    def __repr__(self):
        return f"{self.device_name} @ {self.ip_address} ({self.mac_address})"


def build_dcp_identify() -> bytes:
    """Build DCP Identify All request - WORKING version"""
    frame_id = struct.pack(">H", 0xFEFE)
    service_id = struct.pack("B", 0x05)
    service_type = struct.pack("B", 0x00)
    xid = struct.pack(">I", 0x12345678)
    response_delay = struct.pack(">H", 0x0001)
    data_length = struct.pack(">H", 0x0004)
    option = struct.pack("B", 0xFF)
    suboption = struct.pack("B", 0xFF)
    block_length = struct.pack(">H", 0x0000)

    return (frame_id + service_id + service_type + xid +
            response_delay + data_length + option + suboption + block_length)


def parse_dcp_response(pkt) -> Optional[DCPDevice]:
    """Parse DCP response - WORKING version"""
    if not pkt.haslayer(Raw):
        return None

    data = bytes(pkt[Raw])

    if len(data) < 16:
        return None

    frame_id = struct.unpack(">H", data[0:2])[0]
    if frame_id != 0xFEFF:
        return None

    device_name = None
    ip_address = None
    mac_address = pkt.src
    vendor_id = None
    device_id = None

    # DCP blocks start at offset 12
    offset = 12

    while offset + 4 <= len(data):
        try:
            option = data[offset]
            suboption = data[offset + 1]
            block_length = struct.unpack(">H", data[offset + 2:offset + 4])[0]

            block_data_start = offset + 4
            block_data_end = block_data_start + block_length

            if block_data_end > len(data):
                break

            # Option 0x02 = Device Properties
            if option == 0x02:
                if suboption == 0x02 and block_length >= 2:  # Name of Station
                    name_data = data[block_data_start + 2:block_data_end]
                    device_name = name_data.rstrip(b'\x00').decode('utf-8', errors='ignore')
                elif suboption == 0x03 and block_length >= 6:  # Device ID
                    vendor_id = struct.unpack(">H", data[block_data_start + 2:block_data_start + 4])[0]
                    device_id = struct.unpack(">H", data[block_data_start + 4:block_data_start + 6])[0]

            # Option 0x01 = IP
            elif option == 0x01:
                if suboption == 0x02 and block_length >= 14:  # IP Parameter
                    ip_bytes = data[block_data_start + 2:block_data_start + 6]
                    ip_address = '.'.join(str(b) for b in ip_bytes)

            offset = block_data_end
            if block_length % 2 == 1:
                offset += 1

        except Exception:
            break

    if device_name and ip_address:
        return DCPDevice(mac_address, ip_address, device_name, vendor_id, device_id)

    return None


# ===== RPC Connect for AR Establishment =====

def build_rpc_connect(controller_mac: str, device_ip: str, device_mac: str,
                      device_name: str, controller_ip: str) -> bytes:
    """
    Build RPC Connect request

    This establishes an AR (Application Relationship) with the device
    """
    ar_uuid = uuid.uuid4()
    activity_uuid = uuid.uuid4()

    print(f"[INFO] AR UUID: {ar_uuid}")
    print(f"[INFO] Activity UUID: {activity_uuid}")

    # Build using Scapy layers where available, raw bytes where needed
    # Based on working Water-Controller format and Wireshark analysis

    # Use IP/UDP layers from Scapy
    pkt = (
        IP(src=controller_ip, dst=device_ip) /
        UDP(sport=34964, dport=34964)
    )

    # DCE/RPC header (manual - Scapy's RPC layers incomplete)
    rpc_version = 0x04
    packet_type = 0x00  # Request
    flags1 = 0x22  # From working packet
    flags2 = 0x00
    drep = bytes([0x10, 0x00, 0x00, 0x00])  # Little-endian

    # Build RPC payload manually
    # This is based on the working Water-Controller packet structure

    # For now, return a minimal connect that matches the working format
    # TODO: Complete AR/IOCR block construction

    rpc_payload = struct.pack(
        'BBBB',
        rpc_version,
        packet_type,
        flags1,
        flags2
    ) + drep

    pkt = pkt / Raw(load=rpc_payload)

    return bytes(pkt)


# ===== Main Controller Class =====

class PROFINETController:
    """Complete PROFINET Controller v2.0.0"""

    def __init__(self, interface: str):
        self.interface = interface
        self.mac = get_if_hwaddr(interface)
        self.ip = get_if_addr(interface)
        self.devices = []

        print(f"[INFO] === PROFINET Controller v2.0.0 ===")
        print(f"[INFO] Interface: {interface}")
        print(f"[INFO] Controller: {self.ip} ({self.mac})")

    def discover(self, timeout: float = 3.0) -> List[DCPDevice]:
        """Discover PROFINET devices using DCP"""
        print(f"\n[INFO] === Phase 1: DCP Discovery ===")

        payload = build_dcp_identify()
        pkt = Ether(type=0x8892, src=self.mac, dst='01:0e:cf:00:00:00') / Raw(load=payload)

        print(f"[INFO] Sending DCP Identify Request")

        ans, unans = srp(pkt, iface=self.interface, timeout=timeout, verbose=0, multi=True)

        devices = []
        seen = set()

        for sent, received in ans:
            device = parse_dcp_response(received)
            if device and device.mac_address not in seen:
                devices.append(device)
                seen.add(device.mac_address)
                print(f"[INFO] ✓ Discovered: {device}")

        self.devices = devices
        print(f"[INFO] Discovery complete: {len(devices)} device(s)")

        return devices

    def connect(self, device: DCPDevice) -> bool:
        """
        Connect to device and establish AR

        This is where RPC Connect happens
        """
        print(f"\n[INFO] === Phase 2: RPC Connect ===")
        print(f"[INFO] Connecting to {device.device_name} ({device.ip_address})")

        # Build RPC Connect packet
        # TODO: Complete implementation with proper AR/IOCR blocks

        print(f"[WARNING] RPC Connect not yet fully implemented")
        print(f"[INFO] Next steps:")
        print(f"[INFO]   1. Build AR Block with controller/device MACs and UUIDs")
        print(f"[INFO]   2. Build IOCR Blocks for input/output (Frame IDs 0x8000/0x8001)")
        print(f"[INFO]   3. Build Alarm CR Block")
        print(f"[INFO]   4. Build Expected Submodule Block (requires GSD file)")
        print(f"[INFO]   5. Send to {device.ip_address}:34964")

        return False

    def read_cyclic(self, device: DCPDevice) -> Optional[bytes]:
        """Read cyclic input data from device"""
        # TODO: Implement after AR is established
        pass

    def write_cyclic(self, device: DCPDevice, data: bytes):
        """Write cyclic output data to device"""
        # TODO: Implement after AR is established
        pass


def main():
    parser = argparse.ArgumentParser(
        description='Complete PROFINET Controller v2.0.0',
        epilog='''
Examples:
  # Discover all devices
  sudo python3 profinet_controller_complete.py --interface enp0s3

  # Connect to specific device
  sudo python3 profinet_controller_complete.py --interface enp0s3 --device rtu-ec3b --connect
        '''
    )

    parser.add_argument('--interface', '-i', required=True, help='Network interface')
    parser.add_argument('--device', '-d', help='Device name to connect to')
    parser.add_argument('--connect', action='store_true', help='Attempt RPC Connect')
    parser.add_argument('--timeout', '-t', type=float, default=3.0, help='Timeout (default: 3.0s)')

    args = parser.parse_args()

    # Check root
    import os
    if os.geteuid() != 0:
        print("[ERROR] Root required")
        sys.exit(1)

    # Create controller
    controller = PROFINETController(args.interface)

    # Discover devices
    devices = controller.discover(timeout=args.timeout)

    if not devices:
        print("\n[ERROR] No devices found")
        sys.exit(1)

    print(f"\n[INFO] ✓✓✓ DCP Discovery SUCCESS ✓✓✓")

    # If connect requested
    if args.connect:
        # Find target device
        if args.device:
            target = next((d for d in devices if d.device_name == args.device), None)
            if not target:
                print(f"[ERROR] Device '{args.device}' not found")
                sys.exit(1)
        else:
            target = devices[0]

        # Attempt connect
        success = controller.connect(target)

        if success:
            print(f"\n[INFO] ✓✓✓ RPC Connect SUCCESS ✓✓✓")
        else:
            print(f"\n[WARNING] RPC Connect needs implementation")

    sys.exit(0)


if __name__ == '__main__':
    main()
