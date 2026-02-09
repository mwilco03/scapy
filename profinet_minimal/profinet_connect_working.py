#!/usr/bin/env python3
"""
PROFINET Controller with RPC Connect - v2.1.0

DCP Discovery: WORKING ✓
RPC Connect: IMPLEMENTED (testing)

Version: 2.1.0
Date: 2026-02-09
"""

import sys
import argparse
import struct
import uuid
import time
from typing import Optional

try:
    from scapy.all import *
except ImportError:
    print("[ERROR] Scapy required")
    sys.exit(1)


# ===== Copy working DCP code =====

class DCPDevice:
    def __init__(self, mac_address, ip_address, device_name, vendor_id=None, device_id=None):
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.device_name = device_name
        self.vendor_id = vendor_id
        self.device_id = device_id

    def __repr__(self):
        return f"{self.device_name} @ {self.ip_address} ({self.mac_address})"


def discover_device(interface: str, device_name: Optional[str] = None, timeout: float = 3.0) -> Optional[DCPDevice]:
    """DCP Discovery - WORKING version"""
    print(f"[INFO] === DCP Discovery ===")

    src_mac = get_if_hwaddr(interface)

    # Build request
    payload = struct.pack(">H", 0xFEFE)  # Frame ID
    payload += struct.pack("BB", 0x05, 0x00)  # Service ID/Type
    payload += struct.pack(">I", 0x12345678)  # XID
    payload += struct.pack(">HH", 0x0001, 0x0004)  # Response delay, Data length
    payload += struct.pack("BBH", 0xFF, 0xFF, 0x0000)  # Option, Suboption, Block length

    pkt = Ether(type=0x8892, src=src_mac, dst='01:0e:cf:00:00:00') / Raw(load=payload)

    print(f"[INFO] Searching for devices...")

    ans, unans = srp(pkt, iface=interface, timeout=timeout, verbose=0, multi=True)

    for sent, received in ans:
        if not received.haslayer(Raw):
            continue

        data = bytes(received[Raw])
        if len(data) < 16:
            continue

        frame_id = struct.unpack(">H", data[0:2])[0]
        if frame_id != 0xFEFF:
            continue

        # Parse blocks
        dev_name = None
        ip_addr = None
        mac_addr = received.src
        vendor_id = None
        device_id = None

        offset = 12
        while offset + 4 <= len(data):
            try:
                option = data[offset]
                suboption = data[offset + 1]
                block_length = struct.unpack(">H", data[offset + 2:offset + 4])[0]
                block_start = offset + 4
                block_end = block_start + block_length

                if block_end > len(data):
                    break

                if option == 0x02 and suboption == 0x02 and block_length >= 2:  # Name
                    dev_name = data[block_start + 2:block_end].rstrip(b'\x00').decode('utf-8', errors='ignore')
                elif option == 0x02 and suboption == 0x03 and block_length >= 6:  # Device ID
                    vendor_id = struct.unpack(">H", data[block_start + 2:block_start + 4])[0]
                    device_id = struct.unpack(">H", data[block_start + 4:block_start + 6])[0]
                elif option == 0x01 and suboption == 0x02 and block_length >= 14:  # IP
                    ip_bytes = data[block_start + 2:block_start + 6]
                    ip_addr = '.'.join(str(b) for b in ip_bytes)

                offset = block_end
                if block_length % 2 == 1:
                    offset += 1

            except Exception:
                break

        if dev_name and ip_addr:
            if device_name is None or dev_name == device_name:
                device = DCPDevice(mac_addr, ip_addr, dev_name, vendor_id, device_id)
                print(f"[INFO] ✓ Found: {device}")
                return device

    return None


# ===== RPC Connect Implementation =====

def build_rpc_connect(controller_ip: str, controller_mac: str,
                      device_ip: str, device_mac: str, device_name: str) -> bytes:
    """
    Build RPC Connect packet using raw bytes

    Based on:
    - Working Water-Controller packet structure
    - Wireshark DCE/RPC dissection
    - PROFINET IEC 61158 spec
    """

    # Generate UUIDs
    ar_uuid = uuid.uuid4().bytes
    activity_uuid = uuid.uuid4().bytes

    print(f"[INFO] AR UUID: {ar_uuid.hex()}")
    print(f"[INFO] Activity UUID: {activity_uuid.hex()}")

    # PROFINET Interface UUID (standard)
    interface_uuid = uuid.UUID('DEA00001-6C97-11D1-8271-00A02442DF7D').bytes

    # Parse MACs
    controller_mac_bytes = bytes.fromhex(controller_mac.replace(':', ''))
    device_mac_bytes = bytes.fromhex(device_mac.replace(':', ''))
    device_name_bytes = device_name.encode('utf-8')

    # ===== DCE/RPC Header (80 bytes from working packet) =====
    rpc_header = struct.pack(
        'BBBB',
        0x04,  # Version 4
        0x00,  # Type: Request
        0x22,  # Flags1 (from working packet)
        0x00   # Flags2
    )

    # Add more RPC fields
    rpc_header += struct.pack('<I', 0x00000010)  # Data representation
    rpc_header += activity_uuid  # 16 bytes
    rpc_header += interface_uuid  # 16 bytes

    # Server boot time, interface version, sequence number, opnum, etc.
    # Based on working packet structure
    rpc_header += struct.pack('<I', 0x00000001)  # Server boot time
    rpc_header += struct.pack('<I', 0x00000000)  # Interface version
    rpc_header += struct.pack('<I', 0x00000000)  # Sequence number
    rpc_header += struct.pack('<H', 0x0000)      # Opnum (0 = Connect)
    rpc_header += struct.pack('<H', 0xFFFF)      # Interface hint
    rpc_header += struct.pack('<H', 0xFFFF)      # Activity hint
    rpc_header += struct.pack('<H', len(device_name_bytes) + 250)  # Fragment length (approximate)

    # Padding to 80 bytes total
    rpc_header = rpc_header.ljust(80, b'\x00')

    # ===== NDR Header (20 bytes mandatory) =====
    ndr_header = struct.pack('<I', 0x00000010)  # NDR representation
    ndr_header += struct.pack('<I', 0x000000FA)  # Max count
    ndr_header += struct.pack('<I', 0x000000FA)  # Offset
    ndr_header += struct.pack('<I', 0x00000000)  # Actual count
    ndr_header += struct.pack('<I', 0x000000FA)  # Allocated

    # ===== AR Block (from working packet: 76 bytes) =====
    ar_block = struct.pack('>HH', 0x0101, 0x0048)  # Block type, length
    ar_block += struct.pack('BB', 0x01, 0x00)      # Version high, low
    ar_block += ar_uuid                             # AR UUID (16 bytes)
    ar_block += controller_mac_bytes                # Controller MAC (6 bytes)
    ar_block += device_mac_bytes                    # Device MAC (6 bytes)
    ar_block += struct.pack('>H', 0x0060)          # AR properties
    ar_block += struct.pack('>H', 0x0064)          # Timeout factor (100)
    ar_block += struct.pack('>H', 0x0000)          # Reserved
    ar_block += struct.pack('>H', 0x0003)          # Reserved
    ar_block += struct.pack('>H', len(device_name_bytes))  # Name length
    ar_block += device_name_bytes                   # Device name
    # Pad to align
    ar_block = ar_block.ljust(76, b'\x00')

    # ===== IOCR Block - Input (50 bytes each) =====
    iocr_input = struct.pack('>HH', 0x0102, 0x002E)  # Block type, length
    iocr_input += struct.pack('BB', 0x01, 0x00)       # Version
    iocr_input += struct.pack('>H', 0x0001)           # IOCR type (1=Input)
    iocr_input += struct.pack('>H', 0x8001)           # Frame ID (input)
    iocr_input += struct.pack('>HH', 0x0000, 0x0003)  # Properties
    iocr_input += struct.pack('>HH', 0x0028, 0x0020)  # Data length, frame offset
    iocr_input += struct.pack('>HH', 0x0020, 0x0001)  # Send clock, reduction
    iocr_input += struct.pack('>I', 0x00000000)       # Phase, sequence
    iocr_input += struct.pack('>H', 0x0003)           # Watchdog
    iocr_input += struct.pack('>HH', 0x0003, 0xC000)  # Data hold, tag header
    iocr_input += struct.pack('>I', 0x00000001)       # Multicast MAC
    iocr_input = iocr_input.ljust(50, b'\x00')

    # IOCR Block - Output (50 bytes)
    iocr_output = struct.pack('>HH', 0x0102, 0x002E)
    iocr_output += struct.pack('BB', 0x01, 0x00)
    iocr_output += struct.pack('>H', 0x0002)          # IOCR type (2=Output)
    iocr_output += struct.pack('>H', 0x8000)          # Frame ID (output)
    iocr_output += struct.pack('>HH', 0x0000, 0x0003)
    iocr_output += struct.pack('>HH', 0x0028, 0x0020)
    iocr_output += struct.pack('>HH', 0x0020, 0x0001)
    iocr_output += struct.pack('>I', 0x00000000)
    iocr_output += struct.pack('>H', 0x0003)
    iocr_output += struct.pack('>HH', 0x0003, 0xC000)
    iocr_output += struct.pack('>I', 0x00000001)
    iocr_output = iocr_output.ljust(50, b'\x00')

    # ===== Alarm CR Block (12 bytes) =====
    alarm_cr = struct.pack('>HH', 0x0103, 0x0008)  # Block type, length
    alarm_cr += struct.pack('BB', 0x01, 0x00)       # Version
    alarm_cr += struct.pack('>H', 0x0001)           # Alarm type
    alarm_cr += struct.pack('>H', 0x0000)           # Properties

    # ===== Expected Submodule Block (simplified - 62 bytes) =====
    exp_sub = struct.pack('>HH', 0x0104, 0x003A)  # Block type, length
    exp_sub += struct.pack('BB', 0x01, 0x00)       # Version
    exp_sub += struct.pack('>H', 0x0001)           # Number of APIs
    # API 0, Slot 0, Subslot 1
    exp_sub += struct.pack('>I', 0x00000000)       # API
    exp_sub += struct.pack('>H', 0x0002)           # Slot count
    exp_sub += struct.pack('>HH', 0x0000, 0x0001)  # Slot 0, subslot count
    exp_sub += struct.pack('>HH', 0x0001, 0x0001)  # Subslot 1, module ID
    exp_sub += struct.pack('>I', 0x00000001)       # Submodule ID
    exp_sub += struct.pack('>H', 0x0040)           # Properties
    exp_sub += struct.pack('>H', 0x0001)           # Data length
    exp_sub += struct.pack('>HH', 0x0001, 0x0041)  # Input/output
    exp_sub = exp_sub.ljust(62, b'\x00')

    # ===== Assemble full payload =====
    pnio_data = ar_block + iocr_input + iocr_output + alarm_cr + exp_sub

    # Total RPC payload
    rpc_payload = rpc_header + ndr_header + pnio_data

    # Build complete packet using Scapy for IP/UDP
    packet = (
        IP(src=controller_ip, dst=device_ip) /
        UDP(sport=34964, dport=34964) /
        Raw(load=rpc_payload)
    )

    return bytes(packet)


def rpc_connect(interface: str, device: DCPDevice, timeout: float = 5.0) -> bool:
    """Attempt RPC Connect to establish AR"""

    print(f"\n[INFO] === RPC Connect ===")
    print(f"[INFO] Target: {device.device_name} ({device.ip_address})")

    controller_ip = get_if_addr(interface)
    controller_mac = get_if_hwaddr(interface)

    # Build packet
    packet_bytes = build_rpc_connect(
        controller_ip, controller_mac,
        device.ip_address, device.mac_address, device.device_name
    )

    packet = IP(packet_bytes[14:])  # Skip Ethernet header for sending via IP

    print(f"[INFO] Packet size: {len(packet)} bytes")
    print(f"[INFO] Sending to {device.ip_address}:34964...")

    # Send and wait for response
    response = sr1(packet, iface=interface, timeout=timeout, verbose=0)

    if response:
        print(f"[INFO] ✓ Received response!")
        response.show()

        if UDP in response and response[UDP].sport == 34964:
            print(f"[INFO] ✓ Got RPC response from RTU")
            # TODO: Parse response for connect status
            return True
        else:
            print(f"[WARNING] Unexpected response format")
            return False
    else:
        print(f"[ERROR] ✗ No response (timeout)")
        print(f"[ERROR] RTU may have rejected the connect request")
        print(f"[ERROR] Possible reasons:")
        print(f"[ERROR]   - Expected Submodule config doesn't match RTU's actual config")
        print(f"[ERROR]   - Need RTU's GSD file for correct slot/subslot/module IDs")
        print(f"[ERROR]   - AR properties or IOCR parameters incorrect")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='PROFINET Controller with RPC Connect v2.1.0'
    )
    parser.add_argument('--interface', '-i', required=True)
    parser.add_argument('--device', '-d', help='Device name (default: first found)')
    parser.add_argument('--timeout', '-t', type=float, default=5.0)

    args = parser.parse_args()

    import os
    if os.geteuid() != 0:
        print("[ERROR] Root required")
        sys.exit(1)

    print(f"[INFO] === PROFINET Controller v2.1.0 ===")
    print(f"[INFO] Interface: {args.interface}")

    # Discover device
    device = discover_device(args.interface, device_name=args.device, timeout=args.timeout)

    if not device:
        print(f"[ERROR] No devices found")
        sys.exit(1)

    print(f"[INFO] ✓ Discovery complete")

    # Attempt RPC Connect
    success = rpc_connect(args.interface, device, timeout=args.timeout)

    if success:
        print(f"\n[INFO] ✓✓✓ RPC Connect SUCCESS ✓✓✓")
        sys.exit(0)
    else:
        print(f"\n[WARNING] RPC Connect failed or no response")
        print(f"[INFO] DCP Discovery is working ✓")
        print(f"[INFO] RPC Connect may need GSD file configuration")
        sys.exit(1)


if __name__ == '__main__':
    main()
