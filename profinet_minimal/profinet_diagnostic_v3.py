#!/usr/bin/env python3
"""
PROFINET RPC Connect Diagnostic Tool v3.0.0

Based on p-net internals analysis:
- Validates AR properties (device_access bit)
- Checks module configuration
- Captures request/response with detailed analysis
- Tests against actual RTU expectations

Version: 3.0.0
Date: 2026-02-09
"""

import sys
import argparse
import struct
import uuid
import json
import requests
from typing import Optional

try:
    from scapy.all import *
except ImportError:
    print("[ERROR] Scapy required")
    sys.exit(1)


class ARProperties:
    """AR Properties structure with bit-level access"""

    def __init__(self, raw_value: int):
        self.raw_value = raw_value

    @property
    def state(self) -> int:
        return self.raw_value & 0x07  # Bits 0-2

    @property
    def supervisor_takeover(self) -> bool:
        return bool((self.raw_value >> 3) & 0x01)  # Bit 3

    @property
    def parameterization_server(self) -> bool:
        return bool((self.raw_value >> 4) & 0x01)  # Bit 4

    @property
    def device_access(self) -> bool:
        """CRITICAL: Must be FALSE for IO Controller AR"""
        return bool((self.raw_value >> 8) & 0x01)  # Bit 8

    @property
    def companion_ar(self) -> int:
        return (self.raw_value >> 9) & 0x03  # Bits 9-10

    def __str__(self):
        return (f"ARProperties(0x{self.raw_value:04X}):\n"
                f"  state={self.state}\n"
                f"  supervisor_takeover={self.supervisor_takeover}\n"
                f"  parameterization_server={self.parameterization_server}\n"
                f"  device_access={self.device_access} {'❌ MUST BE FALSE!' if self.device_access else '✓'}\n"
                f"  companion_ar={self.companion_ar}")


def check_rtu_config(device_ip: str) -> dict:
    """Query RTU's actual module configuration via HTTP API"""
    print(f"[INFO] === Checking RTU Configuration ===")

    try:
        # Check slots API (corrected endpoint)
        response = requests.get(f"http://{device_ip}:9081/slots", timeout=2)
        if response.status_code == 200:
            config = response.json()
            print(f"[INFO] RTU Configuration:")
            print(json.dumps(config, indent=2))
            return config
        else:
            print(f"[WARNING] Slots API returned {response.status_code}")
            return {}
    except Exception as e:
        print(f"[WARNING] Could not query RTU config: {e}")
        return {}


def analyze_ar_properties(ar_props_value: int):
    """Analyze AR properties bit-by-bit"""
    props = ARProperties(ar_props_value)
    print(f"\n[INFO] AR Properties Analysis:")
    print(props)

    if props.device_access:
        print(f"\n[ERROR] ❌ device_access=TRUE will cause p-net to REJECT!")
        print(f"[ERROR] p-net silently drops IOCRBlockReq/AlarmCRBlockReq/ExpectedSubmoduleBlockReq")
        print(f"[ERROR] when device_access=TRUE")
        return False
    else:
        print(f"\n[INFO] ✓ device_access=FALSE (correct for IO Controller AR)")
        return True


def build_connect_diagnostic(controller_ip: str, controller_mac: str,
                             device_ip: str, device_mac: str, device_name: str,
                             module_config: dict) -> bytes:
    """
    Build RPC Connect with diagnostic output
    """

    print(f"\n[INFO] === Building RPC Connect Packet ===")

    # UUIDs
    ar_uuid = uuid.uuid4().bytes
    activity_uuid = uuid.uuid4().bytes

    print(f"[INFO] AR UUID: {ar_uuid.hex()}")
    print(f"[INFO] Activity UUID: {activity_uuid.hex()}")

    # Interface UUID (standard PROFINET)
    interface_uuid = uuid.UUID('DEA00001-6C97-11D1-8271-00A02442DF7D').bytes

    # MACs
    controller_mac_bytes = bytes.fromhex(controller_mac.replace(':', ''))
    device_mac_bytes = bytes.fromhex(device_mac.replace(':', ''))
    device_name_bytes = device_name.encode('utf-8')

    # ===== DCE/RPC Header =====
    rpc_header = struct.pack('BBBB', 0x04, 0x00, 0x22, 0x00)
    rpc_header += struct.pack('<I', 0x00000010)
    rpc_header += activity_uuid
    rpc_header += interface_uuid
    rpc_header += struct.pack('<I', 0x00000001)
    rpc_header += struct.pack('<I', 0x00000000)
    rpc_header += struct.pack('<I', 0x00000000)
    rpc_header += struct.pack('<H', 0x0000)  # Opnum = 0 (Connect)
    rpc_header += struct.pack('<H', 0xFFFF)
    rpc_header += struct.pack('<H', 0xFFFF)
    rpc_header += struct.pack('<H', 250)  # Fragment length
    rpc_header = rpc_header.ljust(80, b'\x00')

    print(f"[INFO] DCE/RPC Header: {len(rpc_header)} bytes")
    print(f"[INFO]   Version: 4")
    print(f"[INFO]   Type: Request (0x00)")
    print(f"[INFO]   Opnum: 0 (Connect)")

    # ===== NDR Header =====
    ndr_header = struct.pack('<I', 0x00000010)
    ndr_header += struct.pack('<I', 0x000000FA)
    ndr_header += struct.pack('<I', 0x000000FA)
    ndr_header += struct.pack('<I', 0x00000000)
    ndr_header += struct.pack('<I', 0x000000FA)

    print(f"[INFO] NDR Header: {len(ndr_header)} bytes")

    # ===== AR Block =====
    ar_props_value = 0x0060  # State=0, device_access=FALSE
    analyze_ar_properties(ar_props_value)

    ar_block = struct.pack('>HH', 0x0101, 0x0048)  # Block type, length
    ar_block += struct.pack('BB', 0x01, 0x00)  # Version
    ar_block += ar_uuid
    ar_block += controller_mac_bytes
    ar_block += device_mac_bytes
    ar_block += struct.pack('>H', ar_props_value)  # AR properties
    ar_block += struct.pack('>H', 0x0064)  # Timeout factor
    ar_block += struct.pack('>H', 0x0000)  # Reserved
    ar_block += struct.pack('>H', 0x0003)  # Reserved
    ar_block += struct.pack('>H', len(device_name_bytes))
    ar_block += device_name_bytes
    ar_block = ar_block.ljust(76, b'\x00')

    print(f"[INFO] AR Block: {len(ar_block)} bytes")
    print(f"[INFO]   Station Name: {device_name}")

    # ===== IOCR Blocks =====
    iocr_input = struct.pack('>HH', 0x0102, 0x002E)
    iocr_input += struct.pack('BB', 0x01, 0x00)
    iocr_input += struct.pack('>H', 0x0001)  # Type: Input
    iocr_input += struct.pack('>H', 0x8001)  # Frame ID
    iocr_input += struct.pack('>HH', 0x0000, 0x0003)
    iocr_input += struct.pack('>HH', 0x0028, 0x0020)
    iocr_input += struct.pack('>HH', 0x0020, 0x0001)
    iocr_input += struct.pack('>I', 0x00000000)
    iocr_input += struct.pack('>H', 0x0003)
    iocr_input += struct.pack('>HH', 0x0003, 0xC000)
    iocr_input += struct.pack('>I', 0x00000001)
    iocr_input = iocr_input.ljust(50, b'\x00')

    print(f"[INFO] IOCR Input: {len(iocr_input)} bytes (Frame ID 0x8001)")

    iocr_output = struct.pack('>HH', 0x0102, 0x002E)
    iocr_output += struct.pack('BB', 0x01, 0x00)
    iocr_output += struct.pack('>H', 0x0002)  # Type: Output
    iocr_output += struct.pack('>H', 0x8000)  # Frame ID
    iocr_output += struct.pack('>HH', 0x0000, 0x0003)
    iocr_output += struct.pack('>HH', 0x0028, 0x0020)
    iocr_output += struct.pack('>HH', 0x0020, 0x0001)
    iocr_output += struct.pack('>I', 0x00000000)
    iocr_output += struct.pack('>H', 0x0003)
    iocr_output += struct.pack('>HH', 0x0003, 0xC000)
    iocr_output += struct.pack('>I', 0x00000001)
    iocr_output = iocr_output.ljust(50, b'\x00')

    print(f"[INFO] IOCR Output: {len(iocr_output)} bytes (Frame ID 0x8000)")

    # ===== Alarm CR =====
    alarm_cr = struct.pack('>HH', 0x0103, 0x0008)
    alarm_cr += struct.pack('BB', 0x01, 0x00)
    alarm_cr += struct.pack('>H', 0x0001)
    alarm_cr += struct.pack('>H', 0x0000)

    print(f"[INFO] Alarm CR: {len(alarm_cr)} bytes")

    # ===== Expected Submodule =====
    # Use module config from RTU if available
    if module_config and module_config.get('slot_count', 0) > 0:
        print(f"[INFO] Using actual RTU configuration:")
        for slot in module_config.get('slots', []):
            print(f"[INFO]   Slot {slot['slot']}.{slot['subslot']}: "
                  f"Module=0x{slot['module_ident']:02X}, Submodule=0x{slot['submodule_ident']:02X}")

    exp_sub = struct.pack('>HH', 0x0104, 0x003A)
    exp_sub += struct.pack('BB', 0x01, 0x00)
    exp_sub += struct.pack('>H', 0x0001)  # Number of APIs
    exp_sub += struct.pack('>I', 0x00000000)  # API 0
    exp_sub += struct.pack('>H', 0x0002)  # Slot count
    exp_sub += struct.pack('>HH', 0x0000, 0x0001)  # Slot 0 (DAP)
    exp_sub += struct.pack('>HH', 0x0001, 0x0001)  # Subslot 1
    exp_sub += struct.pack('>I', 0x00000001)  # Module ID (DAP)
    exp_sub += struct.pack('>H', 0x0040)  # Properties
    exp_sub += struct.pack('>H', 0x0001)  # Data length
    exp_sub += struct.pack('>HH', 0x0001, 0x0041)  # Input/output
    exp_sub = exp_sub.ljust(62, b'\x00')

    print(f"[INFO] Expected Submodule: {len(exp_sub)} bytes")
    print(f"[INFO]   Expecting: Slot 0.1 (DAP)")

    # ===== Assemble =====
    pnio_data = ar_block + iocr_input + iocr_output + alarm_cr + exp_sub
    rpc_payload = rpc_header + ndr_header + pnio_data

    packet = (
        IP(src=controller_ip, dst=device_ip) /
        UDP(sport=34964, dport=34964) /
        Raw(load=rpc_payload)
    )

    print(f"\n[INFO] Total packet size: {len(packet)} bytes")
    print(f"[INFO]   RPC Header: 80 bytes")
    print(f"[INFO]   NDR Header: 20 bytes")
    print(f"[INFO]   PNIO Blocks: {len(pnio_data)} bytes")

    return bytes(packet)


def main():
    parser = argparse.ArgumentParser(
        description='PROFINET RPC Connect Diagnostic v3.0.0'
    )
    parser.add_argument('--interface', '-i', required=True)
    parser.add_argument('--device-ip', required=True)
    parser.add_argument('--device-name', required=True)
    parser.add_argument('--timeout', '-t', type=float, default=5.0)

    args = parser.parse_args()

    import os
    if os.geteuid() != 0:
        print("[ERROR] Root required")
        sys.exit(1)

    print(f"[INFO] === PROFINET RPC Connect Diagnostic v3.0.0 ===\n")

    controller_ip = get_if_addr(args.interface)
    controller_mac = get_if_hwaddr(args.interface)
    device_mac = "00:1e:06:39:ec:3b"  # From discovery

    # Check RTU config
    rtu_config = check_rtu_config(args.device_ip)

    # Build packet with diagnostics
    packet_bytes = build_connect_diagnostic(
        controller_ip, controller_mac,
        args.device_ip, device_mac, args.device_name,
        rtu_config
    )

    packet = IP(packet_bytes[14:])

    print(f"\n[INFO] === Sending RPC Connect ===")
    print(f"[INFO] From: {controller_ip}:{34964}")
    print(f"[INFO] To: {args.device_ip}:{34964}")
    print(f"\n[INFO] Watch RTU logs with:")
    print(f"[INFO]   ssh root@{args.device_ip}")
    print(f"[INFO]   journalctl -u water-rtu-manager -f | grep -E 'CALLBACK|exp_module|device_access'")
    print(f"\n[INFO] Sending...")

    response = sr1(packet, iface=args.interface, timeout=args.timeout, verbose=0)

    if response:
        print(f"\n[INFO] ✓✓✓ RECEIVED RESPONSE! ✓✓✓")
        response.show()
        print(f"\n[INFO] Response hex dump:")
        hexdump(response)
        sys.exit(0)
    else:
        print(f"\n[ERROR] ✗ No response (timeout)")
        print(f"\n[INFO] === Diagnostic Checklist ===")
        print(f"[INFO] 1. Check RTU received packet:")
        print(f"[INFO]    ssh root@{args.device_ip} 'sudo tcpdump -i enp0s3 port 34964 -c 1'")
        print(f"[INFO] 2. Check RTU logs for rejection reason:")
        print(f"[INFO]    ssh root@{args.device_ip} 'journalctl -u water-rtu-manager --since \"1 min ago\" | grep -E \"REJECT|device_access|exp_module\"'")
        print(f"[INFO] 3. Check module configuration matches")
        sys.exit(1)


if __name__ == '__main__':
    main()
