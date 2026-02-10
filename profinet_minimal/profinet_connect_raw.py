#!/usr/bin/env python3
"""
PROFINET RPC Connect - Raw Implementation
Based on the comprehensive PROFINET implementation guide

Uses struct.pack() instead of Scapy layers to ensure exact byte layout
"""

import sys
import argparse
import struct
import socket
import uuid as uuid_module
import requests

try:
    from scapy.all import Ether, IP, UDP, Raw, srp, get_if_hwaddr, get_if_addr, hexdump
except ImportError:
    print("[ERROR] Scapy required")
    sys.exit(1)


# PROFINET Constants
PNIO_DEVICE_INTERFACE_UUID = bytes([
    0xDE, 0xA0, 0x00, 0x01, 0x6C, 0x97, 0x11, 0xD1,
    0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D
])


def uuid_swap_fields(uuid_bytes: bytes) -> bytes:
    """
    Swap UUID fields from big-endian to little-endian per DREP=0x10

    Critical for PROFINET: p-net decodes UUIDs using pf_get_uuid() which
    applies the reverse swap based on DREP.

    UUID Structure (16 bytes):
    - time_low (bytes 0-3): 4-byte integer, swap to LE
    - time_mid (bytes 4-5): 2-byte integer, swap to LE
    - time_hi_and_version (bytes 6-7): 2-byte integer, swap to LE
    - clock_seq + node (bytes 8-15): UNCHANGED
    """
    uuid = bytearray(uuid_bytes)

    # time_low (bytes 0-3): reverse 4 bytes
    uuid[0], uuid[3] = uuid[3], uuid[0]
    uuid[1], uuid[2] = uuid[2], uuid[1]

    # time_mid (bytes 4-5): reverse 2 bytes
    uuid[4], uuid[5] = uuid[5], uuid[4]

    # time_hi_and_version (bytes 6-7): reverse 2 bytes
    uuid[6], uuid[7] = uuid[7], uuid[6]

    # clock_seq + node (bytes 8-15): UNCHANGED

    return bytes(uuid)


def build_rpc_header(ar_uuid: bytes, activity_uuid: bytes, fragment_length: int) -> bytes:
    """
    Build 80-byte DCE/RPC header for PROFINET

    CRITICAL: Interface UUID must be swapped to little-endian
    Expected wire format: 01 00 A0 DE 97 6C D1 11...
    """
    header = bytearray(80)

    # Offset 0-7: Basic header
    header[0] = 4                           # version
    header[1] = 0                           # packet_type (0=Request)
    header[2] = 0x20                        # flags1 (LAST_FRAG | IDEMPOTENT)
    header[3] = 0x00                        # flags2
    header[4] = 0x10                        # drep[0] (LITTLE_ENDIAN) ← CRITICAL
    header[5] = 0x00                        # drep[1] (ASCII)
    header[6] = 0x00                        # drep[2]
    header[7] = 0x00                        # serial_high

    # Offset 8-23: Object UUID (AR UUID) - swap to LE
    obj_uuid = uuid_swap_fields(ar_uuid)
    header[8:24] = obj_uuid

    # Offset 24-39: Interface UUID (PNIO Device) - swap to LE
    # This is where the bug was - must swap!
    iface_uuid = uuid_swap_fields(PNIO_DEVICE_INTERFACE_UUID)
    header[24:40] = iface_uuid

    # Offset 40-55: Activity UUID - swap to LE
    act_uuid = uuid_swap_fields(activity_uuid)
    header[40:56] = act_uuid

    # Offset 56-79: Multi-byte fields (all little-endian per DREP=0x10)
    struct.pack_into('<I', header, 56, 0)                   # server_boot
    struct.pack_into('<I', header, 60, 1)                   # interface_version
    struct.pack_into('<I', header, 64, 0)                   # sequence_number
    struct.pack_into('<H', header, 68, 0)                   # opnum (0=Connect)
    struct.pack_into('<H', header, 70, 0xFFFF)              # interface_hint
    struct.pack_into('<H', header, 72, 0xFFFF)              # activity_hint
    struct.pack_into('<H', header, 74, fragment_length)     # fragment_length
    struct.pack_into('<H', header, 76, 0)                   # fragment_number
    header[78] = 0                                          # auth_protocol
    header[79] = 0                                          # serial_low

    return bytes(header)


def build_ndr_request_header(pnio_payload_length: int, max_count: int = 16696) -> bytes:
    """
    Build 20-byte NDR (Network Data Representation) request header
    Required between RPC header and PNIO blocks
    """
    ndr = bytearray(20)

    struct.pack_into('<I', ndr, 0, max_count)              # ArgsMaximum
    struct.pack_into('<I', ndr, 4, pnio_payload_length)    # ArgsLength
    struct.pack_into('<I', ndr, 8, max_count)              # MaxCount
    struct.pack_into('<I', ndr, 12, 0)                     # Offset
    struct.pack_into('<I', ndr, 16, pnio_payload_length)   # ActualCount

    return bytes(ndr)


def build_ar_block_req(ar_uuid: bytes, controller_mac: bytes, controller_uuid: bytes,
                      controller_station_name: str) -> bytes:
    """
    Build ARBlockReq (Block Type 0x0101)
    All multi-byte fields in PNIO blocks are BIG-ENDIAN
    """
    block = bytearray()

    # Block Type (2 bytes, big-endian)
    block += struct.pack('>H', 0x0101)

    # Block Length (will be updated at end)
    block_length_pos = len(block)
    block += struct.pack('>H', 0)  # Placeholder

    # Block Version (2 bytes)
    block += struct.pack('BB', 1, 0)  # Version 1.0

    # AR Type (2 bytes, big-endian)
    block += struct.pack('>H', 0x0001)  # IOCARSingle

    # AR UUID (16 bytes, big-endian - NO SWAP in PNIO blocks!)
    block += ar_uuid

    # Session Key (2 bytes, big-endian)
    block += struct.pack('>H', 0)

    # Controller MAC (6 bytes)
    block += controller_mac

    # Controller UUID (16 bytes, big-endian)
    block += controller_uuid

    # AR Properties (4 bytes, big-endian)
    # Bit 8 (device_access) MUST be 0 for IO Controller
    ar_properties = 0x00000060  # State=Active, ParameterizationServer=Controller
    block += struct.pack('>I', ar_properties)

    # Activity Timeout (2 bytes, units of 100ms)
    block += struct.pack('>H', 100)  # 10 seconds

    # UDP RT Port (2 bytes)
    block += struct.pack('>H', 0x8892)

    # Station Name Length (2 bytes) + Station Name (variable)
    station_bytes = controller_station_name.encode('ascii')
    block += struct.pack('>H', len(station_bytes))
    block += station_bytes

    # Update block length (total - 4 for type/length fields)
    block_length = len(block) - 4
    struct.pack_into('>H', block, block_length_pos, block_length)

    return bytes(block)


def build_iocr_block_req(iocr_type: int, iocr_ref: int, frame_id: int,
                        slot: int, subslot: int, frame_offset: int) -> bytes:
    """
    Build IOCRBlockReq (Block Type 0x0102)
    """
    block = bytearray()

    # Block Type
    block += struct.pack('>H', 0x0102)

    # Block Length (placeholder)
    block_length_pos = len(block)
    block += struct.pack('>H', 0)

    # Block Version
    block += struct.pack('BB', 1, 0)

    # IOCR Type (1=Input, 2=Output)
    block += struct.pack('>H', iocr_type)

    # IOCR Reference
    block += struct.pack('>H', iocr_ref)

    # LT (2 bytes)
    block += struct.pack('>H', 0x8892)

    # IOCR Properties (4 bytes)
    iocr_props = 0x00000000  # RT_CLASS_1
    block += struct.pack('>I', iocr_props)

    # DataLength
    block += struct.pack('>H', 40)

    # FrameID
    block += struct.pack('>H', frame_id)

    # SendClockFactor
    block += struct.pack('>H', 32)

    # ReductionRatio
    block += struct.pack('>H', 32)

    # Phase
    block += struct.pack('>H', 1)

    # Sequence
    block += struct.pack('>H', 0)

    # FrameSendOffset
    block += struct.pack('>I', 0xFFFFFFFF)

    # WatchdogFactor
    block += struct.pack('>H', 3)

    # DataHoldFactor
    block += struct.pack('>H', 3)

    # IOCRTagHeader
    block += struct.pack('>H', 0xC000)

    # IOCRMulticastMACAdd (6 bytes)
    block += bytes([0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00])

    # NumberOfAPIs
    block += struct.pack('>H', 1)

    # API (4 bytes)
    block += struct.pack('>I', 0)

    # NumberOfIODataObjects
    block += struct.pack('>H', 1)

    # IODataObject
    block += struct.pack('>H', slot)       # SlotNumber
    block += struct.pack('>H', subslot)    # SubslotNumber
    block += struct.pack('>H', frame_offset)  # FrameOffset

    # NumberOfIOCS
    if iocr_type == 1:  # Input has IOCS
        block += struct.pack('>H', 1)
        block += struct.pack('>H', slot)
        block += struct.pack('>H', subslot)
        block += struct.pack('>H', 4)
    else:  # Output has no IOCS
        block += struct.pack('>H', 0)

    # Update block length
    block_length = len(block) - 4
    struct.pack_into('>H', block, block_length_pos, block_length)

    return bytes(block)


def build_alarm_cr_block_req() -> bytes:
    """
    Build AlarmCRBlockReq (Block Type 0x0103)
    """
    block = bytearray()

    # Block Type
    block += struct.pack('>H', 0x0103)

    # Block Length
    block += struct.pack('>H', 22)  # Fixed size for basic alarm CR

    # Block Version
    block += struct.pack('BB', 1, 0)

    # AlarmCRType
    block += struct.pack('>H', 0x0001)

    # LT
    block += struct.pack('>H', 0x8892)

    # AlarmCRProperties
    block += struct.pack('>I', 0x00000000)

    # RTATimeoutFactor
    block += struct.pack('>H', 1)

    # RTARetries
    block += struct.pack('>H', 3)

    # LocalAlarmReference
    block += struct.pack('>H', 3)

    # MaxAlarmDataLength
    block += struct.pack('>H', 200)

    # AlarmCRTagHeaderHigh
    block += struct.pack('>H', 0xC000)

    # AlarmCRTagHeaderLow
    block += struct.pack('>H', 0xA000)

    return bytes(block)


def build_expected_submodule_block_req(rtu_config: dict) -> bytes:
    """
    Build ExpectedSubmoduleBlockReq (Block Type 0x0104)
    """
    block = bytearray()

    # Block Type
    block += struct.pack('>H', 0x0104)

    # Block Length (placeholder)
    block_length_pos = len(block)
    block += struct.pack('>H', 0)

    # Block Version
    block += struct.pack('BB', 1, 0)

    # NumberOfAPIs
    block += struct.pack('>H', 1)

    # API
    block += struct.pack('>I', 0)

    # Count slots: DAP + application slots
    num_slots = 1
    if rtu_config and rtu_config.get('slot_count', 0) > 0:
        num_slots += rtu_config['slot_count']

    # NumberOfModules (slots)
    block += struct.pack('>H', num_slots)

    # Slot 0: DAP (always required)
    block += struct.pack('>H', 0)          # SlotNumber
    block += struct.pack('>I', 0x00000001)  # ModuleIdentNumber
    block += struct.pack('>H', 1)          # NumberOfSubmodules

    # DAP Submodule 0.1
    block += struct.pack('>H', 1)          # SubslotNumber
    block += struct.pack('>I', 0x00000001)  # SubmoduleIdentNumber
    block += struct.pack('>HHH', 0, 0, 0)  # InputLength, OutputLength, Properties

    # Add application slots from RTU config
    if rtu_config and rtu_config.get('slot_count', 0) > 0:
        for slot_info in rtu_config['slots']:
            slot_num = slot_info['slot']
            subslot_num = slot_info['subslot']
            module_ident = slot_info['module_ident']
            submodule_ident = slot_info['submodule_ident']
            data_size = slot_info.get('data_size', 5)
            direction = slot_info.get('direction', 'input')

            block += struct.pack('>H', slot_num)
            block += struct.pack('>I', module_ident)
            block += struct.pack('>H', 1)  # NumberOfSubmodules

            block += struct.pack('>H', subslot_num)
            block += struct.pack('>I', submodule_ident)

            # Input/Output lengths
            if direction == 'input':
                block += struct.pack('>H', data_size)  # InputLength
                block += struct.pack('>H', 0)          # OutputLength
            else:
                block += struct.pack('>H', 0)          # InputLength
                block += struct.pack('>H', data_size)  # OutputLength

            block += struct.pack('>H', 0)  # Properties

    # Update block length
    block_length = len(block) - 4
    struct.pack_into('>H', block, block_length_pos, block_length)

    return bytes(block)


def build_connect_request(controller_mac: bytes, controller_name: str,
                         device_ip: str, rtu_config: dict) -> bytes:
    """
    Build complete PROFINET Connect Request using raw struct.pack()
    """
    # Generate UUIDs
    ar_uuid = uuid_module.uuid4().bytes
    activity_uuid = uuid_module.uuid4().bytes

    # Controller UUID (simplified - use random)
    controller_uuid = uuid_module.uuid4().bytes

    print(f"[INFO] AR UUID: {ar_uuid.hex()}")
    print(f"[INFO] Activity UUID: {activity_uuid.hex()}")
    print(f"[INFO] Controller UUID: {controller_uuid.hex()}")

    # Build PNIO blocks (NO PADDING between blocks!)
    pnio_blocks = bytearray()

    # AR Block
    print(f"[INFO] Building AR Block...")
    ar_block = build_ar_block_req(ar_uuid, controller_mac, controller_uuid, controller_name)
    pnio_blocks += ar_block
    print(f"[INFO]   AR Block: {len(ar_block)} bytes")

    # Alarm CR Block (order: AR → Alarm → IOCR per GitHub implementation)
    print(f"[INFO] Building Alarm CR Block...")
    alarm_block = build_alarm_cr_block_req()
    pnio_blocks += alarm_block  # NO PADDING!
    print(f"[INFO]   Alarm CR Block: {len(alarm_block)} bytes")

    # Input IOCR Block
    print(f"[INFO] Building Input IOCR Block...")
    input_iocr = build_iocr_block_req(
        iocr_type=1, iocr_ref=1, frame_id=0x8001,
        slot=1, subslot=1, frame_offset=15
    )
    pnio_blocks += input_iocr  # NO PADDING!
    print(f"[INFO]   Input IOCR Block: {len(input_iocr)} bytes")

    # Output IOCR Block
    print(f"[INFO] Building Output IOCR Block...")
    output_iocr = build_iocr_block_req(
        iocr_type=2, iocr_ref=2, frame_id=0x8000,
        slot=1, subslot=1, frame_offset=0
    )
    pnio_blocks += output_iocr  # NO PADDING!
    print(f"[INFO]   Output IOCR Block: {len(output_iocr)} bytes")

    # Expected Submodule Block
    print(f"[INFO] Building Expected Submodule Block...")
    exp_submod = build_expected_submodule_block_req(rtu_config)
    pnio_blocks += exp_submod  # NO PADDING!
    print(f"[INFO]   Expected Submodule Block: {len(exp_submod)} bytes")

    print(f"[INFO] Total PNIO blocks: {len(pnio_blocks)} bytes")

    # Build NDR header
    ndr_header = build_ndr_request_header(len(pnio_blocks))
    print(f"[INFO] NDR header: {len(ndr_header)} bytes")

    # Build RPC header
    fragment_length = len(ndr_header) + len(pnio_blocks)
    rpc_header = build_rpc_header(ar_uuid, activity_uuid, fragment_length)
    print(f"[INFO] RPC header: {len(rpc_header)} bytes")

    # Validate Interface UUID
    if rpc_header[24:28] != bytes([0x01, 0x00, 0xA0, 0xDE]):
        raise ValueError(f"Interface UUID corrupted: {rpc_header[24:40].hex(' ')}")
    print(f"[INFO] ✓ Interface UUID validated")

    # Assemble complete RPC payload
    rpc_payload = rpc_header + ndr_header + pnio_blocks
    print(f"[INFO] Total RPC payload: {len(rpc_payload)} bytes")

    return bytes(rpc_payload)


def main():
    parser = argparse.ArgumentParser(
        description='PROFINET Controller - Raw Implementation (struct.pack)'
    )
    parser.add_argument('--interface', '-i', required=True)
    parser.add_argument('--device-ip', required=True)
    parser.add_argument('--device-name', required=True)
    parser.add_argument('--device-mac', default='00:1e:06:39:ec:3b')
    parser.add_argument('--timeout', '-t', type=float, default=5.0)

    args = parser.parse_args()

    import os
    if os.geteuid() != 0:
        print("[ERROR] Root required")
        sys.exit(1)

    print(f"[INFO] === PROFINET Controller - Raw Implementation ===\n")

    controller_ip = get_if_addr(args.interface)
    controller_mac_str = get_if_hwaddr(args.interface)
    controller_mac = bytes.fromhex(controller_mac_str.replace(':', ''))
    controller_name = socket.gethostname()

    print(f"[INFO] Controller: {controller_ip} ({controller_mac_str})")
    print(f"[INFO] Controller Name: {controller_name}")
    print(f"[INFO] Target: {args.device_ip} ({args.device_mac})\n")

    # Get RTU config
    print(f"[INFO] Querying RTU configuration...")
    try:
        response = requests.get(f"http://{args.device_ip}:9081/slots", timeout=2)
        rtu_config = response.json() if response.status_code == 200 else {}
    except Exception:
        rtu_config = {}

    if rtu_config:
        print(f"[INFO] RTU has {rtu_config.get('slot_count', 0)} application slot(s)\n")
    else:
        print(f"[WARNING] Could not get RTU config\n")

    # Build Connect Request
    print(f"[INFO] === Building Connect Request ===\n")
    rpc_payload = build_connect_request(controller_mac, controller_name,
                                       args.device_ip, rtu_config)

    # Build complete packet
    device_mac = bytes.fromhex(args.device_mac.replace(':', ''))
    packet = (
        Ether(src=controller_mac, dst=device_mac) /
        IP(src=controller_ip, dst=args.device_ip) /
        UDP(sport=34964, dport=34964) /
        Raw(load=rpc_payload)
    )

    print(f"\n[INFO] === Packet Structure ===")
    print(f"Total size: {len(packet)} bytes")
    print(f"\n[INFO] Packet hex dump:")
    hexdump(packet)

    print(f"\n[INFO] === Sending RPC Connect ===")
    print(f"[INFO] Sending via Layer 2 (srp)...")

    # Send via Layer 2
    answered, unanswered = srp(packet, iface=args.interface, timeout=args.timeout, verbose=1)

    if answered:
        response = answered[0][1]
        print(f"\n[INFO] ✓✓✓ RECEIVED RESPONSE! ✓✓✓")
        response.show()

        if UDP in response and response[UDP].sport == 34964:
            print(f"\n[INFO] ✓✓✓ VALID RPC RESPONSE FROM RTU! ✓✓✓")
            sys.exit(0)
    else:
        print(f"\n[ERROR] No response (timeout)")
        sys.exit(1)


if __name__ == '__main__':
    main()
