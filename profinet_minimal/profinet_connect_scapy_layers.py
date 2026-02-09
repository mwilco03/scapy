#!/usr/bin/env python3
"""
PROFINET Controller - Using Native Scapy Layers (CORRECT)

This version uses Scapy's built-in PROFINET RPC layers instead of
building raw bytes manually.

Based on /home/user/scapy/test/contrib/pnio_rpc.uts (lines 592-697)
"""
import sys
import argparse
import uuid
import struct
import requests
from typing import Optional

try:
    # Import PROFINET RPC layers
    from scapy.all import *
    from scapy.layers.dcerpc import DceRpc4
    from scapy.contrib.pnio_rpc import (
        PNIOServiceReqPDU, ARBlockReq, IOCRBlockReq, IOCRAPI, IOCRAPIObject,
        AlarmCRBlockReq, ExpectedSubmoduleBlockReq, ExpectedSubmoduleAPI,
        ExpectedSubmodule, ExpectedSubmoduleDataDescription
    )
except ImportError as e:
    print(f"[ERROR] Import failed: {e}")
    sys.exit(1)


def get_rtu_config(device_ip: str) -> dict:
    """Query RTU's actual module configuration"""
    try:
        response = requests.get(f"http://{device_ip}:9081/slots", timeout=2)
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return {}


def build_rpc_connect_proper(controller_mac: str, device_mac: str,
                             device_name: str, rtu_config: dict) -> tuple:
    """
    Build RPC Connect using PROPER Scapy layers

    Based on working test example from pnio_rpc.uts
    """

    # Generate UUIDs
    ar_uuid = uuid.uuid4()
    activity_uuid = uuid.uuid4()
    object_uuid = uuid.uuid4()

    # Ensure object UUID starts with proper PROFINET prefix
    object_uuid_str = f"dea00000-6c97-11d1-8271-{object_uuid.hex[24:]}"

    print(f"[INFO] AR UUID: {ar_uuid}")
    print(f"[INFO] Activity UUID: {activity_uuid}")
    print(f"[INFO] Object UUID: {object_uuid_str}")

    # Build AR Block
    ar_block = ARBlockReq(
        ARType='IOCARSingle',                    # Single IO Controller AR
        ARUUID=str(ar_uuid),
        SessionKey=0,
        CMInitiatorMacAdd=controller_mac,
        CMInitiatorStationName=device_name,
        CMInitiatorObjectUUID=object_uuid_str,
        ARProperties_ParametrizationServer='CM_Initator',  # Note: typo is in spec
        ARProperties_State='Active'
    )

    print(f"[INFO] AR Block created")

    # Build Input IOCR Block
    # Get config from RTU or use defaults
    if rtu_config and rtu_config.get('slot_count', 0) > 0:
        slot_info = rtu_config['slots'][0]
        slot_num = slot_info['slot']
        subslot_num = slot_info['subslot']
        data_size = slot_info.get('data_size', 5)
    else:
        slot_num = 1
        subslot_num = 1
        data_size = 5

    iocr_input = IOCRBlockReq(
        IOCRType='InputCR',
        IOCRReference=1,
        SendClockFactor=2,           # 2ms
        ReductionRatio=32,            # 32 cycles
        DataLength=40,                # Total data length
        FrameID=0x8001,              # Input frame ID
        APIs=[
            IOCRAPI(
                API=0,
                IODataObjects=[
                    IOCRAPIObject(SlotNumber=slot_num, SubslotNumber=subslot_num, FrameOffset=15)
                ],
                IOCSs=[
                    IOCRAPIObject(SlotNumber=slot_num, SubslotNumber=subslot_num, FrameOffset=4)
                ]
            )
        ]
    )

    print(f"[INFO] Input IOCR Block created (Frame ID 0x8001)")

    # Build Output IOCR Block
    iocr_output = IOCRBlockReq(
        IOCRType='OutputCR',
        IOCRReference=2,
        SendClockFactor=2,
        ReductionRatio=32,
        DataLength=40,
        FrameID=0x8000,              # Output frame ID
        APIs=[
            IOCRAPI(
                API=0,
                IODataObjects=[
                    IOCRAPIObject(SlotNumber=slot_num, SubslotNumber=subslot_num, FrameOffset=0)
                ],
                IOCSs=[]
            )
        ]
    )

    print(f"[INFO] Output IOCR Block created (Frame ID 0x8000)")

    # Build Alarm CR Block
    alarm_cr = AlarmCRBlockReq(
        AlarmCRType=0x0001,
        AlarmCRProperties_Transport=0,   # RTA_CLASS_1
        RTATimeoutFactor=1,
        RTARetries=3,
        LocalAlarmReference=3
    )

    print(f"[INFO] Alarm CR Block created")

    # Build Expected Submodule Block
    # ALWAYS include Slot 0 (DAP)
    expected_submodules = []

    # Slot 0: DAP (Device Access Point) - always required
    expected_submodules.append(
        ExpectedSubmoduleBlockReq(
            APIs=[
                ExpectedSubmoduleAPI(
                    API=0,
                    SlotNumber=0,
                    ModuleIdentNumber=0x00000001,  # DAP module
                    Submodules=[
                        ExpectedSubmodule(
                            SubslotNumber=1,
                            SubmoduleIdentNumber=0x00000001,  # DAP submodule
                            SubmoduleProperties_Type='NO_IO',
                            DataDescription=[]
                        )
                    ]
                )
            ]
        )
    )

    print(f"[INFO]   Expected Submodule: Slot 0.1 (DAP)")

    # Add application slots from RTU config
    if rtu_config and rtu_config.get('slot_count', 0) > 0:
        for slot_info in rtu_config['slots']:
            slot_num = slot_info['slot']
            subslot_num = slot_info['subslot']
            module_ident = slot_info['module_ident']
            submodule_ident = slot_info['submodule_ident']
            data_size = slot_info.get('data_size', 5)
            direction = slot_info.get('direction', 'input')

            print(f"[INFO]   Expected Submodule: Slot {slot_num}.{subslot_num} (Module 0x{module_ident:08X})")

            # Determine submodule type
            if direction == 'input':
                submod_type = 'INPUT'
                data_desc = [
                    ExpectedSubmoduleDataDescription(
                        DataDescription='Input',
                        SubmoduleDataLength=data_size,
                        LengthIOPS=1,
                        LengthIOCS=1
                    )
                ]
            else:
                submod_type = 'OUTPUT'
                data_desc = [
                    ExpectedSubmoduleDataDescription(
                        DataDescription='Output',
                        SubmoduleDataLength=data_size,
                        LengthIOPS=1,
                        LengthIOCS=1
                    )
                ]

            expected_submodules.append(
                ExpectedSubmoduleBlockReq(
                    APIs=[
                        ExpectedSubmoduleAPI(
                            API=0,
                            SlotNumber=slot_num,
                            ModuleIdentNumber=module_ident,
                            Submodules=[
                                ExpectedSubmodule(
                                    SubslotNumber=subslot_num,
                                    SubmoduleIdentNumber=submodule_ident,
                                    SubmoduleProperties_Type=submod_type,
                                    DataDescription=data_desc
                                )
                            ]
                        )
                    ]
                )
            )

    print(f"[INFO] Expected Submodule Blocks created")

    # Build PNIO Service Request
    pnio_req = PNIOServiceReqPDU(
        blocks=[ar_block, iocr_input, iocr_output, alarm_cr] + expected_submodules
    )

    # Build DCE/RPC header
    dce_rpc = DceRpc4(
        endian='little',                     # Little-endian
        opnum=0,                             # 0 = Connect
        seqnum=0,
        object=object_uuid_str,              # Object UUID
        act_id=str(activity_uuid)            # Activity UUID
    )

    return dce_rpc, pnio_req


def main():
    parser = argparse.ArgumentParser(
        description='PROFINET Controller - Using Scapy Layers (CORRECT)'
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

    print(f"[INFO] === PROFINET Controller - Scapy Layers ===\n")

    controller_ip = get_if_addr(args.interface)
    controller_mac = get_if_hwaddr(args.interface)

    print(f"[INFO] Controller: {controller_ip} ({controller_mac})")
    print(f"[INFO] Target: {args.device_ip} ({args.device_mac})\n")

    # Get RTU config
    print(f"[INFO] Querying RTU configuration...")
    rtu_config = get_rtu_config(args.device_ip)
    if rtu_config:
        print(f"[INFO] RTU has {rtu_config.get('slot_count', 0)} application slot(s)")
    else:
        print(f"[WARNING] Could not get RTU config - using defaults")

    print(f"\n[INFO] === Building RPC Connect ===\n")

    # Build RPC Connect using proper Scapy layers
    dce_rpc, pnio_req = build_rpc_connect_proper(
        controller_mac, args.device_mac,
        args.device_name, rtu_config
    )

    # Build complete packet
    packet = (
        Ether(src=controller_mac, dst=args.device_mac) /
        IP(src=controller_ip, dst=args.device_ip) /
        UDP(sport=34964, dport=34964) /
        dce_rpc / pnio_req
    )

    print(f"\n[INFO] === Packet Structure ===")
    print(f"Total size: {len(packet)} bytes")
    print(f"Layers: {' / '.join([layer.name for layer in packet.layers()])}")

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
            print(f"\n[WARNING] Response not from UDP 34964")
            sys.exit(1)
    else:
        print(f"\n[ERROR] No response (timeout)")
        print(f"\n[INFO] Check RTU logs:")
        print(f"[INFO]   journalctl -u water-rtu-manager -f | grep -E 'CALLBACK|exp_module'")
        sys.exit(1)


if __name__ == '__main__':
    main()
