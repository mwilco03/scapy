#!/usr/bin/env python3
"""
Quick test to see what Scapy PROFINET layers produce
"""
import sys
sys.path.insert(0, '/home/user/scapy')

from scapy.layers.dcerpc import DceRpc4
from scapy.contrib.pnio_rpc import *

# Build simple AR block like in test
ar_block = ARBlockReq(
    ARType='IOCARSingle',
    ARUUID='fedcba98-7654-3210-fedc-ba9876543210',
    SessionKey=0,
    CMInitiatorMacAdd='01:02:03:04:05:06',
    CMInitiatorStationName='plc-1',
    CMInitiatorObjectUUID='dea00000-6c97-11d1-8271-010203040506',
    ARProperties_ParametrizationServer='CM_Initator'
)

print("[TEST] AR Block created")
print(f"AR Block hex: {bytes(ar_block).hex()}")
print(f"AR Block length: {len(bytes(ar_block))} bytes")

# Build IOCR Input
iocr_input = IOCRBlockReq(
    IOCRType='InputCR',
    IOCRReference=1,
    SendClockFactor=2,
    ReductionRatio=32,
    DataLength=40,
    FrameID=0x8001,
    APIs=[
        IOCRAPI(
            API=0,
            IODataObjects=[
                IOCRAPIObject(SlotNumber=3, SubslotNumber=1, FrameOffset=15),
            ],
            IOCSs=[
                IOCRAPIObject(SlotNumber=3, SubslotNumber=1, FrameOffset=4),
            ]
        )
    ]
)

print(f"\n[TEST] Input IOCR Block created")
print(f"IOCR hex: {bytes(iocr_input).hex()}")
print(f"IOCR length: {len(bytes(iocr_input))} bytes")

# Build PNIO Service Request
pnio_req = PNIOServiceReqPDU(
    blocks=[ar_block, iocr_input]
)

print(f"\n[TEST] PNIO Service Request created")
print(f"PNIO hex: {bytes(pnio_req).hex()}")
print(f"PNIO length: {len(bytes(pnio_req))} bytes")

# Build DCE/RPC
dce_rpc = DceRpc4(
    endian='little',
    opnum=0,
    seqnum=0,
    object='dea00000-6c97-11d1-8271-010203040506',
    act_id='01234567-89ab-cdef-0123-456789abcdef'
)

print(f"\n[TEST] DCE/RPC created")
print(f"DCE/RPC hex: {bytes(dce_rpc).hex()}")
print(f"DCE/RPC length: {len(bytes(dce_rpc))} bytes")

# Build complete packet
complete = dce_rpc / pnio_req

print(f"\n[TEST] Complete packet")
print(f"Complete hex: {bytes(complete).hex()}")
print(f"Complete length: {len(bytes(complete))} bytes")

print(f"\n[TEST] Hex dump:")
hexdump(complete)

# Compare with expected from test (first part)
expected_start = '04000000100000000000a0de976cd11182710102030405060100a0de976cd111827100a02442df7d67452301ab89efcd0123456789abcdef'
actual_start = bytes(complete).hex()[:len(expected_start)]

print(f"\n[TEST] Comparison:")
print(f"Expected: {expected_start}")
print(f"Actual:   {actual_start}")
print(f"Match: {expected_start == actual_start}")
