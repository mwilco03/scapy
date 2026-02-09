#!/usr/bin/env python3
"""Quick test to verify DceRpc4 if_id parameter"""
import sys
sys.path.insert(0, '/home/user/scapy')

from scapy.all import *
from scapy.layers.dcerpc import DceRpc4

# Test DceRpc4 with if_id
test_pkt = DceRpc4(
    endian='little',
    opnum=0,
    seqnum=0,
    object='dea00000-6c97-11d1-8271-aabbccddeeff',
    act_id='01234567-89ab-cdef-0123-456789abcdef',
    if_id='dea00001-6c97-11d1-8271-00a02442df7d'
)

print("[TEST] DceRpc4 packet created")
print(f"[TEST] if_id field value: {test_pkt.if_id}")
print(f"\n[TEST] Hex dump:")
hexdump(test_pkt)

# Check if if_id appears in the raw bytes
raw = bytes(test_pkt)
if_id_bytes = bytes.fromhex('dea00001-6c97-11d1-8271-00a02442df7d'.replace('-', ''))
# UUIDs are stored in a specific format, need to check both endianness
print(f"\n[TEST] Searching for Interface UUID in packet...")
if b'\xde\xa0\x00\x01\x6c\x97\x11\xd1\x82\x71\x00\xa0\x24\x42\xdf\x7d' in raw:
    print("[TEST] ✓ Interface UUID found in packet (big-endian)")
elif b'\x01\x00\xa0\xde\x6c\x97\xd1\x11\x82\x71\x00\xa0\x24\x42\xdf\x7d' in raw:
    print("[TEST] ✓ Interface UUID found in packet (mixed-endian)")
else:
    print("[TEST] ✗ Interface UUID NOT found in packet!")
    print(f"[TEST] Raw bytes: {raw.hex()}")
