#!/usr/bin/env python3
"""
PROFINET Debug - See what Scapy actually receives
Version: 1.1.1-debug
"""

import sys
import struct
from scapy.all import *

interface = sys.argv[1] if len(sys.argv) > 1 else "enp0s3"

print(f"[DEBUG] Listening on {interface}")

src_mac = get_if_hwaddr(interface)

# Build DCP request
frame_id = struct.pack(">H", 0xFEFE)
service_id = struct.pack("B", 0x05)
service_type = struct.pack("B", 0x00)
xid = struct.pack(">I", 0x12345678)
response_delay = struct.pack(">H", 0x0001)
data_length = struct.pack(">H", 0x0004)
option = struct.pack("B", 0xFF)
suboption = struct.pack("B", 0xFF)
block_length = struct.pack(">H", 0x0000)

payload = (frame_id + service_id + service_type + xid +
           response_delay + data_length + option + suboption + block_length)

pkt = Ether(type=0x8892, src=src_mac, dst='01:0e:cf:00:00:00') / Raw(load=payload)

print(f"[DEBUG] Sending request:")
hexdump(pkt)

# Send and receive
ans, unans = srp(pkt, iface=interface, timeout=3.0, verbose=1, multi=True)

print(f"\n[DEBUG] Received {len(ans)} responses\n")

for i, (sent, received) in enumerate(ans):
    print(f"=== Response {i+1} ===")
    print(f"Source MAC: {received.src}")
    print(f"Layers: {received.layers()}")

    # Show full packet
    received.show()

    print(f"\nHex dump:")
    hexdump(received)

    # Try to access Raw layer
    if received.haslayer(Raw):
        print(f"\nRaw layer exists!")
        raw_data = bytes(received[Raw])
        print(f"Raw data length: {len(raw_data)} bytes")
        print(f"First 20 bytes: {raw_data[:20].hex()}")

        # Try to parse frame ID
        if len(raw_data) >= 2:
            frame_id_val = struct.unpack(">H", raw_data[0:2])[0]
            print(f"Frame ID at offset 0: 0x{frame_id_val:04x}")
    else:
        print(f"\nNo Raw layer!")
        # Try to access payload
        if hasattr(received, 'payload'):
            print(f"Payload: {received.payload}")

    print("\n" + "="*60 + "\n")
