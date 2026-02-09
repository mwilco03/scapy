#!/usr/bin/env python3
"""
Capture and analyze actual RPC Connect traffic
"""
import sys
import struct
from scapy.all import *

# Import the diagnostic script's build function
sys.path.insert(0, '/home/user/scapy/profinet_minimal')
from profinet_diagnostic_v3 import check_rtu_config, build_connect_diagnostic

interface = "enp0s3"
device_ip = "192.168.6.21"
device_name = "rtu-ec3b"
device_mac = "00:1e:06:39:ec:3b"

controller_ip = get_if_addr(interface)
controller_mac = get_if_hwaddr(interface)

print(f"[DEBUG] === Capturing RPC Connect Traffic ===\n")

# Get RTU config
rtu_config = check_rtu_config(device_ip)

# Build packet
packet = build_connect_diagnostic(
    controller_ip, controller_mac,
    device_ip, device_mac, device_name,
    rtu_config
)

print(f"\n[DEBUG] === Packet Analysis ===")
print(f"Packet layers: {[layer.name for layer in packet.layers()]}")
print(f"Total size: {len(packet)} bytes")

# Show each layer
if Ether in packet:
    print(f"\n[DEBUG] Ethernet Layer:")
    print(f"  Src: {packet[Ether].src}")
    print(f"  Dst: {packet[Ether].dst}")
    print(f"  Type: 0x{packet[Ether].type:04x}")

if IP in packet:
    print(f"\n[DEBUG] IP Layer:")
    print(f"  Src: {packet[IP].src}")
    print(f"  Dst: {packet[IP].dst}")
    print(f"  Proto: {packet[IP].proto}")
    print(f"  Len: {packet[IP].len}")

if UDP in packet:
    print(f"\n[DEBUG] UDP Layer:")
    print(f"  Sport: {packet[UDP].sport}")
    print(f"  Dport: {packet[UDP].dport}")
    print(f"  Len: {packet[UDP].len}")

if Raw in packet:
    raw_data = bytes(packet[Raw])
    print(f"\n[DEBUG] Raw Payload:")
    print(f"  Length: {len(raw_data)} bytes")
    print(f"  First 80 bytes:")
    for i in range(0, min(80, len(raw_data)), 16):
        hex_str = ' '.join(f'{b:02x}' for b in raw_data[i:i+16])
        print(f"    {i:04x}: {hex_str}")

print(f"\n[DEBUG] === Sending and Capturing ===")

# Start capture in background
captured = []

def packet_handler(pkt):
    captured.append(pkt)

# Start sniffing
sniffer = AsyncSniffer(iface=interface, prn=packet_handler,
                       filter="host 192.168.6.21 and port 34964")
sniffer.start()

# Send packet
print(f"[DEBUG] Sending packet...")
sendp(packet, iface=interface, verbose=0)
print(f"[DEBUG] Packet sent!")

# Wait for response
time.sleep(3)
sniffer.stop()

print(f"\n[DEBUG] === Captured Traffic ===")
print(f"Captured {len(captured)} packets")

for i, pkt in enumerate(captured):
    print(f"\n[DEBUG] Packet {i+1}:")
    print(f"  Direction: {pkt[IP].src} -> {pkt[IP].dst}")
    if UDP in pkt:
        print(f"  UDP: {pkt[UDP].sport} -> {pkt[UDP].dport}")
    print(f"  Size: {len(pkt)} bytes")

    # Show hex dump
    hexdump(pkt)
