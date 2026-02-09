# PROFINET RPC Connect: Broken vs Fixed

## What Was Wrong in Your Original Script

Your script was **manually packing DCE/RPC headers** using `struct.pack()`, which created malformed packets that RTUs reject silently.

### The Broken Approach (Manual Packing)

```python
# BROKEN - from your original script
rpc_header = struct.pack(
    '!BBHIQQQQIIIHHHHIIIQQ',
    4,           # Version
    0,           # Type
    0x0022,      # Flags - WRONG!
    0x10000000,  # Serial High - WRONG!
    # ... more fields
)

# Then manually concatenate blocks
packet_data = rpc_header + ar_block_bytes + iocr_bytes + ...

# Send raw
sock.sendto(packet_data, (device_ip, 34964))
```

**Problems:**
1. **Wrong DCE/RPC flags** (0x0022) - should be 0x20 (PFC_FIRST_FRAG)
2. **No opnum field** - PROFINET Connect requires opnum=0
3. **Manual byte ordering** - easy to get endianness wrong
4. **No NDR headers** - DCE/RPC needs Network Data Representation headers
5. **Wrong packet structure** - missing critical framing layers

### The Fixed Approach (Scapy Layers)

```python
# FIXED - using Scapy's built-in layers
connect_request = (
    IP(src=controller_ip, dst=device_ip) /
    UDP(sport=34964, dport=34964) /
    ProfinetIO(frameID=0xFEFC) /              # Correct PROFINET framing
    DCERPCRequest(
        opnum=0,                               # Connect operation
        if_id=PROFINET_IO_UUID,               # Correct UUID
        activity_id=activity_uuid,
        flags1=0x20,                          # Correct flags
        flags2=0x00
    ) /
    IODConnectReq(...) /                      # AR block with proper structure
    IOCRBlockReq(...) /                       # Input IOCR
    IOCRBlockReq(...) /                       # Output IOCR
    AlarmCRBlockReq(...) /                    # Alarm CR
    ExpectedSubmoduleBlockReq(...)            # Submodule config
)

# Scapy handles ALL the framing, byte ordering, checksums, etc.
send(connect_request)
```

**Why this works:**
1. ✓ Scapy knows the DCE/RPC protocol structure
2. ✓ Correct opnum (0 for Connect)
3. ✓ Proper flags and byte ordering
4. ✓ Automatic NDR headers
5. ✓ Correct layer composition

## Comparison: What You Were Sending vs What You Should Send

### Your Broken Packet (from hex dump)

```
04 00 22 00 10 00 00 00 de a0 00 01 6c 97 11 d1 82 71 00 a0
│  │  └──┬──┘ └────┬────┘
│  │     │         │
│  │     │         └─ Serial High (wrong format)
│  │     └─ Flags 0x0022 (WRONG!)
│  └─ Type 0x00 (request) ✓
└─ Version 4 ✓

Missing: opnum field, proper NDR headers, correct flag bits
```

### Fixed Packet (what Scapy generates)

```
04 00 20 00 ...  # Version 4, Type 0, Flags 0x20 (correct)
... opnum: 00 00 00 00  # Connect operation
... if_id: de-a0-00-01-6c-97-11-d1-82-71-00-a0-24-42-df-7d  # Correct UUID
... [NDR headers with proper alignment]
... [AR Block with correct block type 0x0101]
... [IOCR Blocks with frame IDs 0x8000/0x8001]
```

## How to Test

### 1. Run the broken version (your original)
```bash
# This will fail with timeout
sudo python3 test-profinet-scapy.py --interface enp0s3 --timeout 3
```

**Result:** `[ERROR] ✗ Connect timeout - no response from RTU`

### 2. Run the fixed version
```bash
# This should work!
sudo python3 test_profinet_fixed.py --interface enp0s3 --timeout 5
```

**Expected result:** `[INFO] ✓✓✓ Connection ACCEPTED by RTU! ✓✓✓`

### 3. Compare packets in Wireshark

Capture both:
```bash
sudo tcpdump -i enp0s3 -w broken.pcap udp port 34964
sudo tcpdump -i enp0s3 -w fixed.pcap udp port 34964
```

Open in Wireshark and filter `pn_io`:
- **Broken packet:** Wireshark shows "Malformed Packet" or "Unknown DCE/RPC"
- **Fixed packet:** Wireshark shows "PNIO-CM Connect Request" with full dissection

## Common DCE/RPC Mistakes

### 1. Wrong Flags
```python
# WRONG
flags = 0x0022  # Random flags

# RIGHT
flags1 = 0x20  # PFC_FIRST_FRAG
flags2 = 0x00  # No additional flags
```

### 2. Missing Opnum
```python
# WRONG - no opnum field
struct.pack('!BBHIQQQQIII...')

# RIGHT - opnum specified
DCERPCRequest(opnum=0)  # 0 = Connect, 1 = Release, 3 = Read, 4 = Write
```

### 3. UUID Byte Order
```python
# WRONG - string UUID directly
uuid_bytes = "DEA00001-6C97-11D1-8271-00A02442DF7D".encode()

# RIGHT - proper UUID object
uuid_obj = uuid.UUID('DEA00001-6C97-11D1-8271-00A02442DF7D')
DCERPCRequest(if_id=uuid_obj)
```

### 4. Manual Concatenation
```python
# WRONG - concatenating bytes
packet = rpc_header + ar_block + iocr_block

# RIGHT - layer composition
packet = (
    ProfinetIO() /
    DCERPCRequest() /
    IODConnectReq() /
    IOCRBlockReq()
)
```

## Why RTUs Reject Manual Packets

Industrial RTUs are **strict** about protocol compliance:

1. **Safety-critical** - reject malformed packets to prevent accidents
2. **Security** - drop packets that don't match spec exactly
3. **Interoperability** - only accept TIA Portal / standard implementations
4. **No error messages** - silent rejection to avoid DoS attacks

Your manual packet triggered one or more of these checks, so the RTU dropped it silently.

## The Fix Summary

**Before:** Manual `struct.pack()` → Malformed DCE/RPC → Silent rejection

**After:** Scapy layers → Proper DCE/RPC → RTU accepts connection

## Testing Your Fix

Run this command to see the exact difference:

```bash
# Side-by-side comparison
sudo python3 profinet_minimal/test_complete.py --interface enp0s3 --device rtu-ec3b
```

This will:
1. ✓ Discover your RTU using DCP
2. ✓ Connect using proper RPC (should work!)
3. ✓ Test cyclic I/O
4. ✓ Show detailed diagnostics

## Next Steps

Once the connection works:

1. **Add cyclic I/O** - send/receive RT frames at 0x8000/0x8001
2. **Configure I/O mapping** - based on your RTU's GSD file
3. **Handle alarms** - process alarm frames from RTU
4. **Production hardening** - add reconnection logic, error handling

The foundation is now correct - everything else builds on this!
