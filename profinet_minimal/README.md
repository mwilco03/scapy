# PROFINET IO Controller Implementation

Complete PROFINET IO Controller implementation using Scapy with DCP Discovery, RPC Connect, and Cyclic I/O.

## Overview

This implementation provides a working PROFINET IO Controller that can:
1. **Discover** PROFINET devices using DCP (Discovery and Configuration Protocol)
2. **Connect** to devices using RPC Connect to establish AR (Application Relationship)
3. **Exchange** cyclic I/O data using RT (Real-Time) frames

## Files

### Production Files

- **`profinet_controller_v4.py`** - Main production-ready controller
  - Complete implementation with all phases
  - Clean API for integration into other applications
  - Proper error handling and logging

### Diagnostic Tools

- **`profinet_diagnostic_v3.py`** - Detailed diagnostic tool
  - Bit-level AR properties validation
  - Dynamic Expected Submodule Block from RTU API
  - Comprehensive packet analysis and hex dumps
  - Helpful error messages and RTU log commands

### Reference Implementations

- **`profinet_working_final.py`** - Working DCP Discovery only
- **`profinet_connect_working.py`** - RPC Connect implementation
- **`profinet_debug.py`** - Low-level packet debugging

## Quick Start

### Basic Discovery

```bash
# Discover all PROFINET devices
sudo python3 profinet_controller_v4.py -i enp0s3
```

### Connect to Device

```bash
# Discover and connect to specific device
sudo python3 profinet_controller_v4.py -i enp0s3 -d rtu-ec3b --connect
```

### Test Cyclic I/O

```bash
# Full test: discover, connect, and test I/O
sudo python3 profinet_controller_v4.py -i enp0s3 -d rtu-ec3b --connect --test-io
```

### Diagnostic Mode

```bash
# Run diagnostic with detailed analysis
sudo python3 profinet_diagnostic_v3.py -i enp0s3 --device-ip 192.168.6.21 --device-name rtu-ec3b
```

## Architecture

### Phase 1: DCP Discovery

Uses Layer 2 (Ethernet) with EtherType 0x8892:

```python
# Build DCP Identify All request
payload = struct.pack(">H", 0xFEFE)  # Frame ID
payload += struct.pack("BB", 0x05, 0x00)  # Service ID/Type
payload += struct.pack(">I", 0x12345678)  # XID
# ... more fields ...

pkt = Ether(type=0x8892, src=src_mac, dst='01:0e:cf:00:00:00') / Raw(load=payload)
ans, unans = srp(pkt, iface=interface, timeout=timeout, verbose=0, multi=True)
```

**Key Points:**
- Use `srp()` for Layer 2 send (NOT `sr1()` which ignores iface parameter on Layer 3)
- Use raw hex payload (NOT Scapy's ProfinetDCP layers which add unwanted padding)
- Multicast destination: `01:0e:cf:00:00:00`
- Response has Frame ID `0xFEFF`

### Phase 2: RPC Connect

Uses UDP port 34964 over IP, but sent via Layer 2 for proper interface control:

```python
# Build complete Ethernet frame
packet = (
    Ether(src=controller_mac, dst=device_mac) /
    IP(src=controller_ip, dst=device_ip) /
    UDP(sport=34964, dport=34964) /
    Raw(load=rpc_payload)
)

# Send via Layer 2 (srp for Ethernet frames)
answered, unanswered = srp(packet, iface=interface, timeout=timeout, verbose=0)
```

**Critical Requirements:**
- **AR Properties device_access bit (bit 8) MUST be FALSE** (0x0060 not 0x0160)
  - If TRUE, p-net silently drops IOCRBlockReq/AlarmCRBlockReq/ExpectedSubmoduleBlockReq
- **Expected Submodule Block must match RTU's actual configuration**
  - Always include Slot 0 (DAP - Device Access Point)
  - Add application slots from RTU's `/slots` API
  - Module/Submodule IDs must match exactly
- **Use Layer 2 send with srp()** to ensure traffic goes out correct interface

**RPC Payload Structure:**
1. DCE/RPC Header (80 bytes)
   - Version 4, Type 0 (Request)
   - Activity UUID (unique per request)
   - Interface UUID (standard PROFINET: `DEA00001-6C97-11D1-8271-00A02442DF7D`)
   - Opnum 0 (Connect)

2. NDR Header (20 bytes)
   - Network Data Representation metadata

3. PNIO Blocks:
   - **AR Block** (76 bytes) - AR UUID, MACs, properties, device name
   - **IOCR Input Block** (50 bytes) - Frame ID 0x8001, cycle time, data length
   - **IOCR Output Block** (50 bytes) - Frame ID 0x8000, cycle time, data length
   - **Alarm CR Block** (12 bytes) - Alarm handling configuration
   - **Expected Submodule Block** (variable) - Module configuration

### Phase 3: Cyclic I/O

After AR establishment, cyclic data exchange uses RT frames:

**Input Data (Device → Controller):**
- Frame ID: `0x8001`
- EtherType: `0x8892`
- Sent by device at configured cycle time

**Output Data (Controller → Device):**
- Frame ID: `0x8000`
- EtherType: `0x8892`
- Sent by controller at configured cycle time

```python
# Read inputs
def read_cyclic_data(interface: str, timeout: float = 0.1) -> Optional[bytes]:
    def filter_fn(pkt):
        if not pkt.haslayer(Raw):
            return False
        data = bytes(pkt[Raw])
        if len(data) < 2:
            return False
        frame_id = struct.unpack(">H", data[0:2])[0]
        return frame_id == 0x8001  # Input data

    pkt = sniff(iface=interface, lfilter=filter_fn, count=1, timeout=timeout)
    if pkt:
        data = bytes(pkt[0][Raw])
        return data[2:]  # Skip Frame ID
    return None

# Write outputs
def write_cyclic_data(interface: str, device_mac: str, controller_mac: str, data: bytes):
    payload = struct.pack(">H", 0x8000)  # Frame ID
    payload += data
    pkt = Ether(type=0x8892, src=controller_mac, dst=device_mac) / Raw(load=payload)
    sendp(pkt, iface=interface, verbose=0)
```

## Critical Lessons Learned

### 1. Layer 2 vs Layer 3 Send

**WRONG:**
```python
# sr1() ignores iface parameter for Layer 3 packets
packet = IP(...) / UDP(...) / Raw(...)
response = sr1(packet, iface=interface)  # iface IGNORED!
```

**CORRECT:**
```python
# srp() properly sends Layer 2 packets on specified interface
packet = Ether(...) / IP(...) / UDP(...) / Raw(...)
answered, unanswered = srp(packet, iface=interface, timeout=timeout)
```

### 2. Scapy Layers vs Raw Bytes

**For DCP Discovery:**
- ❌ DON'T use `ProfinetDCP()` - adds unwanted padding (60 bytes vs 30 needed)
- ✅ DO use `Ether() / Raw()` with manual `struct.pack()`

**For RPC Connect:**
- ❌ DON'T try to use Scapy's DCE/RPC layers - incomplete for PROFINET
- ✅ DO use `Ether() / IP() / UDP() / Raw()` with manual payload construction

### 3. AR Properties Validation

The **device_access bit (bit 8)** is CRITICAL:

```python
ar_props = 0x0060  # ✅ device_access=FALSE (bit 8 = 0)
ar_props = 0x0160  # ❌ device_access=TRUE (bit 8 = 1) - RTU REJECTS!
```

When device_access=TRUE:
- p-net silently drops IOCR, Alarm CR, and Expected Submodule blocks
- No error message, just timeout
- AR appears to be for "Device AR" not "IO Controller AR"

### 4. Expected Submodule Block

Must match RTU's actual configuration:

```python
# Query RTU config
response = requests.get(f"http://{device_ip}:9081/slots", timeout=2)
config = response.json()

# ALWAYS include Slot 0 (DAP)
exp_sub += ... # Slot 0, Module 0x00000001, Submodule 0x00000001

# Add application slots from config
for slot_info in config['slots']:
    exp_sub += ... # Slot N, Module/Submodule from RTU config
```

### 5. Debugging Tips

**Check if packet is sent:**
```bash
# On controller
sudo tcpdump -i enp0s3 port 34964 -vv

# On RTU
ssh root@192.168.6.21 'sudo tcpdump -i enp0s3 port 34964 -c 1'
```

**Check RTU logs:**
```bash
ssh root@192.168.6.21
journalctl -u water-rtu-manager -f | grep -E 'CALLBACK|exp_module|device_access'
```

**Wireshark filters:**
```
# Display filter (only traffic between controller and RTU)
(pn_dcp or pn_rt or udp.port == 34964) and ((ip.src == 192.168.6.13 and ip.dst == 192.168.6.21) or (ip.src == 192.168.6.21 and ip.dst == 192.168.6.13))

# Capture filter (tcpdump) - only traffic between controller and RTU
(ether proto 0x8892 or port 34964) and ((host 192.168.6.13 and host 192.168.6.21))
```

## Integration Example

```python
from profinet_controller_v4 import PROFINETController

# Create controller
controller = PROFINETController('enp0s3')

# Discover device
device = controller.discover(device_name='rtu-ec3b', timeout=3.0)
if not device:
    print("No device found")
    exit(1)

# Connect
if controller.connect(timeout=5.0):
    print("Connected!")

    # Read inputs
    input_data = controller.read_inputs(timeout=1.0)
    if input_data:
        print(f"Input data: {input_data.hex()}")

    # Write outputs
    controller.write_outputs(b'\x00\x00\x00\x00')
else:
    print("Connect failed")
```

## Requirements

- Python 3.6+
- Scapy (`pip install scapy`)
- Root privileges (for raw socket access)
- Network interface with Layer 2 access

## References

- PROFINET Specification IEC 61158
- p-net (open-source PROFINET device stack)
- DCE/RPC Specification (OSF)
- Wireshark packet-pn-dcp.c dissector

## Troubleshooting

### DCP Discovery finds 0 devices

**Cause:** Firewall blocking multicast or using wrong payload format

**Fix:**
- Check firewall: `sudo iptables -L`
- Verify multicast MAC: `01:0e:cf:00:00:00`
- Use raw hex payload approach (don't use ProfinetDCP layers)

### RPC Connect times out

**Cause 1:** device_access bit is TRUE
- **Fix:** Set AR properties to 0x0060 (not 0x0160)

**Cause 2:** Expected Submodule doesn't match RTU config
- **Fix:** Query `/slots` API and build Expected Submodule dynamically

**Cause 3:** Packet not sent on correct interface
- **Fix:** Use `srp()` with complete Ethernet frame (not `sr1()`)

### No traffic in Wireshark

**Cause:** Using `sr1()` with Layer 3 packet - iface parameter ignored

**Fix:** Use `srp()` with Ethernet frame:
```python
packet = Ether(...) / IP(...) / UDP(...) / Raw(...)
srp(packet, iface=interface, timeout=timeout)
```

## License

MIT License - See LICENSE file

## Author

Developed with Claude Code (Anthropic)
Version 4.0.0 - 2026-02-09
