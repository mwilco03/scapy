# PROFINET Comprehensive Research and Analysis Report

**Date:** 2026-02-09
**Purpose:** Complete analysis of PROFINET protocol implementation, connection establishment, and cyclic data exchange

---

## Table of Contents

1. [Code Frequency Analysis](#part-1-code-frequency-analysis)
2. [Web Research Findings](#part-2-web-research-findings)
3. [Implementation Guide](#part-3-comprehensive-implementation-report)
   - [Connection Establishment](#31-connection-establishment-ar-setup)
   - [Cyclic Data Exchange](#32-cyclic-data-exchange)
   - [Common Pitfalls & Solutions](#33-common-pitfalls--solutions)
   - [Quick Reference](#34-quick-reference-key-values)

---

## Part 1: Code Frequency Analysis

### Key PROFINET Files in Scapy

Located in `/home/user/scapy/scapy/contrib/`:
- **pnio_rpc.py** (1554 lines) - PROFINET RPC/DCE-RPC layers for AR establishment
- **pnio_dcp.py** (671 lines) - Discovery and Configuration Protocol
- **pnio.py** (386 lines) - Real-Time Cyclic (RTC) data exchange

Test files in `/home/user/scapy/test/contrib/`:
- **pnio_rpc.uts** (844 lines) - Contains working AR setup examples
- **pnio_dcp.uts** - DCP discovery tests
- **pnio.uts** - Real-time cyclic tests

### Most Frequently Used Classes for PROFINET Controller Implementation

**Essential Imports:**
```python
from scapy.layers.dcerpc import DceRpc4
from scapy.contrib.pnio_rpc import (
    PNIOServiceReqPDU,
    ARBlockReq,
    IOCRBlockReq,
    AlarmCRBlockReq,
    ExpectedSubmoduleBlockReq,
    ExpectedSubmoduleAPI,
    ExpectedSubmodule,
    ExpectedSubmoduleDataDescription,
    IOCRAPI,
    IOCRAPIObject,
    IODControlReq
)
from scapy.contrib.pnio_dcp import ProfinetDCP
from scapy.contrib.pnio import ProfinetIO, PNIORealTimeCyclicPDU
```

**Most Important Classes by Function:**

1. **Connection Establishment (AR Setup):**
   - `ARBlockReq` - Application Relationship block (lines 776-819)
   - `IOCRBlockReq` - IO Communication Relationship (lines 868-911)
   - `AlarmCRBlockReq` - Alarm Communication Relationship (lines 1133-1170)
   - `ExpectedSubmoduleBlockReq` - Module configuration (lines 1105-1121)

2. **Discovery (DCP):**
   - `ProfinetDCP` - Main DCP packet (lines 534-668 in pnio_dcp.py)
   - `DCPNameOfStationBlock` - Station name operations
   - `DCPIPBlock` - IP address configuration

3. **Cyclic Data Exchange:**
   - `ProfinetIO` - Base PROFINET packet (lines 90-114 in pnio.py)
   - `PNIORealTimeCyclicPDU` - RT cyclic frames (lines 168-279)
   - `PNIORealTime_IOxS` - IOPS/IOCS status bytes

4. **Control Operations:**
   - `IODControlReq` - Control commands (PrmEnd, ApplicationReady, etc.)
   - `IODWriteReq` - Write parameter data
   - `IODReadReq` - Read parameter data

### Key Functions and Methods

**From pnio_rpc.py:**
- `dce_rpc_endianness()` - Determine endianness for DCE/RPC packets
- `_guess_block_class()` - Auto-detect block types during parsing
- `get_response()` - Generate response blocks from requests

**From pnio.py:**
- `i2s_frameid()` / `s2i_frameid()` - Convert frame IDs to/from names
- `get_layout_from_config()` - Configure cyclic data layouts

### Common Patterns in Test Files

**Working AR Connect Pattern (lines 592-697 in pnio_rpc.uts):**
```python
packet = (
    Ether(dst=device_mac) /
    IP(dst=device_ip) /
    UDP(sport=34964, dport=34964) /
    DceRpc4(
        endian='little',
        opnum=0,  # Connect operation
        object='dea00000-6c97-11d1-8271-010203040506',
        if_id=UUID("dea00001-6c97-11d1-8271-00a02442df7d")  # Device Interface
    ) /
    PNIOServiceReqPDU(blocks=[...])
)
```

---

## Part 2: Web Research Findings

### Official Standards and Specifications

1. **IEC 61158/61784 Standards**
   - Current: PROFINET V2.4MU3 (IEC 61158-6-10:2023, IEC 61158-5-10:2023, IEC 61784-2-3:2023)
   - Draft V2.5 available for review (February 2026 deadline) with new security features
   - Available from: [PROFIBUS & PROFINET International](https://www.profibus.com/download/profinet-specification)

2. **DCE/RPC Protocol**
   - PROFINET uses connectionless DCE/RPC over UDP
   - Endianness specified in packet header (little-endian common for PROFINET)
   - Microsoft RPC specs provide background: [MS-RPCE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/)

### Implementation Guides and Tutorials

1. **RT-Labs Beginner Guide**
   - [60-minute PROFINET tutorial](https://rt-labs.com/profinet/a-beginners-guide-to-profinet-get-started-in-60-minutes/)
   - Uses Raspberry Pi with P-Net stack and Codesys PLC

2. **PROFINET Configuration Demonstration**
   - [Full network configuration guide](https://us.profinet.com/profinet-configuration-demonstration/)
   - Covers GSD file import and controller setup

3. **Design Guidelines**
   - [PROFINET Design Guideline V1.14](https://www.profibus-profinet.cz/images/Dokumenty/PROFINET/16548_PROFINET_Design_guideline_8062_V114_Dec14.pdf)
   - Network topology, RT/IRT traffic, wireless, PoE

4. **2025 Complete Guide**
   - [PROFINET Protocol Complete Guide](https://plcprogramming.io/protocols/profinet)
   - Technical specs, use cases, implementation

### Open Source Projects

#### Device (Slave) Stacks

1. **P-Net PROFINET Stack**
   - Repository: [rtlabs-com/p-net](https://github.com/rtlabs-com/p-net)
   - Embedded device stack (C language)
   - Spec 2.4 compliant, Conformance Class A & B, RT Class 1
   - Dual-licensed: GPL v3 + Commercial
   - ⚠️ **Device-only** - No controller support

2. **profipp (P-Net C++ Wrapper)**
   - Repository: [langmo/profipp](https://github.com/langmo/profipp)
   - C++/C wrapper API for p-net device stack
   - Buildable (CMake), targets embedded (Raspberry Pi)
   - Experimental/academic flavor

#### Controller Implementations

3. **PROFINET Controller Simulator (Python)**
   - Repository: [seb711/Profinet-Controller-Simu](https://github.com/seb711/Profinet-Controller-Simu)
   - Python-based PROFINET Controller simulator
   - Loads GSDML files, establishes connections, exchanges cyclic messages
   - Includes GUI (Qt)
   - Status: Experimental/incomplete, limited commits

4. **PROFINET IO Communication (C)**
   - Repository: [vipulsaini2327/profinet-io-communication](https://github.com/vipulsaini2327/profinet-io-communication)
   - Basic demo in C (Linux) with DCP discovery, device listing, PNIO data exchange
   - Initiates connections to devices (controller role)
   - Buildable (Makefile), includes MQTT integration
   - Status: Low activity, likely abandoned proof-of-concept

5. **PROFINET Simple (C#/Windows)**
   - Repository: [hablix/profinet-simple](https://github.com/hablix/profinet-simple)
   - Windows console app in C# using Pcap.Net/WinPcap
   - Packet-level communication with PROFINET field devices (controller/master role)
   - Buildable in Visual Studio
   - Status: Academic origin, abandoned since 2021, but functional for basic interaction

#### Protocol Analysis & Tools

6. **Scapy PROFINET Implementation**
   - [Scapy PROFINET layers](https://github.com/secdev/scapy/blob/master/scapy/contrib/pnio.py)
   - [Documentation](https://scapy.readthedocs.io/en/latest/layers/pnio.html)
   - Complete protocol implementation for packet crafting

7. **PROFINET Scanner Tools**
   - [scada-tools/profinet_scanner](https://github.com/atimorin/scada-tools/blob/master/profinet_scanner.scapy.py)
   - Multicast discovery and device enumeration

8. **Wireshark PROFINET Dissectors**
   - [PROFINET dissector](https://github.com/boundary/wireshark/blob/master/plugins/profinet/packet-dcerpc-pn-io.c)
   - Excellent reference for packet structure

9. **ICSNPP PROFINET IO-CM (Zeek Plugin)**
   - Repository: [cisagov/icsnpp-profinet-io-cm](https://github.com/cisagov/icsnpp-profinet-io-cm)
   - Zeek/Spicy plugin for parsing PROFINET IO-CM (DCE/RPC) traffic
   - Network dissector/monitor only (~10% protocol coverage)
   - Not a stack or controller implementation

10. **TcPnScanner (TwinCAT Utility)**
    - Repository: [TcHaxx/TcPnScanner](https://github.com/TcHaxx/TcPnScanner)
    - C# tool that passively scans existing PROFINET controller traffic
    - Exports devices for Beckhoff TwinCAT simulation (device/slave side)
    - Buildable (.NET), active (2024 release)
    - Utility tool, not a controller

#### Hardware-Specific Examples

11. **Hilscher netPI Packet Handler**
    - Repository: [HilscherAutomation/netPI-netx-programming-examples](https://github.com/HilscherAutomation/netPI-netx-programming-examples)
    - File: PacketHandlerPNS.c
    - Low-level C example for packet handling on Hilscher netX hardware
    - Generic PROFINET packet processing, hardware-specific
    - Not a full controller implementation

#### Key Findings from Repository Analysis

**Controller Implementation Rarity:**
- **Mature controller implementations are extremely rare** in open source
- Most projects are device (slave) stacks or monitoring/analysis tools
- The 3 controller repos found are all experimental/abandoned/incomplete

**Why Controllers Are Rare:**
1. Commercial licensing (vendors like Siemens, Rockwell sell controllers)
2. Complexity of full implementation
3. Certification requirements for production use
4. Patent/IP concerns

**Best References for Implementation:**
1. **Scapy layers** (most complete, actively maintained)
2. **P-Net device stack** (for understanding device-side expectations)
3. **Wireshark dissectors** (for packet structure validation)
4. **hablix/profinet-simple** (simple C# controller example, though abandoned)

### Technical Documentation

1. **AR Setup Process**
   - [Setup of Application Relation](https://www.felser.ch/profinet-manual/pn_kommunikationsbeziehung.html)
   - Detailed step-by-step AR establishment

2. **Cyclic Data Exchange**
   - [Decoding cyclic frames](https://hilscher.atlassian.net/wiki/spaces/PNS3V5/pages/123226978)
   - [Timing calculations](https://felser.ch/profinet-manual/t_-_timing.html)

3. **IOPS/IOCS Documentation**
   - [Hilscher IOCS/IOPS guide](https://hilscher.atlassian.net/wiki/spaces/GLOBALSUP/pages/122802112/PROFINET+IO+Controller+V3+-+IOCS+IOPS+EN)

---

## Part 3: Comprehensive Implementation Report

### 3.1 Connection Establishment (AR Setup)

#### Complete Step-by-Step Process

**1. Device Discovery (DCP)**
```python
# Send DCP Identify All request
discover_pkt = (
    Ether(dst="01:0e:cf:00:00:00", type=0x8892) /
    Raw(load=struct.pack(
        '!HHIHHBBH',
        0xFEFE,  # Frame ID: DCP-Identify-ReqPDU
        0x0500,  # Service ID: Identify, Type: Request
        0x01000001,  # XID
        0, 4,  # Reserved, data length
        255, 255,  # Option: All, SubOption: All
        0  # Block length
    ))
)

# Use srp() for Layer 2
answers, _ = srp(discover_pkt, iface=interface, timeout=2, verbose=0)
```

**2. Set Station Name (if needed)**
```python
set_name_pkt = (
    Ether(dst=device_mac, type=0x8892) /
    ProfinetDCP(
        service_id=0x04,  # Set
        service_type=0x00,  # Request
        option=2,  # Device properties
        sub_option=2,  # Name of station
        block_qualifier=1,  # Save permanent
        name_of_station="my-device"
    )
)
```

**3. Establish AR (Connect Request)**

**Required UUIDs:**
- **Device Interface UUID:** `dea00001-6c97-11d1-8271-00a02442df7d`
- **Controller Interface UUID:** `dea00002-6c97-11d1-8271-00a02442df7d`
- **Object UUID:** Must start with `dea00000-6c97-11d1-8271-` (last 6 bytes = MAC address)
- **AR UUID:** Unique identifier for this AR (random UUID)

**Critical Parameters:**

```python
connect_pkt = (
    Ether(dst=device_mac) /
    IP(dst=device_ip) /
    UDP(sport=34964, dport=34964) /
    DceRpc4(
        endian='little',  # PROFINET typically uses little-endian
        opnum=0,  # Connect operation
        seqnum=0,
        object='dea00000-6c97-11d1-8271-aabbccddeeff',  # Use controller MAC
        if_id=UUID("dea00001-6c97-11d1-8271-00a02442df7d"),  # Device Interface
        act_id='01234567-89ab-cdef-0123-456789abcdef'  # Activity ID
    ) /
    PNIOServiceReqPDU(blocks=[
        # Block 1: AR Block
        ARBlockReq(
            ARType='IOCARSingle',  # 0x0001
            ARUUID='fedcba98-7654-3210-fedc-ba9876543210',  # Random unique
            SessionKey=0,
            CMInitiatorMacAdd='aa:bb:cc:dd:ee:ff',  # Controller MAC
            CMInitiatorObjectUUID='dea00000-6c97-11d1-8271-aabbccddeeff',
            CMInitiatorStationName='my-controller',
            # CRITICAL: DeviceAccess bit (bit 8) MUST be 0 for IO Controller AR
            ARProperties_DeviceAccess='ExpectedSubmodule',  # Bit 8 = 0
            ARProperties_State=1,  # Active
            ARProperties_ParametrizationServer='CM_Initator',
            CMInitiatorActivityTimeoutFactor=1000,
            CMInitiatorUDPRTPort=0x8892
        ),

        # Block 2: IOCR Input Block (device → controller)
        IOCRBlockReq(
            IOCRType='InputCR',  # 0x0001
            IOCRReference=1,
            FrameID=0x8001,  # Typical input frame ID
            DataLength=40,  # Total data length
            SendClockFactor=32,  # 32 * 31.25μs = 1ms base
            ReductionRatio=32,  # Update time = 32 * 1ms = 32ms
            Phase=1,
            WatchdogFactor=10,
            DataHoldFactor=10,
            IOCRProperties_RTClass='RT_CLASS_1',
            APIs=[
                IOCRAPI(
                    API=0,
                    IODataObjects=[
                        IOCRAPIObject(SlotNumber=3, SubslotNumber=1, FrameOffset=0),
                    ],
                    IOCSs=[
                        IOCRAPIObject(SlotNumber=3, SubslotNumber=1, FrameOffset=4),
                    ]
                )
            ]
        ),

        # Block 3: IOCR Output Block (controller → device)
        IOCRBlockReq(
            IOCRType='OutputCR',  # 0x0002
            IOCRReference=2,
            FrameID=0x8000,  # Typical output frame ID
            DataLength=52,
            SendClockFactor=32,
            ReductionRatio=32,
            Phase=1,
            WatchdogFactor=10,
            DataHoldFactor=10,
            IOCRProperties_RTClass='RT_CLASS_1',
            APIs=[
                IOCRAPI(
                    API=0,
                    IODataObjects=[
                        IOCRAPIObject(SlotNumber=3, SubslotNumber=1, FrameOffset=0),
                    ]
                )
            ]
        ),

        # Block 4: Alarm CR Block
        AlarmCRBlockReq(
            AlarmCRType='AlarmCR',  # 0x0001
            LT=0x8892,
            AlarmCRProperties_Transport='RTA_CLASS_1',
            RTATimeoutFactor=1,
            RTARetries=3,
            LocalAlarmReference=3,
            MaxAlarmDataLength=200,
            AlarmCRTagHeaderHigh=0xC000,
            AlarmCRTagHeaderLow=0xA000
        ),

        # Block 5: Expected Submodule Block (CRITICAL!)
        # MUST include Slot 0.1 (DAP) and all configured modules
        ExpectedSubmoduleBlockReq(
            APIs=[
                # DAP (Device Access Point) - Always required!
                ExpectedSubmoduleAPI(
                    API=0,
                    SlotNumber=0,  # DAP is always slot 0
                    ModuleIdentNumber=0x00000001,  # From device GSD
                    Submodules=[
                        ExpectedSubmodule(
                            SubslotNumber=1,  # Subslot 1 (0.1)
                            SubmoduleIdentNumber=0x00000001,  # From GSD
                            SubmoduleProperties_Type='NO_IO'
                        )
                    ]
                ),
                # Your actual I/O module
                ExpectedSubmoduleAPI(
                    API=0,
                    SlotNumber=3,
                    ModuleIdentNumber=0x08c4,  # From device GSD
                    Submodules=[
                        ExpectedSubmodule(
                            SubslotNumber=1,
                            SubmoduleIdentNumber=0x0124,  # From GSD
                            SubmoduleProperties_Type='INPUT_OUTPUT',
                            DataDescription=[
                                ExpectedSubmoduleDataDescription(
                                    DataDescription='Output',
                                    SubmoduleDataLength=3,
                                    LengthIOPS=1,
                                    LengthIOCS=1
                                ),
                                ExpectedSubmoduleDataDescription(
                                    DataDescription='Input',
                                    SubmoduleDataLength=5,
                                    LengthIOPS=1,
                                    LengthIOCS=1
                                )
                            ]
                        )
                    ]
                )
            ]
        )
    ])
)

# Send and receive response
response = sr1(connect_pkt, timeout=5)
```

**4. Parameter End (IODControl)**
```python
prm_end_pkt = (
    Ether(dst=device_mac) /
    IP(dst=device_ip) /
    UDP(sport=34964, dport=34964) /
    DceRpc4(
        endian='little',
        opnum=1,  # Control operation
        object=object_uuid,
        if_id=device_interface_uuid
    ) /
    PNIOServiceReqPDU(blocks=[
        IODControlReq(
            ARUUID=ar_uuid,
            SessionKey=session_key,
            ControlCommand_PrmEnd=1,
            ControlCommand_Done=0
        )
    ])
)
```

**5. Application Ready (IODControl)**
```python
app_ready_pkt = (
    # Similar to PrmEnd but with:
    IODControlReq(
        ARUUID=ar_uuid,
        SessionKey=session_key,
        ControlCommand_ApplicationReady=1,
        ControlCommand_Done=0
    )
)
```

#### AR Properties Bit Field (CRITICAL!)

```
Bits 31-10: Reserved
Bit 9: AcknowledgeCompanionAR (0)
Bits 8-7: CompanionAR (0 = Single_AR)
Bit 6: DeviceAccess *** CRITICAL! ***
  - 0 = ExpectedSubmodule (USE THIS for IO Controller)
  - 1 = Controlled by device app (causes silent rejection!)
Bits 5-3: Reserved
Bit 2: ParametrizationServer (1 = CM_Initiator)
Bit 1: SupervisorTakeoverAllowed (0)
Bit 0: State (1 = Active)

Recommended value: 0x0060 (binary: 0000 0000 0110 0000)
WRONG value: 0x0160 (bit 8 set - will be rejected!)
```

---

### 3.2 Cyclic Data Exchange

#### RT Frame Structure

**Frame IDs:**
- **0x8000-0x8FFF**: RT_CLASS_1 Output frames (Controller → Device)
- **0x8001-0x8FFF**: RT_CLASS_1 Input frames (Device → Controller)
- **0x0100-0x0FFF**: RT_CLASS_3 frames (IRT)
- **0xC000-0xFBFF**: RT_CLASS_UDP frames

**Typical Output Frame (Controller → Device):**
```
[Ethernet Header]
  dst: Device MAC
  src: Controller MAC
  type: 0x8892 (PROFINET)

[PROFINET IO Header]
  FrameID: 0x8000

[Cyclic Data (C_SDU)]
  [Data Bytes] - Process output data
  [IOPS Bytes] - IO Provider Status (1 byte per submodule)

[Padding] - 0 to 40 bytes

[APDU Status]
  CycleCounter: 2 bytes (increments each cycle)
  DataStatus: 1 byte (0x35 = valid, primary, run, no problem)
  TransferStatus: 1 byte (0x00)
```

**IOPS/IOCS Values:**
```
Good Status: 0x80
  Bit 7: DataState = 1 (good)
  Bits 6-5: Instance = 00 (subslot)
  Bits 4-1: Reserved = 0000
  Bit 0: Extension = 0

Bad Status: 0x00
  Indicates invalid or unavailable data
```

#### Timing Calculations

**Update Time Formula:**
```
Update_Time = ReductionRatio × SendClockFactor × 31.25μs

Examples:
- 1ms:   RR=1,  SCF=32  → 1 × 32 × 31.25μs = 1ms
- 32ms:  RR=32, SCF=32  → 32 × 32 × 31.25μs = 32ms
- 4ms:   RR=4,  SCF=32  → 4 × 32 × 31.25μs = 4ms
```

**Watchdog Time:**
```
Watchdog = WatchdogFactor × ReductionRatio × SendClockFactor × 31.25μs
```

#### Sending/Receiving RT Frames

**Sending Output Data:**
```python
# Build RT frame
output_data = b'\x01\x02\x03'  # Your process data
iops = b'\x80'  # Good status

rt_frame = (
    Ether(dst=device_mac, src=controller_mac, type=0x8892) /
    ProfinetIO(frameID=0x8000) /
    Raw(load=output_data + iops + b'\x00' * padding_len) /
    struct.pack('!HBB', cycle_counter, 0x35, 0x00)
)

# Send at cyclic rate (e.g., every 1ms)
sendp(rt_frame, iface=interface, verbose=0)
cycle_counter = (cycle_counter + 1) % 65536
```

**Receiving Input Data:**
```python
def handle_input_frame(pkt):
    if pkt.haslayer(ProfinetIO) and pkt[ProfinetIO].frameID == 0x8001:
        # Extract data
        raw_data = bytes(pkt[Raw])
        input_data = raw_data[:-4]  # Exclude APDU status
        cycle_counter = struct.unpack('!H', raw_data[-4:-2])[0]
        data_status = raw_data[-2]

        # Check IOPS
        if input_data[-1] == 0x80:
            process_data = input_data[:-1]
            print(f"Input data: {process_data.hex()}")

sniff(iface=interface, prn=handle_input_frame, filter="ether proto 0x8892")
```

---

### 3.3 Common Pitfalls & Solutions

#### 1. **AR Properties DeviceAccess Bit (Bit 8)**

**Problem:** Device silently rejects AR Connect with no response

**Root Cause:** ARProperties bit 8 (DeviceAccess) set to 1

**Solution:**
```python
# WRONG - bit 8 = 1 (0x0160)
ARBlockReq(ARProperties_DeviceAccess='Controlled_by_IO_device_app')  # ✗

# CORRECT - bit 8 = 0 (0x0060)
ARBlockReq(ARProperties_DeviceAccess='ExpectedSubmodule')  # ✓
```

**Why:** When bit 8 = 1, the device expects its application to control submodule access, but for a standard IO Controller AR, you must specify expected submodules explicitly (bit 8 = 0).

#### 2. **Missing or Incorrect DAP Configuration**

**Problem:** Device rejects AR with ModuleDiffBlock

**Root Cause:** Slot 0.1 (DAP) not included or wrong module IDs

**Solution:**
```python
# ALWAYS include DAP in ExpectedSubmoduleBlockReq
ExpectedSubmoduleBlockReq(APIs=[
    # DAP - CRITICAL!
    ExpectedSubmoduleAPI(
        API=0,
        SlotNumber=0,  # Always 0 for DAP
        ModuleIdentNumber=0x00000001,  # Check device GSD or query http://device:9081/slots
        Submodules=[
            ExpectedSubmodule(
                SubslotNumber=1,  # Always 1 for DAP
                SubmoduleIdentNumber=0x00000001,  # Must match device
                SubmoduleProperties_Type='NO_IO'
            )
        ]
    ),
    # ... your other modules ...
])
```

**How to get correct IDs:**
- Query device: `http://{device_ip}:9081/slots`
- Check device GSD/GSDML file
- Capture working connection from PLC with Wireshark

#### 3. **Station Name Not Set**

**Problem:** DCP Set Name works, but AR Connect fails

**Root Cause:** Device requires station name to match expected configuration

**Solution:**
```python
# 1. Set station name first
set_name_pkt = Ether(dst=device_mac, type=0x8892) / ProfinetDCP(
    service_id=0x04, service_type=0x00,
    option=2, sub_option=2,
    block_qualifier=1,  # Save permanent
    name_of_station="my-device"
)
srp(set_name_pkt, iface=interface)

# 2. Wait for device to save and reboot if needed
time.sleep(2)

# 3. Then connect with matching station name
ARBlockReq(CMInitiatorStationName='my-controller')
```

**Station Name Rules:**
- Max 240 chars (but tools often limit to 63)
- Use only: 0-9, a-z, hyphen (-)
- Cannot start/end with hyphen
- Prefer lowercase
- Must be unique on network

#### 4. **Using sr1() Instead of srp() for Layer 2**

**Problem:** DCP requests sent but no response received

**Root Cause:** `sr1()` ignores the `iface` parameter for Layer 2 packets

**Solution:**
```python
# WRONG - doesn't work for Layer 2
response = sr1(dcp_packet, iface=interface)  # ✗

# CORRECT - use srp() for Layer 2
answers, _ = srp(dcp_packet, iface=interface, timeout=2)  # ✓
if answers:
    response = answers[0][1]
```

#### 5. **Module/Submodule ID Mismatch**

**Problem:** Device sends ModuleDiffBlock in Connect Response

**Root Cause:** Expected module IDs don't match actual device configuration

**Solution:**
```python
# Query device configuration
import requests
config = requests.get(f'http://{device_ip}:9081/slots').json()

# Use actual IDs from device
for slot in config['slots']:
    ExpectedSubmoduleAPI(
        SlotNumber=slot['number'],
        ModuleIdentNumber=slot['module_id'],  # From device
        Submodules=[
            ExpectedSubmodule(
                SubslotNumber=sub['number'],
                SubmoduleIdentNumber=sub['id'],  # From device
                SubmoduleProperties_Type=sub['type']
            )
            for sub in slot['submodules']
        ]
    )
```

#### 6. **Wrong Endianness in DCE/RPC**

**Problem:** Device doesn't parse Connect Request

**Root Cause:** Incorrect endianness setting

**Solution:**
```python
# PROFINET typically uses little-endian
DceRpc4(
    endian='little',  # NOT 'big'!
    # ... rest of fields
)
```

#### 7. **Incorrect Frame ID Range**

**Problem:** RT frames not received by device

**Root Cause:** Frame ID outside valid range or conflicting IDs

**Solution:**
```python
# Standard RT Class 1 ranges
IOCRBlockReq(
    IOCRType='OutputCR',
    FrameID=0x8000,  # Valid: 0x8000-0xBFFF for RT_CLASS_1
)

IOCRBlockReq(
    IOCRType='InputCR',
    FrameID=0x8001,  # Different from output!
)
```

#### 8. **Not Handling Connect Response**

**Problem:** Connection seems successful but cyclic data fails

**Root Cause:** Not extracting SessionKey and adjusted parameters from response

**Solution:**
```python
# Send Connect Request
response = sr1(connect_pkt, timeout=5)

# Parse response
if response and response.haslayer(PNIOServiceResPDU):
    for block in response[PNIOServiceResPDU].blocks:
        if isinstance(block, ARBlockRes):
            session_key = block.SessionKey  # Save for later use
        elif isinstance(block, IOCRBlockRes):
            actual_frame_id = block.FrameID  # Device may change FrameID
```

#### 9. **Timing Issues**

**Problem:** Watchdog timeout, connection drops

**Root Cause:** Wrong SendClockFactor, ReductionRatio, or WatchdogFactor

**Solution:**
```python
# Conservative settings for testing
IOCRBlockReq(
    SendClockFactor=32,  # 1ms base clock
    ReductionRatio=32,   # 32ms update time
    WatchdogFactor=10,   # 10x timeout = 320ms
    DataHoldFactor=10
)

# Send RT frames at correct rate
update_time = 32e-3  # 32ms
while True:
    sendp(rt_frame, iface=interface)
    time.sleep(update_time)
```

#### 10. **Using ProfinetDCP Layer for Discovery**

**Problem:** DCP Identify packet has wrong format

**Root Cause:** ProfinetDCP layer adds padding in wrong places

**Solution:**
```python
# DON'T use ProfinetDCP for discovery - build manually
discover = (
    Ether(dst="01:0e:cf:00:00:00", type=0x8892) /
    Raw(load=struct.pack(
        '!HHIHHBBH',
        0xFEFE,       # Frame ID
        0x0500,       # Service: Identify, Type: Request
        0x01000001,   # XID
        0, 4,         # Reserved, Length
        255, 255,     # Option: All, SubOption: All
        0             # Block length
    ))
)
```

#### 11. **CMInitiatorStationName Confusion**

**Problem:** Controller uses device name instead of controller name

**Root Cause:** Confusion between controller station name and device name

**Solution:**
```python
# WRONG - using device name
ARBlockReq(CMInitiatorStationName='rtu-ec3b')  # ✗ (device name)

# CORRECT - using controller's own name
import socket
controller_name = socket.gethostname()  # e.g., 'rtu-967e'
ARBlockReq(CMInitiatorStationName=controller_name)  # ✓
```

**Clarification:**
- `--device-name` parameter = The device you're connecting TO (e.g., "rtu-ec3b")
- `CMInitiatorStationName` = The controller's own station name (e.g., "rtu-967e")

---

### 3.4 Quick Reference: Key Values

**UUIDs:**
```
Device Interface:     dea00001-6c97-11d1-8271-00a02442df7d
Controller Interface: dea00002-6c97-11d1-8271-00a02442df7d
Supervisor Interface: dea00003-6c97-11d1-8271-00a02442df7d
Object UUID format:   dea00000-6c97-11d1-8271-{controller_mac}
```

**Frame IDs:**
```
DCP Identify Request:  0xFEFE
DCP Identify Response: 0xFEFF
DCP Get/Set:           0xFEFD
RT Output (typical):   0x8000
RT Input (typical):    0x8001
Alarm High:            0xFC01
Alarm Low:             0xFE01
```

**Ports:**
```
UDP/RT: 34964 (0x8892)
Ethertype: 0x8892
```

**AR Properties (recommended):**
```
Value: 0x0060
  Bit 8 (DeviceAccess) = 0 ✓
  Bit 2 (ParametrizationServer) = 1
  Bit 0 (State) = 1
```

**IOPS/IOCS:**
```
Good: 0x80
Bad:  0x00
```

---

## Sources and References

### Official Standards
- [PROFINET Specification Downloads](https://www.profibus.com/download/profinet-specification)
- [IEC 61158/61784 Standards](https://webstore.iec.ch)
- [Microsoft RPC Protocol Specs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/)

### Implementation Guides
- [RT-Labs Beginner's Guide to PROFINET](https://rt-labs.com/profinet/a-beginners-guide-to-profinet-get-started-in-60-minutes/)
- [PROFINET Configuration Demonstration](https://us.profinet.com/profinet-configuration-demonstration/)
- [PROFINET Design Guideline V1.14](https://www.profibus-profinet.cz/images/Dokumenty/PROFINET/16548_PROFINET_Design_guideline_8062_V114_Dec14.pdf)
- [PROFINET Protocol Complete Guide 2025](https://plcprogramming.io/protocols/profinet)

### Open Source Projects
- [P-Net PROFINET Device Stack](https://github.com/rtlabs-com/p-net)
- [Scapy PROFINET Layers](https://github.com/secdev/scapy/blob/master/scapy/contrib/pnio.py)
- [Scapy PROFINET Documentation](https://scapy.readthedocs.io/en/latest/layers/pnio.html)
- [PROFINET Scanner Tools](https://github.com/atimorin/scada-tools/blob/master/profinet_scanner.scapy.py)
- [Wireshark PROFINET Dissector](https://github.com/boundary/wireshark/blob/master/plugins/profinet/packet-dcerpc-pn-io.c)

### Technical Documentation
- [Setup of Application Relation](https://www.felser.ch/profinet-manual/pn_kommunikationsbeziehung.html)
- [PROFINET Cyclic Frame Decoding](https://hilscher.atlassian.net/wiki/spaces/PNS3V5/pages/123226978)
- [PROFINET Timing Calculations](https://felser.ch/profinet-manual/t_-_timing.html)
- [Hilscher PROFINET IOCS/IOPS Guide](https://hilscher.atlassian.net/wiki/spaces/GLOBALSUP/pages/122802112/PROFINET+IO+Controller+V3+-+IOCS+IOPS+EN)
- [PROFINET Troubleshooting Guide](https://hilscher.atlassian.net/wiki/spaces/GLOBALSUP/pages/122791141/PROFINET+Troubleshooting)
- [PROFINET Naming Convention](https://profinetuniversity.com/naming-addressing/profinet-naming-convention/)
- [What's in a PROFINET Device Name](https://profinews.com/2017/01/whats-in-a-profinet-device-name/)

---

**Report Generated:** 2026-02-09
**Based on:** Comprehensive code analysis, web research, and official PROFINET documentation
