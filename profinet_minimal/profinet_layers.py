#!/usr/bin/env python3
"""
Custom PROFINET Scapy Layers - Built from scratch

Creates proper Scapy patterns for PROFINET controller functionality.
If Scapy's built-in layers don't work, we build our own.

Version: 1.0.0
Date: 2026-02-09
"""

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ByteField, ShortField, IntField, StrFixedLenField,
    StrLenField, XByteField, XShortField, XIntField,
    MACField, IPField, FieldLenField, ConditionalField,
    ByteEnumField, ShortEnumField
)
from scapy.layers.l2 import Ether
from scapy.all import *


# ===== PROFINET Real-Time (RT) Layer =====

class ProfinetRT(Packet):
    """
    PROFINET Real-Time base layer
    Used for all PROFINET frames (DCP, cyclic I/O, etc.)
    """
    name = "PROFINET RT"
    fields_desc = [
        XShortField("frameID", 0x8000)
    ]

    def guess_payload_class(self, payload):
        # Route to DCP or cyclic based on frameID
        if self.frameID == 0xFEFE or self.frameID == 0xFEFF:
            return ProfinetDCP
        elif 0x8000 <= self.frameID <= 0xBFFF:
            return ProfinetCyclic
        return Packet.guess_payload_class(self, payload)


# ===== DCP (Discovery and Configuration Protocol) =====

DCP_SERVICE_IDS = {
    0x03: "Get",
    0x04: "Set",
    0x05: "Identify",
    0x06: "Hello"
}

DCP_SERVICE_TYPES = {
    0x00: "Request",
    0x01: "Response Success",
    0x05: "Not Supported"
}

class ProfinetDCP(Packet):
    """
    PROFINET DCP layer - Custom implementation

    Fixes issues with Scapy's built-in:
    - Allows custom XID (not hardcoded default)
    - Correct field ordering
    - No unwanted padding
    """
    name = "PROFINET DCP"
    fields_desc = [
        ByteEnumField("service_id", 0x05, DCP_SERVICE_IDS),
        ByteEnumField("service_type", 0x00, DCP_SERVICE_TYPES),
        XIntField("xid", 0x12345678),  # Default to working value
        XShortField("reserved", 0x0001),
        ShortField("dcp_data_length", None),

        # Request-specific fields
        ConditionalField(
            XByteField("option", 0xFF),
            lambda pkt: pkt.service_type == 0x00
        ),
        ConditionalField(
            XByteField("sub_option", 0xFF),
            lambda pkt: pkt.service_type == 0x00
        ),
        ConditionalField(
            ShortField("dcp_block_length", 0),
            lambda pkt: pkt.service_type == 0x00
        )
    ]

    def post_build(self, pkt, pay):
        # Auto-calculate dcp_data_length if None
        if self.dcp_data_length is None:
            # For Identify All: 4 bytes (option + sub_option + block_length)
            if self.service_type == 0x00:
                pkt = pkt[:6] + struct.pack("!H", 4) + pkt[8:]
        return pkt + pay


class DCPBlock(Packet):
    """Base class for DCP response blocks"""
    name = "DCP Block"
    fields_desc = [
        XByteField("option", 0x02),
        XByteField("sub_option", 0x02),
        ShortField("block_length", None)
    ]


class DCPNameOfStation(DCPBlock):
    """DCP Name of Station block"""
    name = "DCP Name of Station"
    fields_desc = [
        XByteField("option", 0x02),
        XByteField("sub_option", 0x02),
        FieldLenField("block_length", None, length_of="device_name", fmt="!H", adjust=lambda pkt,x: x+2),
        XShortField("block_info", 0x0000),
        StrLenField("device_name", "device", length_from=lambda pkt: pkt.block_length - 2)
    ]


class DCPIPParameter(DCPBlock):
    """DCP IP Parameter block"""
    name = "DCP IP Parameter"
    fields_desc = [
        XByteField("option", 0x01),
        XByteField("sub_option", 0x02),
        ShortField("block_length", 14),
        XShortField("block_info", 0x0000),
        IPField("ip", "0.0.0.0"),
        IPField("netmask", "0.0.0.0"),
        IPField("gateway", "0.0.0.0")
    ]


class DCPDeviceID(DCPBlock):
    """DCP Device ID block"""
    name = "DCP Device ID"
    fields_desc = [
        XByteField("option", 0x02),
        XByteField("sub_option", 0x03),
        ShortField("block_length", 6),
        XShortField("block_info", 0x0000),
        ShortField("vendor_id", 0),
        ShortField("device_id", 0)
    ]


# ===== PROFINET Cyclic I/O =====

class ProfinetCyclic(Packet):
    """
    PROFINET Cyclic I/O frame
    For real-time data exchange
    """
    name = "PROFINET Cyclic"
    fields_desc = [
        # Cycle counter (optional, depends on frameID)
        ConditionalField(
            ShortField("cycle_counter", 0),
            lambda pkt: hasattr(pkt, 'underlayer') and
                       hasattr(pkt.underlayer, 'frameID') and
                       0x8000 <= pkt.underlayer.frameID <= 0xBFFF
        ),
        # Data status
        XByteField("data_status", 0x35),
        XByteField("transfer_status", 0x00)
    ]


# ===== RPC (for AR establishment) =====

class DCERPC(Packet):
    """
    DCE/RPC header for PROFINET Connect/Release
    Custom implementation because Scapy's is incomplete
    """
    name = "DCE/RPC"
    fields_desc = [
        ByteField("version", 4),
        ByteField("packet_type", 0),  # 0=Request, 2=Response
        ByteField("flags1", 0x20),    # PFC_FIRST_FRAG
        ByteField("flags2", 0x00),
        ByteField("drep0", 0x10),     # Little endian
        ByteField("drep1", 0x00),
        ByteField("drep2", 0x00),
        ByteField("drep3", 0x00),
        ShortField("frag_length", None),
        ShortField("auth_length", 0),
        IntField("call_id", 0),

        # Request-specific
        ConditionalField(
            IntField("alloc_hint", 0),
            lambda pkt: pkt.packet_type == 0
        ),
        ConditionalField(
            ShortField("context_id", 0),
            lambda pkt: pkt.packet_type == 0
        ),
        ConditionalField(
            ShortField("opnum", 0),  # 0=Connect, 1=Release, 3=Read, 4=Write
            lambda pkt: pkt.packet_type == 0
        )
    ]

    def post_build(self, pkt, pay):
        # Auto-calculate frag_length if None
        if self.frag_length is None:
            total_len = len(pkt) + len(pay)
            pkt = pkt[:8] + struct.pack("!H", total_len) + pkt[10:]
        return pkt + pay


class PNIOBlockHeader(Packet):
    """
    PROFINET IO Block Header
    Used for AR, IOCR, Alarm blocks
    """
    name = "PNIO Block Header"
    fields_desc = [
        XShortField("block_type", 0x0101),
        ShortField("block_length", None),
        ByteField("block_version_high", 1),
        ByteField("block_version_low", 0)
    ]


class ARBlockReq(Packet):
    """
    Application Relationship Block Request
    Used in Connect Request
    """
    name = "AR Block Request"
    fields_desc = [
        XShortField("block_type", 0x0101),
        ShortField("block_length", 0x0048),
        ByteField("block_version_high", 1),
        ByteField("block_version_low", 0),

        # AR UUID
        StrFixedLenField("ar_uuid", b"\x00" * 16, 16),

        # MACs
        MACField("controller_mac", "00:00:00:00:00:00"),
        MACField("device_mac", "00:00:00:00:00:00"),

        # AR Properties
        ShortField("ar_properties", 0x0060),

        # Timeouts
        ShortField("cm_initiator_activity_timeout_factor", 100),
        ShortField("cm_initiator_udp_rt_port", 0x8892),

        # Station name
        FieldLenField("station_name_length", None, length_of="station_name", fmt="!H"),
        StrLenField("station_name", "controller", length_from=lambda pkt: pkt.station_name_length),

        # Padding to align
        ConditionalField(
            StrLenField("padding", "", length_from=lambda pkt: (pkt.station_name_length % 4 and 4 - pkt.station_name_length % 4) or 0),
            lambda pkt: pkt.station_name_length % 4 != 0
        )
    ]


class IOCRBlockReq(Packet):
    """
    IO Connection Relationship Block Request
    """
    name = "IOCR Block Request"
    fields_desc = [
        XShortField("block_type", 0x0102),
        ShortField("block_length", 0x002E),
        ByteField("block_version_high", 1),
        ByteField("block_version_low", 0),

        XShortField("iocr_type", 1),  # 1=Input, 2=Output
        XShortField("iocr_reference", 1),
        XShortField("frame_id", 0x8001),

        ShortField("send_clock_factor", 32),
        ShortField("reduction_ratio", 32),
        ShortField("phase", 1),
        ShortField("sequence", 0),
        IntField("frame_send_offset", 0),

        ShortField("watchdog_factor", 3),
        ShortField("data_hold_factor", 3),
        XShortField("iocr_tag_header", 0xC000),

        MACField("iocr_multicast_mac", "01:0e:cf:00:00:00"),

        ShortField("number_of_apis", 1),
        ShortField("data_length", 40),
        ByteField("frame_id_mode", 0),
        ByteField("reserved", 0)
    ]


# ===== Bind layers =====

bind_layers(Ether, ProfinetRT, type=0x8892)
bind_layers(ProfinetRT, ProfinetDCP, frameID=0xFEFE)  # Identify Request
bind_layers(ProfinetRT, ProfinetDCP, frameID=0xFEFF)  # Identify Response
bind_layers(ProfinetRT, ProfinetCyclic)  # Cyclic data
bind_layers(ProfinetDCP, DCPNameOfStation)
bind_layers(ProfinetDCP, DCPIPParameter)
bind_layers(ProfinetDCP, DCPDeviceID)


if __name__ == '__main__':
    print("[INFO] PROFINET Custom Scapy Layers v1.0.0")
    print("[INFO] Available layers:")
    print("[INFO]   - ProfinetRT: Base real-time layer")
    print("[INFO]   - ProfinetDCP: Discovery and Configuration")
    print("[INFO]   - ProfinetCyclic: Cyclic I/O data")
    print("[INFO]   - DCERPC: RPC for AR establishment")
    print("[INFO]   - ARBlockReq: Application Relationship")
    print("[INFO]   - IOCRBlockReq: IO Connection Relationship")
    print()
    print("[INFO] Example usage:")
    print("[INFO]   from profinet_layers import *")
    print("[INFO]   pkt = Ether()/ProfinetRT()/ProfinetDCP()")
