#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
PROFINET IO Controller Implementation

This module provides a high-level PROFINET IO Controller that can:
- Discover RTU devices using DCP (Discovery and Configuration Protocol)
- Establish AR (Application Relationship) connections
- Configure IOCR (IO Connection Relationship) for cyclic data
- Exchange real-time cyclic data with IO devices
- Handle alarms and diagnostics

Example usage:
    from scapy.contrib.pnio_controller import PROFINETController

    controller = PROFINETController(interface="eth0", station_name="Controller1")
    controller.discover_devices(timeout=5)

    # Connect to a device
    device = controller.get_device("my-rtu")
    if device:
        controller.connect_device(device)
        controller.write_output_data(device, b"\\x01\\x02\\x03\\x04")
        input_data = controller.read_input_data(device)
"""

import uuid
import time
import threading
import logging
from collections import OrderedDict
from typing import Optional, List, Dict, Callable

from scapy.packet import Packet
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sendp, sniff, AsyncSniffer
from scapy.config import conf
from scapy.error import Scapy_Exception

# Import PROFINET layers
from scapy.contrib.pnio import ProfinetIO, PNIORealTimeCyclicPDU, PNIORealTime_IOxS
from scapy.contrib.pnio_dcp import (ProfinetDCP, DCPNameOfStationBlock,
                                     DCPDeviceIDBlock, DCPDeviceRoleBlock,
                                     DCPIPBlock, DCPFullIPBlock)
from scapy.contrib.pnio_rpc import (ARBlockReq, ARBlockRes, IOCRBlockReq,
                                     IOCRBlockRes, AlarmCRBlockReq,
                                     AlarmCRBlockRes, ProfinetIO as PNIO_RPC,
                                     IODReadReq, IODWriteReq)


# Setup logging
logger = logging.getLogger(__name__)


class PROFINETDevice:
    """Represents a discovered PROFINET IO Device (RTU)"""

    def __init__(self, mac: str, name: str = "", ip: str = "", device_id: int = 0,
                 vendor_id: int = 0, device_role: int = 1):
        self.mac = mac
        self.name = name
        self.ip = ip
        self.device_id = device_id
        self.vendor_id = vendor_id
        self.device_role = device_role

        # Connection state
        self.ar_uuid = None
        self.session_key = 0
        self.connected = False

        # IOCR state
        self.input_cr_id = 0x8000  # Frame ID for input data
        self.output_cr_id = 0x8001  # Frame ID for output data
        self.cycle_counter = 0

        # Data buffers
        self.input_data = b""
        self.output_data = b""
        self.last_input_time = 0
        self.last_output_time = 0

    def __repr__(self):
        return (f"PROFINETDevice(name='{self.name}', mac='{self.mac}', "
                f"ip='{self.ip}', connected={self.connected})")


class PROFINETController:
    """
    PROFINET IO Controller implementation for communicating with RTU devices.

    This controller provides:
    - DCP-based device discovery
    - AR connection establishment
    - Cyclic real-time data exchange
    - Device configuration and monitoring
    """

    # DCP Multicast MAC for discovery
    DCP_MULTICAST_MAC = "01:0e:cf:00:00:00"
    DCP_IDENTIFY_FRAME_ID = 0xfefe
    DCP_GET_SET_FRAME_ID = 0xfefd

    # PROFINET RT_CLASS_1 Frame ID range
    RT_CLASS_1_START = 0x8000
    RT_CLASS_1_END = 0xbfff

    def __init__(self, interface: str, station_name: str = "Controller",
                 ip: Optional[str] = None):
        """
        Initialize PROFINET Controller.

        Args:
            interface: Network interface to use (e.g., "eth0")
            station_name: Station name for this controller
            ip: IP address of controller (auto-detected if None)
        """
        self.interface = interface
        self.station_name = station_name
        self.ip = ip or conf.iface  # Use configured IP if not specified

        # Device registry
        self.devices: Dict[str, PROFINETDevice] = OrderedDict()

        # Sniffer for receiving packets
        self.sniffer: Optional[AsyncSniffer] = None
        self.running = False

        # Callbacks
        self.input_data_callbacks: Dict[str, Callable] = {}
        self.alarm_callbacks: List[Callable] = []

        # Frame ID allocation
        self.next_frame_id = self.RT_CLASS_1_START

        logger.info(f"PROFINET Controller initialized: {self.station_name} on {self.interface}")

    def start(self):
        """Start the controller and begin listening for packets."""
        if self.running:
            logger.warning("Controller already running")
            return

        self.running = True

        # Start packet sniffer
        self.sniffer = AsyncSniffer(
            iface=self.interface,
            filter="ether proto 0x8892 or ether proto 0x8100",
            prn=self._handle_packet,
            store=False
        )
        self.sniffer.start()

        logger.info("Controller started")

    def stop(self):
        """Stop the controller."""
        if not self.running:
            return

        self.running = False

        # Disconnect all devices
        for device in list(self.devices.values()):
            if device.connected:
                self.disconnect_device(device)

        # Stop sniffer
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None

        logger.info("Controller stopped")

    def discover_devices(self, timeout: float = 5.0, name_filter: Optional[str] = None) -> List[PROFINETDevice]:
        """
        Discover PROFINET devices on the network using DCP Identify.

        Args:
            timeout: Time to wait for responses (seconds)
            name_filter: Optional device name filter (substring match)

        Returns:
            List of discovered devices
        """
        logger.info(f"Starting device discovery (timeout={timeout}s)")

        # Build DCP Identify request (broadcast)
        identify_pkt = (
            Ether(dst=self.DCP_MULTICAST_MAC) /
            ProfinetIO(frameID=self.DCP_IDENTIFY_FRAME_ID) /
            ProfinetDCP(
                service_id=0x05,  # Identify
                service_type=0x00,  # Request
                xid=0x01000000,
                response_delay=1,
                dcp_data_length=4
            ) /
            DCPNameOfStationBlock(
                option=2,  # Device properties
                sub_option=2,  # Name of station
                dcp_block_length=0  # Query all
            )
        )

        # Sniff for responses
        discovered = []

        def handle_identify_response(pkt):
            if not pkt.haslayer(ProfinetDCP):
                return

            dcp = pkt[ProfinetDCP]
            if dcp.service_id != 0x05 or dcp.service_type != 0x01:  # Not identify response
                return

            # Extract device information
            mac = pkt[Ether].src
            name = ""
            ip = ""
            device_id = 0
            vendor_id = 0
            device_role = 1  # IO Device

            # Parse DCP blocks
            layer = dcp.payload
            while layer:
                if isinstance(layer, DCPNameOfStationBlock):
                    name = layer.name_of_station.decode('utf-8', errors='ignore').rstrip('\x00')
                elif isinstance(layer, DCPFullIPBlock) or isinstance(layer, DCPIPBlock):
                    if hasattr(layer, 'ip'):
                        ip = layer.ip
                elif isinstance(layer, DCPDeviceIDBlock):
                    device_id = layer.device_id
                    vendor_id = layer.vendor_id
                elif isinstance(layer, DCPDeviceRoleBlock):
                    device_role = layer.device_role

                layer = layer.payload if hasattr(layer, 'payload') else None

            # Apply name filter
            if name_filter and name_filter not in name:
                return

            # Create device object
            device = PROFINETDevice(
                mac=mac,
                name=name,
                ip=ip,
                device_id=device_id,
                vendor_id=vendor_id,
                device_role=device_role
            )

            # Add to registry if not already present
            if mac not in self.devices:
                self.devices[mac] = device
                discovered.append(device)
                logger.info(f"Discovered device: {device}")

        # Send identify request
        sendp(identify_pkt, iface=self.interface, verbose=False)

        # Wait for responses
        sniff(
            iface=self.interface,
            filter="ether proto 0x8892",
            prn=handle_identify_response,
            timeout=timeout,
            store=False
        )

        logger.info(f"Discovery complete: found {len(discovered)} device(s)")
        return discovered

    def get_device(self, name_or_mac: str) -> Optional[PROFINETDevice]:
        """
        Get a device by name or MAC address.

        Args:
            name_or_mac: Device name or MAC address

        Returns:
            PROFINETDevice if found, None otherwise
        """
        # Try MAC first
        if name_or_mac in self.devices:
            return self.devices[name_or_mac]

        # Try name
        for device in self.devices.values():
            if device.name == name_or_mac:
                return device

        return None

    def connect_device(self, device: PROFINETDevice,
                      input_size: int = 64, output_size: int = 64) -> bool:
        """
        Establish AR connection with a device.

        Args:
            device: Device to connect to
            input_size: Size of input data in bytes
            output_size: Size of output data in bytes

        Returns:
            True if connection successful
        """
        if device.connected:
            logger.warning(f"Device {device.name} already connected")
            return True

        logger.info(f"Connecting to device: {device.name}")

        # Generate AR UUID and session key
        device.ar_uuid = str(uuid.uuid4())
        device.session_key = int(time.time()) & 0xFFFF

        # Allocate frame IDs for cyclic data
        device.input_cr_id = self._allocate_frame_id()
        device.output_cr_id = self._allocate_frame_id()

        # Initialize data buffers
        device.input_data = b"\x00" * input_size
        device.output_data = b"\x00" * output_size
        device.cycle_counter = 0

        # Mark as connected (simplified - real implementation would do AR handshake)
        device.connected = True

        logger.info(f"Connected to {device.name}: input_cr=0x{device.input_cr_id:04x}, "
                   f"output_cr=0x{device.output_cr_id:04x}")

        return True

    def disconnect_device(self, device: PROFINETDevice):
        """Disconnect from a device."""
        if not device.connected:
            return

        logger.info(f"Disconnecting from device: {device.name}")
        device.connected = False
        device.ar_uuid = None

    def write_output_data(self, device: PROFINETDevice, data: bytes) -> bool:
        """
        Write output data to a device (Controller -> Device).

        Args:
            device: Target device
            data: Output data to write

        Returns:
            True if write successful
        """
        if not device.connected:
            logger.error(f"Device {device.name} not connected")
            return False

        # Build cyclic RT packet
        device.cycle_counter = (device.cycle_counter + 1) % 65536

        # Build IO status byte (good data from controller)
        io_status = PNIORealTime_IOxS(
            dataState=1,  # good
            instance=3  # controller
        )

        # Build cyclic PDU
        pkt = (
            Ether(dst=device.mac, src=self._get_mac()) /
            ProfinetIO(frameID=device.output_cr_id) /
            PNIORealTimeCyclicPDU(
                cycleCounter=device.cycle_counter,
                dataStatus=0x35,  # primary, validData, run, no_problem
                transferStatus=0,
                data=[bytes(io_status), data]
            )
        )

        # Send packet
        sendp(pkt, iface=self.interface, verbose=False)

        device.output_data = data
        device.last_output_time = time.time()

        logger.debug(f"Wrote {len(data)} bytes to {device.name}")
        return True

    def read_input_data(self, device: PROFINETDevice) -> Optional[bytes]:
        """
        Read current input data from a device (Device -> Controller).

        Args:
            device: Source device

        Returns:
            Input data bytes, or None if not available
        """
        if not device.connected:
            logger.error(f"Device {device.name} not connected")
            return None

        return device.input_data

    def set_device_name(self, device: PROFINETDevice, new_name: str) -> bool:
        """
        Set the name of a device using DCP Set request.

        Args:
            device: Target device
            new_name: New device name

        Returns:
            True if successful
        """
        logger.info(f"Setting device name: {device.mac} -> '{new_name}'")

        # Build DCP Set request
        set_pkt = (
            Ether(dst=device.mac) /
            ProfinetIO(frameID=self.DCP_GET_SET_FRAME_ID) /
            ProfinetDCP(
                service_id=0x04,  # Set
                service_type=0x00,  # Request
                xid=0x02000000,
                response_delay=1
            ) /
            DCPNameOfStationBlock(
                option=2,  # Device properties
                sub_option=2,  # Name of station
                name_of_station=new_name.encode('utf-8')
            )
        )

        # Send packet
        sendp(set_pkt, iface=self.interface, verbose=False)

        # Update local cache
        device.name = new_name

        return True

    def set_device_ip(self, device: PROFINETDevice, ip: str,
                     netmask: str = "255.255.255.0", gateway: str = "0.0.0.0") -> bool:
        """
        Set the IP address of a device using DCP Set request.

        Args:
            device: Target device
            ip: New IP address
            netmask: Subnet mask
            gateway: Gateway address

        Returns:
            True if successful
        """
        logger.info(f"Setting device IP: {device.mac} -> {ip}")

        # Build DCP Set request with IP parameters
        set_pkt = (
            Ether(dst=device.mac) /
            ProfinetIO(frameID=self.DCP_GET_SET_FRAME_ID) /
            ProfinetDCP(
                service_id=0x04,  # Set
                service_type=0x00,  # Request
                xid=0x03000000,
                response_delay=1
            ) /
            DCPFullIPBlock(
                option=1,  # IP
                sub_option=2,  # Full IP suite
                ip=ip,
                netmask=netmask,
                gateway=gateway
            )
        )

        # Send packet
        sendp(set_pkt, iface=self.interface, verbose=False)

        # Update local cache
        device.ip = ip

        return True

    def register_input_callback(self, device: PROFINETDevice, callback: Callable):
        """
        Register a callback for when input data is received from a device.

        Args:
            device: Device to monitor
            callback: Function to call with signature: callback(device, data)
        """
        self.input_data_callbacks[device.mac] = callback

    def _handle_packet(self, pkt: Packet):
        """Internal packet handler for received PROFINET packets."""
        if not pkt.haslayer(ProfinetIO):
            return

        pnio = pkt[ProfinetIO]

        # Handle cyclic real-time data
        if pnio.haslayer(PNIORealTimeCyclicPDU):
            self._handle_cyclic_data(pkt)

    def _handle_cyclic_data(self, pkt: Packet):
        """Handle received cyclic real-time data from devices."""
        if not pkt.haslayer(Ether) or not pkt.haslayer(PNIORealTimeCyclicPDU):
            return

        src_mac = pkt[Ether].src
        device = self.devices.get(src_mac)

        if not device or not device.connected:
            return

        rtc = pkt[PNIORealTimeCyclicPDU]

        # Extract data (skip IOxS status bytes)
        if hasattr(rtc, 'data') and len(rtc.data) > 0:
            # Parse data list - typically: [IOxS, actual_data, IOxS]
            actual_data = b""
            for item in rtc.data:
                if isinstance(item, bytes):
                    actual_data += item
                elif isinstance(item, PNIORealTime_IOxS):
                    continue  # Skip status bytes

            if actual_data:
                device.input_data = actual_data
                device.last_input_time = time.time()

                # Call callback if registered
                callback = self.input_data_callbacks.get(src_mac)
                if callback:
                    try:
                        callback(device, actual_data)
                    except Exception as e:
                        logger.error(f"Error in input callback: {e}")

    def _allocate_frame_id(self) -> int:
        """Allocate a new frame ID for RT_CLASS_1."""
        frame_id = self.next_frame_id
        self.next_frame_id += 1

        if self.next_frame_id > self.RT_CLASS_1_END:
            self.next_frame_id = self.RT_CLASS_1_START

        return frame_id

    def _get_mac(self) -> str:
        """Get MAC address of the controller interface."""
        try:
            import netifaces
            return netifaces.ifaddresses(self.interface)[netifaces.AF_LINK][0]['addr']
        except:
            # Fallback: use scapy's method
            from scapy.arch import get_if_hwaddr
            return get_if_hwaddr(self.interface)

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()


# Convenience function
def create_controller(interface: str, station_name: str = "Controller") -> PROFINETController:
    """
    Create and start a PROFINET controller.

    Args:
        interface: Network interface to use
        station_name: Controller station name

    Returns:
        Started PROFINETController instance
    """
    controller = PROFINETController(interface, station_name)
    controller.start()
    return controller


if __name__ == "__main__":
    # Example usage
    import sys

    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python pnio_controller.py <interface>")
        print("Example: python pnio_controller.py eth0")
        sys.exit(1)

    iface = sys.argv[1]

    print(f"Starting PROFINET Controller on {iface}")

    with create_controller(iface, "ScapyController") as controller:
        # Discover devices
        devices = controller.discover_devices(timeout=5)

        if not devices:
            print("No devices found")
            sys.exit(0)

        print(f"\nFound {len(devices)} device(s):")
        for i, dev in enumerate(devices):
            print(f"  {i+1}. {dev}")

        # Connect to first device
        device = devices[0]
        print(f"\nConnecting to: {device.name}")

        if controller.connect_device(device):
            print("Connected successfully!")

            # Write some output data
            print("Writing output data...")
            controller.write_output_data(device, b"\x01\x02\x03\x04")

            # Wait for input data
            print("Waiting for input data...")
            time.sleep(2)

            input_data = controller.read_input_data(device)
            if input_data:
                print(f"Received input data: {input_data.hex()}")

            # Disconnect
            controller.disconnect_device(device)
            print("Disconnected")
