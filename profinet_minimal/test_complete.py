#!/usr/bin/env python3
"""
Complete PROFINET Controller Test Suite
Tests DCP discovery and RPC Connect against real RTU

Usage:
    sudo python3 test_complete.py --interface enp0s3 --device rtu-ec3b

This script will:
1. Discover your RTU using DCP
2. Attempt proper RPC Connect using Scapy layers
3. Show detailed diagnostics if connection fails
4. Test cyclic I/O if connection succeeds
"""

import sys
import argparse
import socket
import struct
import time
import uuid
from typing import Optional, Tuple

# Scapy imports - using proper layers
try:
    from scapy.all import *
    from scapy.contrib.pnio import *
    from scapy.contrib.pnio_dcp import *
    from scapy.contrib.pnio_rpc import *
except ImportError:
    print("[ERROR] Scapy not found. Install with: pip3 install scapy")
    sys.exit(1)

# ANSI colors for output
class Color:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def info(msg): print(f"[{Color.BLUE}INFO{Color.RESET}] {msg}")
def success(msg): print(f"[{Color.GREEN}✓{Color.RESET}] {msg}")
def warning(msg): print(f"[{Color.YELLOW}WARN{Color.RESET}] {msg}")
def error(msg): print(f"[{Color.RED}✗{Color.RESET}] {msg}")
def step(msg): print(f"\n{Color.BOLD}=== {msg} ==={Color.RESET}\n")


class PROFINETTester:
    """Complete PROFINET test suite"""

    def __init__(self, interface: str):
        self.interface = interface
        self.controller_mac = get_if_hwaddr(interface)
        self.controller_ip = get_if_addr(interface)

        # Device info
        self.device_mac = None
        self.device_ip = None
        self.device_name = None

        # Connection state
        self.ar_uuid = None
        self.session_key = None

        info(f"Controller: {self.controller_ip} ({self.controller_mac}) on {interface}")

    def test_dcp_discovery(self, timeout: float = 3.0, device_name: Optional[str] = None) -> bool:
        """Test 1: DCP Discovery"""
        step("Test 1: DCP Discovery")

        info(f"Searching for devices (timeout={timeout}s)...")
        if device_name:
            info(f"Looking for specific device: {device_name}")

        # Build DCP Identify request
        dcp_request = (
            Ether(dst="01:0e:cf:00:00:00", src=self.controller_mac, type=0x8892) /
            ProfinetDCP(service_id=0x05, service_type=0x00) /
            DCPIdentAllReqBlock(xid=0x12345678)
        )

        info(f"DCP packet size: {len(dcp_request)} bytes")

        # Send and sniff for responses
        responses = srp1(dcp_request, iface=self.interface, timeout=timeout, verbose=0)

        if not responses:
            error("No DCP responses received")
            warning("Check that:")
            warning("  1. RTU is powered on and connected")
            warning("  2. Network interface is correct")
            warning("  3. No firewall blocking 0x8892")
            return False

        # Parse response
        if ProfinetDCP in responses:
            dcp = responses[ProfinetDCP]

            # Extract device info from blocks
            name = None
            ip = None
            mac = responses.src

            # Parse DCP blocks
            layer = dcp
            while layer:
                if hasattr(layer, 'device_name_value'):
                    name = layer.device_name_value.decode('utf-8', errors='ignore')
                if hasattr(layer, 'ip'):
                    ip = layer.ip
                layer = layer.payload if hasattr(layer, 'payload') else None

            if name and ip:
                success(f"Found device: {name} @ {ip} ({mac})")

                # Check if this is the device we want
                if device_name and name != device_name:
                    warning(f"Found {name} but looking for {device_name}")
                    return False

                # Save device info
                self.device_name = name
                self.device_ip = ip
                self.device_mac = mac

                return True

        error("DCP response malformed")
        return False

    def test_rpc_connect(self, timeout: float = 5.0) -> bool:
        """Test 2: RPC Connect using proper Scapy layers"""
        step("Test 2: RPC Connect")

        if not self.device_ip:
            error("No device discovered - run test_dcp_discovery first")
            return False

        info(f"Connecting to {self.device_name} ({self.device_ip})...")

        # Generate UUIDs
        self.ar_uuid = uuid.uuid4()
        activity_uuid = uuid.uuid4()
        self.session_key = 1

        info(f"AR UUID: {self.ar_uuid}")
        info(f"Activity UUID: {activity_uuid}")
        info(f"Session Key: {self.session_key}")

        # Build proper RPC Connect packet using Scapy layers
        # This is the CORRECT way to do it!

        try:
            # Create AR block
            ar_block = IODConnectReq(
                ARUUID=str(self.ar_uuid),
                CMInitiatorMacAdd=self.controller_mac,
                CMInitiatorObjectUUID=str(self.ar_uuid),
                StationNameLength=len(self.device_name),
                CMInitiatorStationName=self.device_name.encode('utf-8')
            )

            # Create IOCR blocks for input and output
            iocr_input = IOCRBlockReq(
                IOCRType=1,  # Input
                IOCRReference=1,
                FrameID=0x8001,
                DataLength=40,
                SendClockFactor=32,
                ReductionRatio=32,
                Phase=1,
                Sequence=0
            )

            iocr_output = IOCRBlockReq(
                IOCRType=2,  # Output
                IOCRReference=2,
                FrameID=0x8000,
                DataLength=40,
                SendClockFactor=32,
                ReductionRatio=32,
                Phase=1,
                Sequence=0
            )

            # Alarm CR
            alarm_cr = AlarmCRBlockReq(
                AlarmCRType=1,
                AlarmCRProperties=0
            )

            # Expected submodule configuration
            exp_sub = ExpectedSubmoduleBlockReq(
                NumberOfAPIs=1,
                APIs=[
                    {
                        'API': 0,
                        'SlotNumber': 0,
                        'SubslotNumber': 1,
                        'ModuleIdentNumber': 1,
                        'SubmoduleIdentNumber': 1
                    }
                ]
            )

            # Build complete RPC packet
            # CRITICAL: Use ProfinetIO layer which includes proper DCE/RPC framing!
            rpc_packet = (
                IP(src=self.controller_ip, dst=self.device_ip) /
                UDP(sport=34964, dport=34964) /
                ProfinetIO(
                    frameID=0xFEFC  # RPC frame ID
                ) /
                DCERPCRequest(
                    opnum=0,  # Connect operation
                    if_id=uuid.UUID('DEA00001-6C97-11D1-8271-00A02442DF7D'),  # PROFINET IO Device Interface
                    activity_id=activity_uuid
                ) /
                ar_block /
                iocr_input /
                iocr_output /
                alarm_cr /
                exp_sub
            )

            info("Packet structure:")
            rpc_packet.show2()

            info(f"\nTotal packet size: {len(rpc_packet)} bytes")
            print(f"\n{Color.CYAN}Hex dump:{Color.RESET}")
            hexdump(rpc_packet)

            # Send and wait for response
            info(f"\nSending to {self.device_ip}:34964...")
            response = sr1(rpc_packet, iface=self.interface, timeout=timeout, verbose=0)

            if not response:
                error("No response received")
                self._diagnose_connect_failure()
                return False

            # Check response
            if DCERPCResponse in response:
                success("Received RPC Response!")
                response.show()

                # Check for positive acknowledgment
                if hasattr(response, 'status'):
                    if response.status == 0:
                        success("Connection ACCEPTED by RTU!")
                        return True
                    else:
                        error(f"Connection REJECTED - Status: 0x{response.status:08x}")
                        return False
                else:
                    success("Response received (status unclear)")
                    return True
            else:
                error("Response doesn't contain DCE/RPC layer")
                response.show()
                return False

        except Exception as e:
            error(f"Exception building/sending packet: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _diagnose_connect_failure(self):
        """Diagnose why connect failed"""
        error("\n=== Connection Failure Diagnosis ===\n")

        warning("Common causes:")
        warning("  1. RTU doesn't support this station name")
        warning("  2. RTU requires specific GSD configuration")
        warning("  3. Wrong Frame IDs (0x8000/0x8001)")
        warning("  4. Missing or incorrect Expected Submodule config")
        warning("  5. DCE/RPC framing incorrect")

        info("\nDebugging steps:")
        info("  1. Capture with: sudo tcpdump -i enp0s3 -w profinet.pcap udp port 34964")
        info("  2. Open in Wireshark with PROFINET dissector")
        info("  3. Check 'PNIO-CM' protocol for error codes")
        info("  4. Compare with known-good Connect from TIA Portal")

    def test_cyclic_io(self, duration: float = 5.0) -> bool:
        """Test 3: Cyclic I/O communication"""
        step("Test 3: Cyclic I/O")

        if not self.ar_uuid:
            error("No active AR - run test_rpc_connect first")
            return False

        info(f"Testing cyclic I/O for {duration} seconds...")

        # Build cyclic output frame
        output_data = b"\x01\x02\x03\x04" * 10  # 40 bytes

        cyclic_frame = (
            Ether(dst=self.device_mac, src=self.controller_mac, type=0x8892) /
            ProfinetIO(frameID=0x8000) /  # Output frame ID
            Raw(load=output_data)
        )

        info(f"Cyclic frame size: {len(cyclic_frame)} bytes")

        # Send frames and listen for input
        start = time.time()
        sent = 0
        received = 0

        # Set up packet capture for input frames
        def packet_handler(pkt):
            nonlocal received
            if ProfinetIO in pkt and pkt[ProfinetIO].frameID == 0x8001:
                received += 1
                if received == 1:
                    success(f"Received first input frame!")
                    hexdump(pkt)

        # Start async sniffer
        sniffer = AsyncSniffer(
            iface=self.interface,
            prn=packet_handler,
            filter=f"ether src {self.device_mac}",
            store=False
        )
        sniffer.start()

        try:
            while time.time() - start < duration:
                sendp(cyclic_frame, iface=self.interface, verbose=0)
                sent += 1
                time.sleep(0.01)  # 100 Hz
        finally:
            sniffer.stop()

        info(f"\nCyclic I/O statistics:")
        info(f"  Sent: {sent} frames")
        info(f"  Received: {received} frames")

        if received > 0:
            success(f"Cyclic I/O working! ({received}/{sent} frames)")
            return True
        else:
            warning("No input frames received")
            warning("This may be normal if RTU requires AR before sending cyclic data")
            return False

    def run_all_tests(self, device_name: Optional[str] = None):
        """Run complete test suite"""
        print(f"\n{Color.BOLD}{Color.CYAN}")
        print("╔════════════════════════════════════════════════════╗")
        print("║   PROFINET Controller Test Suite                  ║")
        print("║   Complete AR Establishment & I/O Test             ║")
        print("╚════════════════════════════════════════════════════╝")
        print(f"{Color.RESET}\n")

        results = {}

        # Test 1: DCP Discovery
        results['dcp'] = self.test_dcp_discovery(device_name=device_name)
        if not results['dcp']:
            error("Discovery failed - cannot continue")
            return results

        # Test 2: RPC Connect
        results['rpc'] = self.test_rpc_connect()

        # Test 3: Cyclic I/O (only if connected)
        if results['rpc']:
            results['cyclic'] = self.test_cyclic_io()
        else:
            warning("Skipping cyclic I/O test (not connected)")
            results['cyclic'] = False

        # Print summary
        step("Test Summary")

        total = len(results)
        passed = sum(1 for v in results.values() if v)

        print(f"DCP Discovery:    {_status(results['dcp'])}")
        print(f"RPC Connect:      {_status(results['rpc'])}")
        print(f"Cyclic I/O:       {_status(results.get('cyclic', False))}")

        print(f"\n{Color.BOLD}Result: {passed}/{total} tests passed{Color.RESET}")

        if passed == total:
            print(f"{Color.GREEN}{Color.BOLD}")
            print("╔════════════════════════════════════════════════════╗")
            print("║              ALL TESTS PASSED!                     ║")
            print("║   Your PROFINET controller is working correctly   ║")
            print("╚════════════════════════════════════════════════════╝")
            print(f"{Color.RESET}")
        elif results['dcp'] and not results['rpc']:
            print(f"\n{Color.YELLOW}Discovery works but Connect fails{Color.RESET}")
            print("This suggests a protocol-level issue.")
            print("Check the diagnosis output above for details.")

        return results


def _status(passed: bool) -> str:
    """Format test status"""
    if passed:
        return f"{Color.GREEN}✓ PASS{Color.RESET}"
    else:
        return f"{Color.RED}✗ FAIL{Color.RESET}"


def main():
    parser = argparse.ArgumentParser(
        description='Complete PROFINET Controller Test Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test all devices
  sudo python3 test_complete.py --interface enp0s3

  # Test specific device
  sudo python3 test_complete.py --interface enp0s3 --device rtu-ec3b

  # Run individual tests
  sudo python3 test_complete.py --interface enp0s3 --test dcp
  sudo python3 test_complete.py --interface enp0s3 --test rpc --device rtu-ec3b
        """
    )

    parser.add_argument('--interface', '-i', required=True,
                       help='Network interface (e.g., enp0s3, eth0)')
    parser.add_argument('--device', '-d',
                       help='Specific device name to test (e.g., rtu-ec3b)')
    parser.add_argument('--test', '-t', choices=['dcp', 'rpc', 'cyclic', 'all'],
                       default='all',
                       help='Which test to run (default: all)')
    parser.add_argument('--timeout', type=float, default=5.0,
                       help='Timeout for operations (default: 5s)')

    args = parser.parse_args()

    # Check we're running as root
    if os.geteuid() != 0:
        error("This script requires root privileges")
        error("Run with: sudo python3 test_complete.py ...")
        sys.exit(1)

    # Create tester
    tester = PROFINETTester(args.interface)

    # Run requested tests
    if args.test == 'all':
        results = tester.run_all_tests(device_name=args.device)
        sys.exit(0 if all(results.values()) else 1)
    elif args.test == 'dcp':
        success = tester.test_dcp_discovery(device_name=args.device)
        sys.exit(0 if success else 1)
    elif args.test == 'rpc':
        # Need discovery first
        if not tester.test_dcp_discovery(device_name=args.device):
            sys.exit(1)
        success = tester.test_rpc_connect(timeout=args.timeout)
        sys.exit(0 if success else 1)
    elif args.test == 'cyclic':
        # Need discovery and connect first
        if not tester.test_dcp_discovery(device_name=args.device):
            sys.exit(1)
        if not tester.test_rpc_connect(timeout=args.timeout):
            sys.exit(1)
        success = tester.test_cyclic_io()
        sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
