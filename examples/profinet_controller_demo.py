#!/usr/bin/env python
"""
PROFINET Controller Demo

This example demonstrates how to use the PROFINET Controller to:
1. Discover RTU devices on the network
2. Connect to an RTU
3. Exchange cyclic real-time data
4. Configure device parameters

Requirements:
    - Root/admin privileges (for raw socket access)
    - Network interface connected to PROFINET network
    - One or more PROFINET IO devices (RTUs) on the network

Usage:
    sudo python profinet_controller_demo.py <interface>
    sudo python profinet_controller_demo.py eth0
"""

import sys
import time
import signal
import logging
from pathlib import Path

# Add scapy to path if running from examples directory
sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.contrib.pnio_controller import PROFINETController, PROFINETDevice


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class RTUController:
    """
    Example RTU Controller application using PROFINET.

    This demonstrates a complete workflow for controlling industrial RTUs
    via PROFINET protocol.
    """

    def __init__(self, interface: str):
        self.interface = interface
        self.controller = None
        self.running = False
        self.connected_devices = []

    def start(self):
        """Initialize and start the controller."""
        logger.info(f"Starting PROFINET Controller on interface: {self.interface}")

        # Create controller
        self.controller = PROFINETController(
            interface=self.interface,
            station_name="ScapyController"
        )

        # Start controller
        self.controller.start()
        self.running = True

        logger.info("Controller started successfully")

    def stop(self):
        """Stop the controller and cleanup."""
        if not self.running:
            return

        logger.info("Stopping controller...")

        # Disconnect all devices
        for device in self.connected_devices:
            self.controller.disconnect_device(device)

        # Stop controller
        if self.controller:
            self.controller.stop()

        self.running = False
        logger.info("Controller stopped")

    def discover_devices(self, timeout: float = 5.0, device_filter: str = None):
        """
        Discover PROFINET devices on the network.

        Args:
            timeout: Discovery timeout in seconds
            device_filter: Optional name filter (substring match)
        """
        logger.info(f"Discovering devices (timeout={timeout}s)...")

        devices = self.controller.discover_devices(
            timeout=timeout,
            name_filter=device_filter
        )

        if not devices:
            logger.warning("No devices discovered")
            return []

        logger.info(f"Discovered {len(devices)} device(s):")
        for i, device in enumerate(devices, 1):
            logger.info(f"  [{i}] Name: {device.name}")
            logger.info(f"      MAC: {device.mac}")
            logger.info(f"      IP: {device.ip or 'Not set'}")
            logger.info(f"      Device ID: 0x{device.device_id:04x}")
            logger.info(f"      Vendor ID: 0x{device.vendor_id:04x}")

        return devices

    def connect_to_device(self, device: PROFINETDevice,
                         input_size: int = 64, output_size: int = 64):
        """
        Connect to a device and establish cyclic data exchange.

        Args:
            device: Device to connect to
            input_size: Expected input data size
            output_size: Output data size
        """
        logger.info(f"Connecting to device: {device.name} ({device.mac})")

        success = self.controller.connect_device(
            device,
            input_size=input_size,
            output_size=output_size
        )

        if success:
            self.connected_devices.append(device)
            logger.info(f"Successfully connected to {device.name}")

            # Register callback for input data
            self.controller.register_input_callback(
                device,
                self._handle_input_data
            )
        else:
            logger.error(f"Failed to connect to {device.name}")

        return success

    def write_outputs(self, device: PROFINETDevice, data: bytes):
        """
        Write output data to an RTU.

        Args:
            device: Target device
            data: Output data bytes
        """
        logger.info(f"Writing {len(data)} bytes to {device.name}: {data.hex()}")

        success = self.controller.write_output_data(device, data)

        if success:
            logger.info("Output data written successfully")
        else:
            logger.error("Failed to write output data")

        return success

    def read_inputs(self, device: PROFINETDevice) -> bytes:
        """
        Read current input data from an RTU.

        Args:
            device: Source device

        Returns:
            Input data bytes
        """
        data = self.controller.read_input_data(device)

        if data:
            logger.info(f"Read {len(data)} bytes from {device.name}: {data.hex()}")
        else:
            logger.warning(f"No input data available from {device.name}")

        return data

    def configure_device(self, device: PROFINETDevice,
                        name: str = None, ip: str = None):
        """
        Configure device parameters.

        Args:
            device: Target device
            name: New device name (optional)
            ip: New IP address (optional)
        """
        if name:
            logger.info(f"Setting device name to: {name}")
            self.controller.set_device_name(device, name)
            time.sleep(0.5)

        if ip:
            logger.info(f"Setting device IP to: {ip}")
            self.controller.set_device_ip(device, ip)
            time.sleep(0.5)

    def _handle_input_data(self, device: PROFINETDevice, data: bytes):
        """
        Callback for received input data from devices.

        Args:
            device: Source device
            data: Received data
        """
        logger.info(f"[CALLBACK] Received input from {device.name}: {data.hex()}")

        # Example: Process input data and update outputs based on logic
        # This is where you would implement your control logic

    def run_cyclic_io_demo(self, device: PROFINETDevice, duration: int = 10):
        """
        Demonstrate cyclic I/O exchange with a device.

        Args:
            device: Target device
            duration: Demo duration in seconds
        """
        logger.info(f"Starting cyclic I/O demo with {device.name} for {duration}s")

        start_time = time.time()
        counter = 0

        try:
            while time.time() - start_time < duration:
                # Prepare output data (example: incrementing counter)
                output_data = bytes([
                    counter & 0xFF,
                    (counter >> 8) & 0xFF,
                    0x00,
                    0xFF
                ])

                # Write outputs
                self.write_outputs(device, output_data)

                # Wait for cycle time (e.g., 10ms for typical PROFINET cycle)
                time.sleep(0.01)

                # Read inputs
                input_data = self.read_inputs(device)

                counter += 1

                # Log every 100 cycles
                if counter % 100 == 0:
                    logger.info(f"Cycle {counter}: Last input = {input_data.hex() if input_data else 'None'}")

        except KeyboardInterrupt:
            logger.info("Demo interrupted by user")

        logger.info(f"Cyclic I/O demo complete. Total cycles: {counter}")


def main():
    """Main demo application."""

    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    interface = sys.argv[1]

    # Create RTU controller application
    app = RTUController(interface)

    # Setup signal handler for clean shutdown
    def signal_handler(sig, frame):
        logger.info("Shutdown signal received")
        app.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Start controller
        app.start()

        # Discover devices
        print("\n" + "="*60)
        print("STEP 1: Device Discovery")
        print("="*60)
        devices = app.discover_devices(timeout=5.0)

        if not devices:
            logger.error("No devices found. Exiting.")
            return

        # Select first device for demo
        device = devices[0]

        # Optional: Configure device
        print("\n" + "="*60)
        print("STEP 2: Device Configuration (Optional)")
        print("="*60)

        configure = input(f"Configure device {device.name}? (y/n): ").lower().strip()
        if configure == 'y':
            new_name = input("Enter new device name (or press Enter to skip): ").strip()
            new_ip = input("Enter new IP address (or press Enter to skip): ").strip()

            if new_name or new_ip:
                app.configure_device(
                    device,
                    name=new_name if new_name else None,
                    ip=new_ip if new_ip else None
                )
                logger.info("Device configured. Rediscovering...")
                time.sleep(2)
                devices = app.discover_devices(timeout=2.0)
                device = devices[0]  # Get updated device info

        # Connect to device
        print("\n" + "="*60)
        print("STEP 3: Connect to Device")
        print("="*60)

        if not app.connect_to_device(device, input_size=64, output_size=64):
            logger.error("Failed to connect. Exiting.")
            return

        # Run cyclic I/O demo
        print("\n" + "="*60)
        print("STEP 4: Cyclic I/O Exchange")
        print("="*60)

        duration = 10
        print(f"Running cyclic I/O for {duration} seconds...")
        print("Press Ctrl+C to stop early")

        app.run_cyclic_io_demo(device, duration=duration)

        # Demo complete
        print("\n" + "="*60)
        print("Demo Complete!")
        print("="*60)

    except Exception as e:
        logger.error(f"Error during demo: {e}", exc_info=True)

    finally:
        # Cleanup
        app.stop()


if __name__ == "__main__":
    main()
