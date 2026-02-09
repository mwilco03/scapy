# PROFINET IO Controller for Scapy

A high-level PROFINET IO Controller implementation for Scapy that enables communication with industrial RTUs (Remote Terminal Units) and other PROFINET IO devices.

## Overview

This module provides a complete PROFINET IO Controller that can:

- **Discover devices** using DCP (Discovery and Configuration Protocol)
- **Configure devices** (set IP address, device name, etc.)
- **Establish connections** (AR - Application Relationship)
- **Exchange real-time data** with IO devices cyclically
- **Handle alarms** and diagnostics
- **Monitor device status** and health

## Features

### Device Discovery
- DCP-based device discovery with broadcast/multicast
- Filter devices by name
- Extract device information (MAC, IP, device ID, vendor ID)

### Device Configuration
- Set device name via DCP Set requests
- Configure IP address, subnet mask, gateway
- Reset devices to factory defaults

### Real-Time Communication
- Cyclic data exchange (RT_CLASS_1 real-time)
- Configurable input/output data sizes
- Support for cycle times down to 1ms
- Automatic cycle counter management

### Connection Management
- AR (Application Relationship) establishment
- IOCR (IO Connection Relationship) configuration
- Frame ID allocation and management
- Multiple simultaneous device connections

## Installation

The PROFINET Controller module is part of Scapy's contrib modules:

```python
from scapy.contrib.pnio_controller import PROFINETController
```

## Requirements

- **Scapy** 2.5.0 or later
- **Root/Administrator privileges** for raw socket access
- **Network interface** connected to PROFINET network
- **Python 3.7+**

Optional:
- `netifaces` - for network interface information

## Quick Start

### Basic Example

```python
from scapy.contrib.pnio_controller import PROFINETController

# Create controller
controller = PROFINETController(
    interface="eth0",
    station_name="MyController"
)

# Start controller
controller.start()

# Discover devices
devices = controller.discover_devices(timeout=5.0)
print(f"Found {len(devices)} devices")

# Connect to first device
if devices:
    device = devices[0]
    controller.connect_device(device)

    # Write output data
    controller.write_output_data(device, b"\x01\x02\x03\x04")

    # Read input data
    input_data = controller.read_input_data(device)
    print(f"Input: {input_data.hex()}")

    # Disconnect
    controller.disconnect_device(device)

# Stop controller
controller.stop()
```

### Using Context Manager

```python
from scapy.contrib.pnio_controller import PROFINETController

with PROFINETController("eth0", "Controller") as controller:
    devices = controller.discover_devices(timeout=5.0)

    for device in devices:
        print(f"Found: {device.name} at {device.mac}")

    # Controller automatically stopped when exiting context
```

## API Reference

### PROFINETController

#### Constructor

```python
PROFINETController(interface, station_name="Controller", ip=None)
```

**Parameters:**
- `interface` (str): Network interface to use (e.g., "eth0")
- `station_name` (str): Station name for this controller
- `ip` (str, optional): IP address of controller (auto-detected if None)

#### Methods

##### start()
```python
controller.start()
```
Start the controller and begin listening for packets.

##### stop()
```python
controller.stop()
```
Stop the controller and disconnect all devices.

##### discover_devices()
```python
devices = controller.discover_devices(timeout=5.0, name_filter=None)
```
Discover PROFINET devices on the network.

**Parameters:**
- `timeout` (float): Time to wait for responses in seconds
- `name_filter` (str, optional): Filter by device name (substring match)

**Returns:** List of `PROFINETDevice` objects

##### get_device()
```python
device = controller.get_device(name_or_mac)
```
Get a device by name or MAC address.

**Parameters:**
- `name_or_mac` (str): Device name or MAC address

**Returns:** `PROFINETDevice` or None

##### connect_device()
```python
success = controller.connect_device(device, input_size=64, output_size=64)
```
Establish AR connection with a device.

**Parameters:**
- `device` (PROFINETDevice): Device to connect to
- `input_size` (int): Size of input data in bytes
- `output_size` (int): Size of output data in bytes

**Returns:** True if successful

##### disconnect_device()
```python
controller.disconnect_device(device)
```
Disconnect from a device.

##### write_output_data()
```python
success = controller.write_output_data(device, data)
```
Write output data to a device (Controller → Device).

**Parameters:**
- `device` (PROFINETDevice): Target device
- `data` (bytes): Output data to write

**Returns:** True if successful

##### read_input_data()
```python
data = controller.read_input_data(device)
```
Read current input data from a device (Device → Controller).

**Parameters:**
- `device` (PROFINETDevice): Source device

**Returns:** Input data bytes or None

##### set_device_name()
```python
success = controller.set_device_name(device, new_name)
```
Set the name of a device using DCP.

**Parameters:**
- `device` (PROFINETDevice): Target device
- `new_name` (str): New device name

**Returns:** True if successful

##### set_device_ip()
```python
success = controller.set_device_ip(device, ip, netmask="255.255.255.0", gateway="0.0.0.0")
```
Set the IP address of a device using DCP.

**Parameters:**
- `device` (PROFINETDevice): Target device
- `ip` (str): New IP address
- `netmask` (str): Subnet mask
- `gateway` (str): Gateway address

**Returns:** True if successful

##### register_input_callback()
```python
controller.register_input_callback(device, callback)
```
Register a callback for when input data is received.

**Parameters:**
- `device` (PROFINETDevice): Device to monitor
- `callback` (Callable): Function with signature `callback(device, data)`

### PROFINETDevice

Represents a discovered PROFINET IO Device.

#### Attributes

- `mac` (str): MAC address
- `name` (str): Device name
- `ip` (str): IP address
- `device_id` (int): Device ID
- `vendor_id` (int): Vendor ID
- `device_role` (int): Device role (0=Supervisor, 1=Device, 2=Controller)
- `connected` (bool): Connection status
- `ar_uuid` (str): AR UUID when connected
- `input_data` (bytes): Last received input data
- `output_data` (bytes): Last sent output data

## Examples

### Example 1: Device Discovery

```python
from scapy.contrib.pnio_controller import PROFINETController

controller = PROFINETController("eth0", "Discoverer")
controller.start()

# Discover all devices
all_devices = controller.discover_devices(timeout=5.0)

# Discover specific device by name
rtu_devices = controller.discover_devices(timeout=3.0, name_filter="rtu")

for device in all_devices:
    print(f"Device: {device.name}")
    print(f"  MAC: {device.mac}")
    print(f"  IP: {device.ip}")
    print(f"  Device ID: 0x{device.device_id:04x}")
    print(f"  Vendor ID: 0x{device.vendor_id:04x}")

controller.stop()
```

### Example 2: Configure Device

```python
from scapy.contrib.pnio_controller import PROFINETController

controller = PROFINETController("eth0")
controller.start()

devices = controller.discover_devices(timeout=5.0)
device = devices[0]

# Set device name
controller.set_device_name(device, "MyRTU-001")

# Set IP address
controller.set_device_ip(
    device,
    ip="192.168.1.100",
    netmask="255.255.255.0",
    gateway="192.168.1.1"
)

controller.stop()
```

### Example 3: Cyclic I/O Exchange

```python
from scapy.contrib.pnio_controller import PROFINETController
import time

controller = PROFINETController("eth0", "IOController")
controller.start()

# Find and connect to device
devices = controller.discover_devices(timeout=5.0)
device = controller.get_device("my-rtu")

if device:
    controller.connect_device(device, input_size=32, output_size=32)

    # Cyclic I/O loop
    for i in range(100):
        # Prepare output data
        output = bytes([i & 0xFF, (i >> 8) & 0xFF, 0x00, 0xFF])

        # Write outputs
        controller.write_output_data(device, output)

        # Wait for cycle time (10ms)
        time.sleep(0.01)

        # Read inputs
        input_data = controller.read_input_data(device)
        if input_data:
            print(f"Cycle {i}: Input = {input_data.hex()}")

    controller.disconnect_device(device)

controller.stop()
```

### Example 4: Asynchronous Input Handling

```python
from scapy.contrib.pnio_controller import PROFINETController
import time

def handle_input(device, data):
    """Callback for received input data"""
    print(f"[{device.name}] Received: {data.hex()}")

    # Process data based on application logic
    if data[0] & 0x80:  # Check alarm bit
        print(f"  ALARM from {device.name}!")

controller = PROFINETController("eth0")
controller.start()

devices = controller.discover_devices(timeout=5.0)

for device in devices:
    controller.connect_device(device)
    controller.register_input_callback(device, handle_input)

# Run for 60 seconds
print("Monitoring devices for 60 seconds...")
time.sleep(60)

controller.stop()
```

### Example 5: Multiple Devices

```python
from scapy.contrib.pnio_controller import PROFINETController
import time

controller = PROFINETController("eth0", "MultiController")
controller.start()

# Discover all devices
devices = controller.discover_devices(timeout=5.0)
print(f"Found {len(devices)} devices")

# Connect to all devices
for device in devices:
    print(f"Connecting to {device.name}...")
    controller.connect_device(device)

# Control loop
for cycle in range(100):
    # Write outputs to all devices
    for i, device in enumerate(devices):
        output_data = bytes([cycle & 0xFF, i, 0x00, 0xFF])
        controller.write_output_data(device, output_data)

    time.sleep(0.01)  # 10ms cycle

    # Read inputs from all devices
    for device in devices:
        input_data = controller.read_input_data(device)
        if input_data:
            print(f"[{device.name}] Input: {input_data.hex()}")

# Disconnect all
for device in devices:
    controller.disconnect_device(device)

controller.stop()
```

## Demo Scripts

### Quick Start Script

Run the quick start example:

```bash
sudo python examples/profinet_quickstart.py eth0
```

Or with device filter:

```bash
sudo python examples/profinet_quickstart.py eth0 my-rtu
```

### Full Demo Script

Run the comprehensive demo:

```bash
sudo python examples/profinet_controller_demo.py eth0
```

The demo will:
1. Discover all devices on the network
2. Allow you to configure a device (optional)
3. Connect to a device
4. Run cyclic I/O exchange
5. Display results

## Architecture

### Communication Stack

```
┌─────────────────────────────────────┐
│   Application (Your Code)           │
├─────────────────────────────────────┤
│   PROFINETController                │
│   - Device Management                │
│   - Connection Control               │
│   - I/O Data Exchange                │
├─────────────────────────────────────┤
│   PROFINET Protocol Layers           │
│   - DCP (Discovery)                  │
│   - RPC (Configuration)              │
│   - RT (Real-Time Cyclic)            │
├─────────────────────────────────────┤
│   Scapy Core                         │
│   - Packet Building/Parsing          │
│   - Send/Receive                     │
└─────────────────────────────────────┘
```

### Real-Time Classes

The controller uses **RT_CLASS_1** (0x8000-0xBFFF) for cyclic data exchange:

- **Frame IDs**: Automatically allocated from RT_CLASS_1 range
- **Cycle Time**: Configurable (default 10ms, can go down to 1ms)
- **Data Size**: Configurable input/output sizes
- **Priority**: Real-time Ethernet priority

## Network Setup

### Requirements

1. **Network Interface**: Connected to PROFINET network
2. **Permissions**: Root/administrator for raw sockets
3. **Network Configuration**:
   - Interface should be UP
   - No IP address required for RT communication
   - IP address needed for configuration via DCP

### Example Network Setup

```bash
# Bring up interface
sudo ip link set eth0 up

# (Optional) Set IP for configuration
sudo ip addr add 192.168.1.10/24 dev eth0

# Disable firewalls that might block PROFINET
sudo iptables -A INPUT -p all -i eth0 -j ACCEPT
sudo iptables -A OUTPUT -p all -o eth0 -j ACCEPT
```

## Troubleshooting

### No Devices Found

**Problem:** `discover_devices()` returns empty list

**Solutions:**
- Check network cable is connected
- Verify interface is UP: `ip link show eth0`
- Check devices are powered on
- Try increasing timeout: `discover_devices(timeout=10)`
- Verify devices are on same network segment
- Check for VLAN configuration

### Permission Denied

**Problem:** "Operation not permitted" error

**Solution:** Run with root/administrator privileges:
```bash
sudo python your_script.py
```

### No Input Data Received

**Problem:** `read_input_data()` returns empty/old data

**Solutions:**
- Verify device is configured to send cyclic data
- Check IOCR configuration matches device expectations
- Verify cycle time is appropriate
- Check device is in RUN mode
- Use `register_input_callback()` for asynchronous reception

### Connection Failures

**Problem:** `connect_device()` returns False

**Solutions:**
- Ensure device was discovered first
- Check device supports the requested I/O sizes
- Verify AR parameters are compatible
- Check for existing connections to the device

## Protocol Details

### DCP (Discovery and Configuration Protocol)

- **Frame ID**: 0xFEFE (Identify), 0xFEFD (Get/Set)
- **Multicast MAC**: 01:0e:cf:00:00:00
- **Services**: Identify, Get, Set, Hello

### AR (Application Relationship)

- **UUID**: Generated for each connection
- **Session Key**: Time-based unique identifier
- **Lifecycle**: Connect → Configure → Run → Disconnect

### RT (Real-Time Cyclic)

- **Frame IDs**: 0x8000-0xBFFF (RT_CLASS_1)
- **Cycle Counter**: 16-bit rolling counter
- **Data Status**: Flags for validity, redundancy, state
- **IOxS**: I/O status bytes (IOCS/IOPS)

## Performance Considerations

### Cycle Time

- **Minimum**: 1ms (requires optimized system)
- **Typical**: 10ms (most industrial applications)
- **Maximum**: 512ms

### Data Size

- **Input/Output**: Up to 1440 bytes per frame
- **Recommended**: 64-256 bytes for best performance

### Number of Devices

- **Practical Limit**: 10-50 devices per controller
- **Depends On**: Cycle time, data size, CPU performance

## Known Limitations

1. **Simplified AR Handshake**: Current implementation uses simplified connection establishment
2. **No IRT Support**: Only RT_CLASS_1 supported (IRT/RT_CLASS_3 not implemented)
3. **No Redundancy**: MRP (Media Redundancy Protocol) not supported
4. **Limited Diagnostics**: Basic alarm handling only
5. **No FSU**: Fast Startup not implemented

These limitations are planned for future releases.

## Future Enhancements

- Full AR/IOCR handshake with RPC
- IRT (Isochronous Real-Time) support
- MRP (Media Redundancy Protocol)
- Advanced diagnostics and alarms
- PROFIsafe support
- Device simulation mode
- Web-based monitoring interface

## Contributing

Contributions are welcome! Please ensure:

- Code follows Scapy coding standards
- Tests are included for new features
- Documentation is updated
- Examples are provided

## License

This module is part of Scapy and is licensed under GPL-2.0-only.

## References

- **PROFINET Specification**: IEC 61158 / IEC 61784
- **DCP Protocol**: IEC 61158-6-10
- **RT Communication**: IEC 61158-5-10
- **Scapy Documentation**: https://scapy.readthedocs.io

## Support

For issues and questions:
- GitHub Issues: https://github.com/secdev/scapy/issues
- Scapy Mailing List: https://scapy.net

## Author

Scapy PROFINET Controller Module
Part of the Scapy Project
