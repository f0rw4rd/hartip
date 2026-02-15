#!/usr/bin/env python3
"""Example 1: Basic device identification using the high-level Device API.

Connects to a HART-IP device, reads identity (Commands 0/13/20), and prints
device info — all in a single constructor call.

Usage:
    python examples/01_basic_read.py [host] [port]
"""

import sys

from hartip import Device

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5094

with Device(host, port=port) as dev:
    print(f"Manufacturer : {dev.manufacturer_name} (ID {dev.manufacturer_id})")
    print(f"Device type  : {dev.device_type}")
    print(f"Device ID    : {dev.device_id}")
    print(f"HART revision: {dev.hart_revision}")
    print(f"SW revision  : {dev.software_revision}")
    print(f"HW revision  : {dev.hardware_revision}")
    print(f"Unique addr  : {dev.unique_address.hex()}")
    print(f"Tag          : {dev.tag!r}")
    print(f"Long tag     : {dev.long_tag!r}")
    print(f"Descriptor   : {dev.descriptor!r}")
