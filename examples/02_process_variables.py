#!/usr/bin/env python3
"""Example 2: Read process variables with the high-level Device API.

Demonstrates primary variable, loop current, percent range, and dynamic
variables — all as simple property access.

Usage:
    python examples/02_process_variables.py [host] [port]
"""

import sys

from hartip import Device

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5094

with Device(host, port=port) as dev:
    # Primary variable — single property access
    pv = dev.primary_variable
    if pv:
        print(f"PV: {pv.value:.4f} {pv.unit_name} (unit code {pv.unit_code})")

    # Loop current and percent of range
    print(f"Loop current: {dev.loop_current} mA")
    print(f"Percent range: {dev.percent_range}%")

    # Dynamic variables (PV, SV, TV, QV)
    print("\nDynamic variables:")
    for var in dev.dynamic_variables:
        print(f"  {var.label}: {var.value:.4f} {var.unit_name}")
