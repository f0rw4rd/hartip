#!/usr/bin/env python3
"""Example 5: Device variables with decoded status and classification.

Demonstrates Command 9 with the new decoded fields: classification names,
status bit decoding, and extended device status.

Usage:
    python examples/05_device_variables.py [host] [port]
"""

import sys

from hartip import Device

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5094

with Device(host, port=port) as dev:
    print(f"Device: {dev.manufacturer_name} (tag={dev.tag!r})\n")

    # Command 9: device variables with full status decoding
    variables = dev.device_variables([0, 1, 2, 3])

    for var in variables:
        print(f"Slot {var.slot}: {var.value:.4f} {var.unit_name}")
        print(f"  Classification : {var.classification_name} (code {var.classification})")
        print(f"  Status byte    : 0x{var.status:02x}")

        # Decoded status sub-fields
        decoded = var.status_decoded
        print(f"  Process data   : {decoded['process_data_status_name']}")
        print(f"  Limit status   : {decoded['limit_status_name']}")
        print(f"  More status    : {decoded['more_device_variable_status_available']}")
        print()

    # Also show the extended device status from the response
    resp = dev.client.read_device_vars_status(device_var_codes=[0, 1, 2, 3])
    if resp.success and resp.parsed:
        ext = resp.parsed.get("extended_device_status_decoded", {})
        print("Extended device status:")
        for flag, active in ext.items():
            print(f"  {flag}: {active}")

        ts = resp.parsed.get("timestamp_seconds")
        if ts is not None:
            print(f"\nTimestamp: {ts:.3f} seconds")
