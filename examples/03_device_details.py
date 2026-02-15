#!/usr/bin/env python3
"""Example 3: Detailed device information with decoded status fields.

Shows tag/descriptor/date, message, output info (with decoded alarm/transfer
function/write-protect names), and additional status with decoded bit fields.

Usage:
    python examples/03_device_details.py [host] [port]
"""

import sys

from hartip import Device

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5094

with Device(host, port=port) as dev:
    # Identity (cached from connect)
    print("--- Identity ---")
    print(f"  Tag       : {dev.tag!r}")
    print(f"  Descriptor: {dev.descriptor!r}")
    print(f"  Date      : {dev.date}")
    print(f"  Long tag  : {dev.long_tag!r}")

    # Message (Command 12)
    print("\n--- Message ---")
    print(f"  {dev.message!r}")

    # Output info (Command 15) — now with decoded names
    resp = dev.client.read_output_info()
    if resp.success and resp.parsed:
        out = resp.parsed
        print("\n--- Output Info (Cmd 15) ---")
        print(f"  Range units       : {out.get('range_unit_name', '?')}")
        print(f"  Upper range       : {out.get('upper_range_value', '?')}")
        print(f"  Lower range       : {out.get('lower_range_value', '?')}")
        print(f"  Damping           : {out.get('damping_value', '?')}")
        print(f"  Write protect     : {out.get('write_protect_name', '?')}")
        print(f"  Alarm selection   : {out.get('alarm_selection_name', '?')}")
        print(f"  Transfer function : {out.get('transfer_function_name', '?')}")

    # Additional status (Command 48) — now with decoded bit fields
    status = dev.status
    if status:
        print("\n--- Additional Status (Cmd 48) ---")
        print(f"  Device-specific status: {status['device_specific_status'].hex()}")
        if "extended_device_status" in status:
            print(f"  Extended status       : 0x{status['extended_device_status']:02x}")
            decoded = status.get("extended_device_status_decoded", {})
            for flag, val in decoded.items():
                if val:
                    print(f"    - {flag}")
        if "operating_mode_name" in status:
            print(f"  Operating mode        : {status['operating_mode_name']}")
        # Standardized status bytes
        for i in range(4):
            key = f"standardized_status_{i}_decoded"
            if key in status:
                active = [k for k, v in status[key].items() if v]
                if active:
                    print(f"  Status byte {i} flags  : {', '.join(active)}")
