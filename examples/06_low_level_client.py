#!/usr/bin/env python3
"""Example 6: Low-level client with command registry and parser styles.

Shows three parser naming conventions, the registry dispatch, and how
the default_unique_addr is auto-set after read_unique_id().

Usage:
    python examples/06_low_level_client.py [host] [port]
"""

import sys

from hartip import HARTIPClient, parse_command

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5094

with HARTIPClient(host, port=port) as client:
    # read_unique_id auto-sets client.default_unique_addr
    resp = client.read_unique_id()
    print(f"Default unique addr set: {client.default_unique_addr.hex()}")

    # Convenience methods now use the default address automatically
    commands = [
        ("read_unique_id", client.read_unique_id),
        ("read_primary_variable", client.read_primary_variable),
        ("read_current_and_percent", client.read_current_and_percent),
        ("read_dynamic_variables", client.read_dynamic_variables),
        ("read_tag_descriptor_date", client.read_tag_descriptor_date),
        ("read_output_info", client.read_output_info),
        ("read_additional_status", client.read_additional_status),
    ]

    print("\n--- Command walk (using default address) ---")
    for name, method in commands:
        resp = method()
        parsed = resp.parsed
        type_name = type(parsed).__name__ if parsed else "None"
        cmd_num = resp.command_number
        print(f"  Cmd {cmd_num:>3} ({name:<36}) -> {type_name}")

    # Three parser styles for the same payload
    print("\n--- Three parser styles ---")
    from hartip import parse_cmd0, parse_unique_id

    resp = client.read_unique_id()
    r1 = parse_cmd0(resp.payload)
    r2 = parse_unique_id(resp.payload)
    r3 = parse_command(0, resp.payload)
    r4 = resp.parsed
    assert r1.device_id == r2.device_id == r3.device_id == r4.device_id
    print(f"  All 4 parse methods agree: {r1.manufacturer_name} ID={r1.device_id}")
