#!/usr/bin/env python3
"""Example 4: Scan a multidrop HART network.

Iterates through poll addresses 0-15, identifies devices, and prints
a summary table. Uses low-level HARTIPClient since Device assumes a
single device.

Usage:
    python examples/04_multidrop_scan.py [host] [port]
"""

import sys

from hartip import HARTIPClient

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5094

print(f"Scanning {host}:{port} for HART devices (addresses 0-15)...\n")
print(f"{'Addr':>4}  {'Manufacturer':<16} {'Type':>4}  {'Device ID':>9}  {'HART Rev':>8}  {'Tag'}")
print("-" * 72)

with HARTIPClient(host, port=port, timeout=2.0) as client:
    for address in range(16):
        try:
            resp = client.read_unique_id(address=address)
            if resp.response_code != 0:
                continue

            info = resp.parsed
            # Try to get tag — no address needed, default was set by read_unique_id
            tag = ""
            try:
                tag_resp = client.read_tag_descriptor_date(unique_addr=info.unique_address)
                tag_data = tag_resp.parsed
                if tag_data:
                    tag = tag_data["tag"].strip()
            except Exception:  # noqa: S110
                pass

            print(
                f"{address:>4}  {info.manufacturer_name:<16} {info.device_type:>4}  "
                f"{info.device_id:>9}  {info.hart_revision:>8}  {tag}"
            )
        except Exception:  # noqa: S112
            continue

print()
