#!/usr/bin/env python3
"""Example 7: HART-IP v2 with TLS-PSK authentication.

HART-IP v2 (HCF_SPEC-085 rev 3.1) adds mandatory TLS for TCP connections.
Two authentication methods are supported:

  - TLS-PSK: Pre-Shared Key (most common for field devices)
  - TLS-SRP: Secure Remote Password (less common)

The PSK identity and key are typically provisioned during device
commissioning or found in the device documentation.

Usage:
    python examples/07_tls_psk_auth.py <host> [--port PORT]
                                       [--identity ID] [--key KEY]

    # Against local TLS mock (hipserver-tls on port 5095):
    python examples/07_tls_psk_auth.py 127.0.0.1 --port 5095

    # Against local mock (plaintext fallback, for testing):
    python examples/07_tls_psk_auth.py 127.0.0.1 --port 5094 --no-tls

Note on PSK key format:
    The --key is the raw PSK bytes as a hex string.  The FieldComm
    hipserver stores keys as the ASCII hex string + null terminator
    (a hipserver quirk), so the default key value below is pre-encoded
    for the hipserver default configuration.
"""

import argparse
import sys

from hartip import (
    HARTIP_V2_PSK_CIPHERS,
    Device,
    HARTIPConnectionError,
    HARTIPTimeoutError,
    HARTIPTLSError,
    probe_server_version,
)

# hipserver default PSK: the ASCII hex string "7777772e68617274636f6d6d2e6f7267"
# plus a null terminator (hipserver stores the JSON key value as raw chars).
HIPSERVER_DEFAULT_KEY = b"7777772e68617274636f6d6d2e6f7267\x00"


def parse_args():
    p = argparse.ArgumentParser(description="HART-IP v2 TLS-PSK example")
    p.add_argument("host", help="Device IP or hostname")
    p.add_argument("--port", type=int, default=5094, help="TCP port (default: 5094)")
    p.add_argument("--identity", default="HART-IPClient", help="PSK identity string")
    p.add_argument(
        "--key",
        default=None,
        help="PSK key as raw bytes in hex (default: hipserver built-in key)",
    )
    p.add_argument("--no-tls", action="store_true", help="Use plaintext TCP (for mock testing)")
    p.add_argument("--probe", action="store_true", help="Probe server version before connecting")
    p.add_argument("--timeout", type=float, default=5.0, help="Connection timeout")
    return p.parse_args()


def main():
    args = parse_args()

    # Optional version probe
    if args.probe:
        try:
            ver = probe_server_version(args.host, port=args.port)
            print(f"Server reports HART-IP v{ver}")
        except (HARTIPConnectionError, HARTIPTimeoutError) as e:
            print(f"Probe failed: {e}")

    # Resolve PSK key
    if args.key is not None:
        try:
            psk_key = bytes.fromhex(args.key)
        except ValueError:
            print(f"Error: --key must be a hex string, got {args.key!r}")
            sys.exit(1)
    else:
        psk_key = HIPSERVER_DEFAULT_KEY

    # Build Device kwargs
    kwargs = {"port": args.port, "protocol": "tcp", "timeout": args.timeout}

    if args.no_tls:
        print(f"Connecting to {args.host}:{args.port} (TCP, plaintext)...")
        kwargs["version"] = 1
    else:
        print(f"Connecting to {args.host}:{args.port} (TLS-PSK)...")
        print(f"  Identity: {args.identity}")
        print(f"  Key:      {psk_key.hex()}")
        kwargs.update(
            version=2,
            psk_identity=args.identity,
            psk_key=psk_key,
            ciphers=HARTIP_V2_PSK_CIPHERS,
        )

    try:
        with Device(args.host, **kwargs) as dev:
            print("  Connected!\n")

            print(f"Device: {dev.manufacturer_name}")
            print(f"  Type    : {dev.device_type}")
            print(f"  ID      : {dev.device_id}")
            print(f"  HART rev: {dev.hart_revision}")
            print(f"  Tag     : {dev.tag!r}")
            print(f"  Long tag: {dev.long_tag!r}")

            pv = dev.primary_variable
            if pv:
                print(f"  PV      : {pv.value:.4f} {pv.unit_name}")

            status = dev.status
            if status and "extended_device_status" in status:
                print(f"  Status  : 0x{status['extended_device_status']:02x}")
                decoded = status.get("extended_device_status_decoded", {})
                active = [k for k, v in decoded.items() if v]
                if active:
                    print(f"  Flags   : {', '.join(active)}")

            print("\nDone.")

    except HARTIPTLSError as e:
        print(f"\nTLS error: {e}")
        print("  Check PSK identity/key match the device configuration.")
        sys.exit(1)
    except HARTIPConnectionError as e:
        print(f"\nConnection error: {e}")
        sys.exit(1)
    except HARTIPTimeoutError as e:
        print(f"\nTimeout: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
