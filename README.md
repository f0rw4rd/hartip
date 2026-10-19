# hartip-py

[![CI](https://github.com/f0rw4rd/hartip/actions/workflows/ci.yml/badge.svg)](https://github.com/f0rw4rd/hartip/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/hartip-py)](https://pypi.org/project/hartip-py/)
[![Python](https://img.shields.io/pypi/pyversions/hartip-py)](https://pypi.org/project/hartip-py/)
[![License](https://img.shields.io/github/license/f0rw4rd/hartip)](LICENSE)
[![Code style: ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![CLA](https://img.shields.io/badge/CLA-required-blue)](CONTRIBUTING.md)

Pure-Python HART-IP **client** library. Server functionality is not included.

Supports HART-IP v1 (plaintext, TCP/UDP) and v2 (TLS, Direct PDU, Audit Log). DTLS is not supported — Python's `ssl` module does not provide DTLS.

## Features

- **HART-IP v1**: UDP (default) and TCP on port 5094, with session initiate/close, keep-alive and sequence numbers
- **HART-IP v2 TLS**: STARTTLS upgrade (HCF_SPEC-085) or TLS-first, TLS-PSK, CA-verified and mutual TLS, certificate validation callbacks, custom `SSLContext`; TLS 1.2 minimum
- **v2 messages**: Direct PDU (several commands per request) and Read Audit Log
- **Command parsers**: 42 commands in the registry (`parse_command`), including extended commands above 253 via Command 31
- **Robust parsing**: byte count and checksum validation, delayed-response retries, communication-error decoding
- **Lookup tables**: 178 engineering unit codes, 551 manufacturer IDs, status and classification decoders
- **High-level API**: `Device` caches identity (Commands 0/13/20) and reads process values on access
- **Multidrop**: address each device on a loop by poll address or unique address
- **Declarative parsing**: wire structs via the [construct](https://construct.readthedocs.io/) library
- **Typed**: ships `py.typed`; parsers return `TypedDict`s (empty dict when the payload is too short)

## Requirements

- Python 3.10+
- Python 3.13+ for TLS-PSK (`ssl` PSK callbacks)
- `construct>=2.10`
- No root privileges: HART-IP is plain UDP/TCP

## Installation

```bash
pip install hartip-py
```

Runnable scripts live in [`examples/`](examples/README.md).

## Quick start

```python
from hartip import HARTIPClient, parse_cmd0, parse_cmd1

# v1 over UDP (default)
with HARTIPClient("192.168.1.100") as client:
    resp = client.read_unique_id()
    info = parse_cmd0(resp.payload)
    print(info.manufacturer_name, info.device_id)

    resp = client.read_primary_variable()
    pv = parse_cmd1(resp.payload)
    print(f"{pv.value} (unit {pv.unit_code})")
```

## TLS (HART-IP v2)

```python
from hartip import HARTIPClient, HARTIP_V2_PSK_CIPHERS

# PSK authentication
with HARTIPClient(
    "192.168.1.100",
    protocol="tcp",
    version=2,
    psk_identity="client1",
    psk_key=b"\x00" * 16,
    ciphers=HARTIP_V2_PSK_CIPHERS,
) as client:
    resp = client.read_unique_id()

# CA-verified + mutual TLS
with HARTIPClient(
    "192.168.1.100",
    protocol="tcp",
    version=2,
    ca_certs="/path/to/ca.pem",
    certfile="/path/to/client.pem",
    keyfile="/path/to/client.key",
) as client:
    resp = client.read_unique_id()

# Custom certificate validation callback
def pin_cert(cert_dict):
    subject = dict(x[0] for x in cert_dict.get("subject", ()))
    return subject.get("commonName") == "my-device.local"

with HARTIPClient(
    "192.168.1.100",
    protocol="tcp",
    version=2,
    cert_validator=pin_cert,
) as client:
    resp = client.read_unique_id()

# Full custom SSLContext
import ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.load_verify_locations("/path/to/ca.pem")

with HARTIPClient("192.168.1.100", protocol="tcp", version=2, ssl_context=ctx) as client:
    resp = client.read_unique_id()
```

## Publish (burst) frames

Devices in burst mode, and gateways with an active subscription, send unsolicited
Publish frames on the client's session. The client skips them while it waits for
the reply to a request. To receive them, pass a callback:

```python
from hartip import HARTIPClient

def on_publish(resp):
    print(resp.command_number, resp.parsed)

with HARTIPClient("192.168.1.100", protocol="tcp", on_publish=on_publish) as client:
    client.read_primary_variable()
```

Publish frames are only read while a request is outstanding; there is no
background reader. Frames that fail validation are dropped.

## Error handling

```python
from hartip import HARTIPClient
from hartip.exceptions import (
    HARTIPConnectionError,
    HARTIPTimeoutError,
    HARTIPTLSError,
    HARTResponseError,
)

with HARTIPClient("192.168.1.100") as client:
    resp = client.read_unique_id()

    # Check manually
    if not resp.success:
        print(resp.error_message)

    # Or raise
    resp.raise_for_error()  # raises HARTResponseError on failure
```

Exception hierarchy:

```
HARTError
├── HARTIPError
│   ├── HARTIPTimeoutError
│   ├── HARTIPConnectionError
│   │   └── HARTIPTLSError
│   └── HARTIPStatusError
└── HARTProtocolError
    ├── HARTChecksumError
    ├── HARTFrameError (also a ValueError)
    ├── HARTResponseError
    └── HARTCommunicationError
```

## Convenience methods

| Method | HART Command |
|--------|-------------|
| `read_unique_id()` | 0 |
| `read_primary_variable()` | 1 |
| `read_current_and_percent()` | 2 |
| `read_dynamic_variables()` | 3 |
| `read_tag_descriptor_date()` | 13 |
| `read_output_info()` | 15 |
| `read_long_tag()` | 20 |
| `read_additional_status()` | 48 |
| `send_command(cmd, ...)` | any |
| `send_direct_pdu(commands)` | v2 Direct PDU |
| `read_audit_log()` | v2 Audit Log |

Commands above 253 go out wrapped in Command 31. The reply is unwrapped for you:
`command_number` reports the expanded number (e.g. 534), `payload` no longer
starts with its 2 bytes, `parsed` uses the parser for 534, and `pdu.command`
stays 31. A reply that carries a different expanded number raises `HARTFrameError`.

## Testing

```bash
# Unit tests (no server needed)
pytest

# Integration tests (requires HART-IP server)
pytest -m integration
```

## Support

If you find this project useful, consider supporting development:

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/f0rw4rd)

## License

Dual-licensed under [GPL-3.0](LICENSE) and a [commercial license](LICENSE-COMMERCIAL.md).

Free for open source use under GPL-3.0. If you want to use hartip-py in proprietary
products without GPL obligations, a commercial license is available —
see [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) for details.

## References

- [HART specifications (FieldComm Group)](https://www.fieldcommgroup.org/hart-specifications)
- [FieldComm hipserver](https://github.com/FieldCommGroup/hipserver) (reference HART-IP server, used by the integration tests)
- [Wireshark HART-IP dissector](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-hartip.c)
- [CISA ICSNPP HART-IP parser](https://github.com/cisagov/icsnpp-hart-ip)
- [construct library](https://construct.readthedocs.io/)

## Trademarks

All marks belong to their owners; used nominatively to describe interoperability; no endorsement implied.
