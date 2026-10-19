# HART-IP Examples

## Quick Start

```python
from hartip import Device

# High-level: identity is read once on connect, process values on access
with Device("192.168.1.100") as dev:
    print(dev.manufacturer_name, dev.tag)
    print(dev.primary_variable)
```

```python
from hartip import HARTIPClient

# Low-level: one call per HART command, raw HARTIPResponse back
with HARTIPClient("192.168.1.100") as client:  # v1 over UDP by default
    resp = client.read_unique_id()
    resp.raise_for_error()
    print(resp.parsed)
```

## Arguments

Examples 01 to 06 take the target as positional arguments:

```bash
python examples/01_basic_read.py [host] [port]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `host` | `127.0.0.1` | Device or gateway address |
| `port` | `5094` | HART-IP port (UDP for 01 to 06) |

Example 07 uses `argparse`; run it with `--help` for its options
(`--port`, `--identity`, `--key`, `--no-tls`, `--probe`, `--timeout`).

## Requirements

| Example | Transport | Python |
|---------|-----------|--------|
| 01 to 06 | HART-IP v1, UDP | 3.10+ |
| 07 with TLS-PSK | HART-IP v2, TLS over TCP | 3.13+ (`ssl` PSK callbacks) |
| 07 with `--no-tls` | HART-IP v1, TCP | 3.10+ |

No root privileges are needed: HART-IP is plain UDP/TCP on port 5094.

## Examples

### High-level `Device` API

| File | Description |
|------|-------------|
| `01_basic_read.py` | Identity from Commands 0/13/20 in one constructor call |
| `02_process_variables.py` | PV, loop current, percent of range, dynamic variables |
| `03_device_details.py` | Tag, descriptor, message, output info, decoded status fields |
| `05_device_variables.py` | Command 9 device variables with classification and status decoding |

### Low-level `HARTIPClient`

| File | Description |
|------|-------------|
| `04_multidrop_scan.py` | Poll addresses 0 to 15 on a multidrop loop, print a summary table |
| `06_low_level_client.py` | Convenience methods, the command registry and parser naming styles |

### HART-IP v2

| File | Description |
|------|-------------|
| `07_tls_psk_auth.py` | TLS-PSK session, optional server version probe |

## Local test target

The integration suite's FieldComm hipserver container serves HART-IP on
port 5094 (UDP and TCP):

```bash
./tests/integration/run.sh --keep
python examples/01_basic_read.py 127.0.0.1 5094
```

Only point these scripts at real devices on an isolated, non-safety-critical
network.
