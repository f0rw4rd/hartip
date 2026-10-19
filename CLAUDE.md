# CLAUDE.md

This file provides guidance to Claude Code and other AI coding assistants when
working in this repository.

## Project overview

`hartip-py` (import name `hartip`) is a pure-Python HART-IP **client** library.
Server functionality is not included. It supports HART-IP v1 (plaintext, TCP
and UDP) and v2 (TLS over TCP, Direct PDU, Read Audit Log). DTLS is not
supported because Python's `ssl` module has no DTLS.

The package requires Python 3.10 or newer (`requires-python = ">=3.10"`; CI
tests 3.10 to 3.15, 3.15 as a pre-release until it is final).
`construct>=2.10` is its only runtime dependency.

It is dual-licensed under GPL-3.0-only (`LICENSE`) and a commercial license
(`LICENSE-COMMERCIAL.md`); contributions fall under the CLA in
`CONTRIBUTING.md`.

This is an unofficial implementation. Changes involving a real HART-IP device
or gateway must be tested against an isolated, non-safety-critical device.

## Repository layout

- `hartip/client.py`: `HARTIPClient` and `HARTIPResponse`; socket management
  (TCP/UDP), session initiate/close/keep-alive, sequence numbers, TLS and
  STARTTLS, checksum validation, extended commands via Command 31,
  delayed-response retries, `probe_server_version()`
- `hartip/protocol.py`: `construct` structs for the HART-IP header and HART PDU
  frames, `build_pdu()` / `parse_pdu()` / `parse_response()`
- `hartip/constants.py`: protocol enums (message types and ids, HART-IP status,
  response codes, commands, device status, comm error flags), ports, cipher
  strings
- `hartip/device.py`: `DeviceInfo`, `Variable`, `DeviceVariable`, the
  `parse_cmdNN` parsers, friendly-name aliases and the command registry
  (`COMMAND_REGISTRY`, `get_parser`, `parse_command`)
- `hartip/high_level.py`: `Device`, a property-based wrapper over
  `HARTIPClient` that caches identity (Commands 0/13/20) and reads process
  values fresh
- `hartip/v2.py`: HART-IP v2 Direct PDU (msg_id 4) and Read Audit Log
  (msg_id 5) structures
- `hartip/lookups.py`: status/classification/transfer-function lookup tables
  and bitfield decoders
- `hartip/units.py`: engineering unit code table (`UNITS`)
- `hartip/vendors.py`: manufacturer id table (`MANUFACTURERS`)
- `hartip/ascii.py`: HART 6-bit packed ASCII
- `hartip/types.py`: `TypedDict` return shapes for the parsers
- `hartip/exceptions.py`: the exception hierarchy
- `tests/`: unit tests (`test_*.py`) and `tests/integration/` (hipserver in
  Docker via `docker-compose.yml` / `run.sh`, plus tests against the msf-ics
  Python mock server)
- `examples/`: numbered runnable scripts (`01_basic_read.py` to
  `07_tls_psk_auth.py`), indexed in `examples/README.md`; keep the index in
  step when adding or renaming one
- `vulture_whitelist.py`: vulture allowlist for public API that looks unused

`ref/` (specs, dissectors, reference implementations, pcaps, `SOURCES.md`) and
`tasks/` are gitignored local material, not part of the repository.

Package data: `hartip/py.typed` ships through
`[tool.setuptools.package-data]` in `pyproject.toml`. Keep it listed there.

## Protocol stack and design constraints

The on-wire stack is TCP or UDP (port 5094 for both) -> 8-byte HART-IP header
(version, message type, message id, status, sequence number, byte count) ->
message body. Message ids used: Session Initiate, Session Close, Keep Alive,
HART PDU pass-through (3), Direct PDU (4, v2) and Read Audit Log (5, v2). The
HART PDU is delimiter, address (short or long), command, byte count, data and
an XOR checksum.

For v2 over TCP the default (`starttls=True`) is the HCF_SPEC-085 STARTTLS
model: Session Initiate goes in plaintext, then the socket is upgraded to TLS.
`starttls=False` does TLS before Session Initiate. TLS is TCP only. The client
enforces TLS 1.2 minimum and caps at TLS 1.2 when PSK credentials are given.

Protocol parsing must treat device data as untrusted:

- Validate the HART-IP `byte_count`, the PDU byte count, data lengths and the
  checksum before using a payload; truncated or oversized input must raise,
  never index past the end.
- Check the HART-IP status byte, the HART response code and the device status
  byte separately; the communication-error bit changes the meaning of the
  response code byte (`is_comm_error`, `decode_comm_error_flags`).
- Use the `construct` structs in `protocol.py` / `v2.py` and the existing
  parsers rather than hand-rolled slicing.
- Raise from `hartip.exceptions` (`HARTError` base; `HARTIPError` subtree for
  transport: timeout, connection, TLS, status; `HARTProtocolError` subtree for
  checksum, response and communication errors).
- Use the module `logger = logging.getLogger(__name__)`, not `print()`, for
  library diagnostics. Never log PSK keys or other key material; `__repr__`
  already prints `psk_key=<redacted>`, keep it that way.
- Without `ca_certs` the client currently uses `CERT_NONE` (devices commonly
  have self-signed or no certificates); with `ca_certs` it sets
  `CERT_REQUIRED` and `check_hostname=True`. Never weaken these defaults, the
  TLS 1.2 minimum, or certificate validation merely to make a test pass.

Keep socket and session mechanics in `client.py`, wire structs in
`protocol.py` / `v2.py`, payload parsing in `device.py`, and tables in
`lookups.py` / `units.py` / `vendors.py`.

## Public API

Everything public is re-exported from `hartip/__init__.py`: `HARTIPClient`,
`HARTIPResponse`, `probe_server_version`, `Device`, the v2 types
(`DirectPDUCommand` and friends), protocol structs and helpers, constants and
enums, `DeviceInfo` / `Variable` / `DeviceVariable`, every `parse_cmdNN` and
its friendly alias, lookup tables and decoders, and all exceptions. `__all__`
is intentionally grouped by category (RUF022 is ignored). Update it
deliberately when adding public API.

```python
from hartip import HARTIPClient, parse_cmd0

with HARTIPClient("192.168.1.100") as client:  # v1 over UDP by default
    resp = client.read_unique_id()
    resp.raise_for_error()
    info = parse_cmd0(resp.payload)
    print(info.manufacturer_name, info.device_id)
```

```python
from hartip import HARTIPClient, HARTIP_V2_PSK_CIPHERS

with HARTIPClient(
    "192.168.1.100",
    protocol="tcp",
    version=2,
    psk_identity="client1",
    psk_key=b"\x00" * 16,
    ciphers=HARTIP_V2_PSK_CIPHERS,
) as client:
    resp = client.read_unique_id()
```

`Device(host, port=5094, *, auto_read_tags=True, **kwargs)` passes extra
keyword arguments through to `HARTIPClient`.

## Development setup and checks

```bash
pip install -e ".[dev]"
```

CI (`.github/workflows/ci.yml`, push and pull request on `main`) runs:

```bash
ruff check hartip/
ruff format --check hartip/
pytest -v                      # Python 3.10 to 3.15
pytest --collect-only -q
vulture hartip/ vulture_whitelist.py
bandit -c pyproject.toml -r hartip/
```

`.github/workflows/auto-format.yml` runs `ruff format hartip/` on pull
requests to `main` and pushes a `style: auto-format with ruff` commit to the
PR branch when it changes anything. It is kept out of `ci.yml` so the reusable
CI workflow never holds `contents: write`.

`.pre-commit-config.yaml` uses three stages: pre-commit (`ruff check --fix`,
`ruff format`, vulture), pre-push (bandit, `python -m pytest tests/ -x -q`) and
commit-msg (`.githooks/no-ai-coauthor`). Install each stage's hook type for it
to run.

Ruff targets py310 with a 100-character line length; the rule set and
per-file ignores are in `pyproject.toml`. MyPy is not configured in this
repository. Bandit skips B101, B104 and B311; vulture uses
`min_confidence = 80`.

`addopts = "-m 'not integration'"` deselects integration tests by default, so
plain `pytest` needs no network or device. Integration tests:

```bash
./tests/integration/run.sh            # builds and starts hipserver, runs, stops
./tests/integration/run.sh --keep     # leave the container running
HARTIP_TEST_HOST=10.0.0.1 HARTIP_TEST_UDP_PORT=5094 pytest -m integration
```

They skip when the hipserver or the msf-ics mock server is not reachable; the
TLS-PSK tests also need Python 3.13+.

Release (`.github/workflows/release.yml`): pushing a tag `vX.Y.Z` reruns CI,
checks that the tag equals `hartip.__version__` (the single version source;
`pyproject.toml` reads it via `[tool.setuptools.dynamic]`), builds with
`python -m build`, runs `twine check`, attests provenance, publishes to PyPI by
trusted publishing through the `pypi` environment (approval required), and
creates a GitHub Release with `SHA256SUMS.txt`. `workflow_dispatch` with
`dry_run` builds without publishing. There is no changelog file; release notes
are generated by GitHub.

## Testing expectations

- Add byte-exact tests (fixed hex frames) for new structs, builders and
  parsers, plus a build/parse round trip where both directions exist.
- Add malformed and truncated input cases for every parser: short payloads,
  wrong byte counts, bad checksums, error response codes and status bytes.
- Bug fixes include a regression test that fails without the fix.
- Unit tests must not need a device or network; use captured frames or the
  integration mock servers for end-to-end behavior.
- Real-device and server tests carry `@pytest.mark.integration` and stay
  opt-in. Do not turn an integration failure into a unit-test skip.

## Code quality and contribution rules

- Cite a checkable source for every new command number, response code, status
  bit, unit, vendor or table entry (HART spec, Wireshark `packet-hartip.c`,
  CISAGOV `hart_ip_enum.spicy`, FieldComm hipserver/hipflowapp, a pcap), and
  say when a value is unverified.
- Prefer small, focused changes and one coherent purpose per pull request.
- Conventional commits, lowercase after the colon (`fix:`, `feat:`, `docs:`,
  `test:`, `refactor:`, `chore:`, `ci:`).
- No AI co-author trailers; `.githooks/no-ai-coauthor` rejects
  `Co-Authored-By:` lines naming Claude or Anthropic, and `CONTRIBUTING.md`
  forbids AI co-author lines generally.
- Run `ruff check` and `ruff format` before submitting; keep vulture and bandit
  clean (extend `vulture_whitelist.py` only for genuine public API).
- Update `README.md`, `hartip/__init__.py` exports, `hartip/types.py`,
  examples and tests when a public API or supported-feature claim changes.
