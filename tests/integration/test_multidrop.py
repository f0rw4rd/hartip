"""
Integration tests for HART-IP multi-drop scan against the Python mock server.

Starts the mock server in multidrop mode (HART_MODE=multidrop) with devices
at addresses 0-3, each with a different manufacturer, device type, and tag.

Requires the Python mock server from msf-ics.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

import pytest

from hartip import (
    DeviceInfo,
    HARTIPClient,
    Variable,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MOCK_HOST = os.environ.get("HARTIP_TEST_HOST", "127.0.0.1")
MD_UDP_PORT = 26094
MD_TCP_PORT = 26095

MOCK_SERVER_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "..",
    "..",
    "msf-ics",
    "docker",
    "mocks",
    "services",
    "hart_server.py",
)
# Resolve relative path
MOCK_SERVER_PATH = os.path.normpath(MOCK_SERVER_PATH)

# Fallback: check known absolute path
if not os.path.exists(MOCK_SERVER_PATH):
    MOCK_SERVER_PATH = "/home/feb/pro/msf-ics/docker/mocks/services/hart_server.py"

_skip_no_mock_server = pytest.mark.skipif(
    not os.path.exists(MOCK_SERVER_PATH),
    reason=f"Mock server not found at {MOCK_SERVER_PATH}",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def multidrop_server():
    """Start the mock server in multidrop mode on non-standard ports.

    Session-scoped: starts once for all tests in this module, killed on teardown.
    """
    if not os.path.exists(MOCK_SERVER_PATH):
        pytest.skip(f"Mock server not found at {MOCK_SERVER_PATH}")

    env = os.environ.copy()
    env.update(
        {
            "HART_MODE": "multidrop",
            "HART_UDP_PORT": str(MD_UDP_PORT),
            "HART_TCP_PORT": str(MD_TCP_PORT),
            "HART_TLS_PORT": "0",  # disable TLS
        }
    )

    proc = subprocess.Popen(
        [sys.executable, MOCK_SERVER_PATH],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for TCP port readiness (up to 10 seconds)
    deadline = time.monotonic() + 10
    ready = False
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((MOCK_HOST, MD_TCP_PORT), timeout=1):
                ready = True
                break
        except (TimeoutError, ConnectionRefusedError, OSError):
            time.sleep(0.2)

    if not ready:
        proc.kill()
        proc.wait()
        pytest.skip("Multidrop mock server did not start in time")

    yield proc

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


@pytest.fixture()
def md_client(multidrop_server):
    """Per-test UDP client connected to multidrop mock server."""
    client = HARTIPClient(MOCK_HOST, port=MD_UDP_PORT, protocol="udp", timeout=3.0)
    client.connect()
    yield client
    client.close()


# Expected data per address (from MULTIDROP_DEVICES in hart_server.py)
EXPECTED_MANUFACTURERS = {
    0: 0x26,  # Rosemount/Emerson
    1: 0x17,  # Honeywell
    2: 0x37,  # Yokogawa
    3: 0x2A,  # Siemens
}

EXPECTED_DEVICE_TYPES = {
    0: 42,
    1: 51,
    2: 62,
    3: 73,
}

EXPECTED_TAGS = {
    0: "PT-101",
    1: "TT-201",
    2: "FT-301",
    3: "LT-401",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@_skip_no_mock_server
@pytest.mark.integration
class TestMultidropScan:
    """Multi-drop scan tests with devices at addresses 0-3."""

    def test_read_cmd0_all_addresses(self, md_client):
        """Read cmd 0 from addresses 0-3: each returns different manufacturer/device_type."""
        seen_manufacturers = set()
        seen_device_types = set()

        for addr in range(4):
            resp = md_client.send_command(0, address=addr)
            assert resp.success, f"Command 0 failed at address {addr}: rc={resp.response_code}"

            parsed = resp.parsed
            assert isinstance(parsed, DeviceInfo)
            assert parsed.manufacturer_id == EXPECTED_MANUFACTURERS[addr], (
                f"Address {addr}: expected mfr 0x{EXPECTED_MANUFACTURERS[addr]:02X}, "
                f"got 0x{parsed.manufacturer_id:02X}"
            )
            assert parsed.device_type == EXPECTED_DEVICE_TYPES[addr], (
                f"Address {addr}: expected device type {EXPECTED_DEVICE_TYPES[addr]}, "
                f"got {parsed.device_type}"
            )
            seen_manufacturers.add(parsed.manufacturer_id)
            seen_device_types.add(parsed.device_type)

        # Verify all addresses returned different manufacturers and types
        assert len(seen_manufacturers) == 4
        assert len(seen_device_types) == 4

    def test_address_15_returns_error(self, md_client):
        """Address 15 (no device) returns an error response code."""
        resp = md_client.send_command(0, address=15)
        assert resp.response_code != 0

    def test_read_tags_per_address(self, md_client):
        """Read tag from each address: returns different tags."""
        for addr in range(4):
            resp = md_client.send_command(13, address=addr)
            assert resp.success, f"Command 13 failed at address {addr}"

            parsed = resp.parsed
            assert isinstance(parsed, dict)
            assert parsed["tag"] == EXPECTED_TAGS[addr], (
                f"Address {addr}: expected tag {EXPECTED_TAGS[addr]!r}, got {parsed['tag']!r}"
            )

    def test_read_primary_variable_per_address(self, md_client):
        """Read PV from each address: each returns a valid Variable."""
        pv_values = []
        for addr in range(4):
            resp = md_client.send_command(1, address=addr)
            assert resp.success, f"Command 1 failed at address {addr}"

            parsed = resp.parsed
            assert isinstance(parsed, Variable)
            assert parsed.label == "PV"
            pv_values.append(parsed.value)

        # Different devices should have meaningfully different PV values
        # (25.5, 85.3, 125.7, 2.35 in the mock -- all different)
        assert len({int(v) for v in pv_values}) >= 3
