"""
Integration tests for HART-IP v2 TLS-PSK authentication.

Starts the Python mock server with TLS-PSK enabled on non-standard ports
and verifies that correct credentials establish a session while incorrect
credentials are rejected with HARTIPTLSError.

Requires Python 3.13+ for TLS-PSK callback support.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

import pytest

from hartip import HARTIPClient, parse_cmd0
from hartip.exceptions import HARTIPTLSError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MOCK_HOST = os.environ.get("HARTIP_TEST_HOST", "127.0.0.1")
TLS_UDP_PORT = 27094
TLS_TCP_PORT = 27095
TLS_PORT = 27096
PSK_IDENTITY = "hart-test"
PSK_KEY_HEX = "0123456789abcdef0123456789abcdef"
PSK_KEY = bytes.fromhex(PSK_KEY_HEX)

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

# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------

_skip_no_python313 = pytest.mark.skipif(
    sys.version_info < (3, 13),
    reason="TLS-PSK callbacks require Python 3.13+",
)

_skip_no_mock_server = pytest.mark.skipif(
    not os.path.exists(MOCK_SERVER_PATH),
    reason=f"Mock server not found at {MOCK_SERVER_PATH}",
)


def _tls_port_reachable() -> bool:
    """Check if TLS port is already reachable."""
    try:
        with socket.create_connection((MOCK_HOST, TLS_PORT), timeout=1):
            return True
    except (TimeoutError, ConnectionRefusedError, OSError):
        return False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def tls_mock_server():
    """Start the mock server with TLS-PSK on non-standard ports.

    Session-scoped: starts once for all tests in this module, killed on teardown.
    """
    if sys.version_info < (3, 13):
        pytest.skip("TLS-PSK callbacks require Python 3.13+")

    if not os.path.exists(MOCK_SERVER_PATH):
        pytest.skip(f"Mock server not found at {MOCK_SERVER_PATH}")

    env = os.environ.copy()
    env.update(
        {
            "HART_UDP_PORT": str(TLS_UDP_PORT),
            "HART_TCP_PORT": str(TLS_TCP_PORT),
            "HART_TLS_PORT": str(TLS_PORT),
            "HART_PSK_IDENTITY": PSK_IDENTITY,
            "HART_PSK_KEY": PSK_KEY_HEX,
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
            with socket.create_connection((MOCK_HOST, TLS_TCP_PORT), timeout=1):
                ready = True
                break
        except (TimeoutError, ConnectionRefusedError, OSError):
            time.sleep(0.2)

    if not ready:
        proc.kill()
        proc.wait()
        pytest.skip("TLS mock server did not start in time")

    yield proc

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@_skip_no_python313
@_skip_no_mock_server
@pytest.mark.integration
class TestTLSPSK:
    """TLS-PSK integration tests against the mock server."""

    def test_correct_psk_connects(self, tls_mock_server):
        """Correct PSK identity and key establishes a session and reads cmd 0."""
        client = HARTIPClient(
            MOCK_HOST,
            port=TLS_PORT,
            protocol="tcp",
            version=2,
            psk_identity=PSK_IDENTITY,
            psk_key=PSK_KEY,
            timeout=5.0,
        )
        client.connect()
        try:
            resp = client.read_unique_id()
            assert resp.success
            info = parse_cmd0(resp.payload)
            assert info.manufacturer_id > 0
        finally:
            client.close()

    def test_wrong_identity_raises(self, tls_mock_server):
        """Wrong PSK identity raises HARTIPTLSError."""
        client = HARTIPClient(
            MOCK_HOST,
            port=TLS_PORT,
            protocol="tcp",
            version=2,
            psk_identity="wrong-identity",
            psk_key=PSK_KEY,
            timeout=5.0,
        )
        with pytest.raises(HARTIPTLSError):
            client.connect()
        client.close()

    def test_wrong_key_raises(self, tls_mock_server):
        """Wrong PSK key raises HARTIPTLSError."""
        client = HARTIPClient(
            MOCK_HOST,
            port=TLS_PORT,
            protocol="tcp",
            version=2,
            psk_identity=PSK_IDENTITY,
            psk_key=b"\xff" * 16,
            timeout=5.0,
        )
        with pytest.raises(HARTIPTLSError):
            client.connect()
        client.close()
