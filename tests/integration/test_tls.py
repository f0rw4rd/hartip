"""
Integration tests for HART-IP v2 TLS-PSK against FieldComm hipserver.

Targets the ``hart-device-tls`` compose service: hipserver started with
``-psk``, which takes a plaintext Session Initiate and then upgrades the
TCP socket to TLS (HCF_SPEC-085 STARTTLS).  Correct credentials must
establish a session; a wrong identity or key must raise HARTIPTLSError.

Requires Python 3.13+ for TLS-PSK callback support.

Override via environment variables::

    HARTIP_TEST_TLS_PORT=5095
"""

from __future__ import annotations

import os
import socket
import sys

import pytest

from hartip import HARTIP_V2_PSK_CIPHERS, HARTIPClient, parse_cmd0
from hartip.exceptions import HARTIPTLSError
from hartip.v2 import DirectPDUCommand

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TLS_HOST = os.environ.get("HARTIP_TEST_HOST", "127.0.0.1")
TLS_PORT = int(os.environ.get("HARTIP_TEST_TLS_PORT", "5095"))
# Seeded into hipServer.conf slot 0 by docker/Dockerfile.hipserver-tls.
PSK_IDENTITY = "HART-IPClient"
PSK_KEY = bytes.fromhex("7777772e68617274636f6d6d2e6f7267")

# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------


def _tls_port_reachable() -> bool:
    try:
        with socket.create_connection((TLS_HOST, TLS_PORT), timeout=1):
            return True
    except OSError:
        return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.version_info < (3, 13),
        reason="TLS-PSK callbacks require Python 3.13+",
    ),
    pytest.mark.skipif(
        not _tls_port_reachable(),
        reason=f"hipserver TLS-PSK not reachable on {TLS_HOST}:{TLS_PORT} "
        "(run tests/integration/run.sh)",
    ),
]


def _client(*, identity: str = PSK_IDENTITY, key: bytes = PSK_KEY) -> HARTIPClient:
    return HARTIPClient(
        TLS_HOST,
        port=TLS_PORT,
        protocol="tcp",
        version=2,
        psk_identity=identity,
        psk_key=key,
        ciphers=HARTIP_V2_PSK_CIPHERS,
        timeout=5.0,
    )


@pytest.fixture()
def tls_client():
    client = _client()
    client.connect()
    yield client
    client.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestTLSPSK:
    def test_correct_psk_connects(self, tls_client):
        """Correct PSK identity and key establishes a v2 session and reads cmd 0."""
        assert tls_client.server_version == 2
        assert tls_client._socket.version() == "TLSv1.2"
        assert tls_client._socket.cipher()[0].startswith("PSK-")
        resp = tls_client.read_unique_id()
        assert resp.success
        info = parse_cmd0(resp.payload)
        assert info.manufacturer_id > 0

    def test_wrong_identity_raises(self):
        client = _client(identity="wrong-identity")
        with pytest.raises(HARTIPTLSError):
            client.connect()
        client.close()

    def test_wrong_key_raises(self):
        client = _client(key=b"\xff" * 16)
        with pytest.raises(HARTIPTLSError):
            client.connect()
        client.close()


class TestV2MessagesOverTLS:
    def test_direct_pdu(self, tls_client):
        result = tls_client.send_direct_pdu([DirectPDUCommand(0), DirectPDUCommand(48)])
        assert [c.command_number for c in result.commands] == [0, 48]
        assert all(c.response_code == 0 for c in result.commands)
        assert parse_cmd0(result.commands[0].data).manufacturer_id > 0

    def test_audit_log_lists_this_session(self, tls_client):
        """hipserver clamps an over-long range and answers with status 8 (warning)."""
        log = tls_client.read_audit_log(start_record=0, number_of_records=128)
        assert log.number_of_records == len(log.records) >= 1
        assert log.session_record_size == 58
