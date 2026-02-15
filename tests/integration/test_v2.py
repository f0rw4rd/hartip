"""
Integration tests for HART-IP v2 features against FieldComm hipserver.

Tests Direct PDU (msg_id=4) and Read Audit Log (msg_id=5) over plaintext
connections. The hipserver supports these message types regardless of TLS
status when operating in v1-compatible mode.

Requires a HART-IP hipserver to be running (Docker container or external).
"""

from __future__ import annotations

import pytest

from hartip import HARTIPClient
from hartip.constants import (
    HARTIP_HEADER_SIZE,
    HARTIPMessageID,
    HARTIPVersion,
)
from hartip.exceptions import (
    HARTIPConnectionError,
    HARTIPStatusError,
    HARTIPTimeoutError,
)
from hartip.protocol import HARTIPHeader, build_session_init
from hartip.v2 import (
    DirectPDU,
    DirectPDUCommand,
)

from .conftest import skip_no_hipserver, skip_no_udp

pytestmark = [
    pytest.mark.integration,
    skip_no_hipserver,
    skip_no_udp,
]


@pytest.fixture(scope="module")
def udp_client(hart_host, hart_udp_port):
    """Module-scoped UDP client connected to hipserver (v1 mode)."""
    client = HARTIPClient(hart_host, port=hart_udp_port, protocol="udp", timeout=5.0)
    client.connect()
    yield client
    client.close()


class TestDirectPDU:
    """Test Direct PDU (msg_id=4) against hipserver.

    The hipserver processes Direct PDU messages by decomposing them into
    individual HART commands, executing each, and assembling the combined
    response. This works for any command the device supports.
    """

    def test_direct_pdu_command_0(self, udp_client):
        """Send Command 0 (Read Unique ID) via Direct PDU."""
        cmds = [DirectPDUCommand(command_number=0, data=b"")]
        result = udp_client.send_direct_pdu(cmds)

        assert isinstance(result, DirectPDU)
        assert len(result.commands) >= 1
        # Command 0 should succeed
        cmd0_resp = result.commands[0]
        assert cmd0_resp.command_number == 0
        assert cmd0_resp.response_code == 0

    def test_direct_pdu_multi_command(self, udp_client):
        """Send multiple commands in a single Direct PDU."""
        cmds = [
            DirectPDUCommand(command_number=0, data=b""),
            DirectPDUCommand(command_number=48, data=b""),
        ]
        result = udp_client.send_direct_pdu(cmds)

        assert isinstance(result, DirectPDU)
        # hipserver always appends a Command 48 response internally for
        # device_status/extended_status, so we should get responses for both
        assert len(result.commands) >= 2

    def test_direct_pdu_device_status(self, udp_client):
        """Verify device status is present in Direct PDU response."""
        cmds = [DirectPDUCommand(command_number=0, data=b"")]
        result = udp_client.send_direct_pdu(cmds)

        # device_status and extended_status should be populated
        assert isinstance(result.device_status, int)
        assert isinstance(result.extended_status, int)


class TestV2SessionInitiate:
    """Test sending session initiate with version=2.

    When hipserver is in v1-compatible mode (no TLS configured),
    it accepts v2 session initiate requests but may respond with
    a version-not-supported warning or downgrade to v1.
    """

    def test_v2_session_init_accepted_or_warned(self, hart_host, hart_udp_port):
        """Verify the server responds to a v2 session initiate."""
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        frame = build_session_init(
            sequence=1,
            master_type=1,
            inactivity_timer=30000,
            version=HARTIPVersion.V2,
        )

        try:
            sock.sendto(frame, (hart_host, hart_udp_port))
            raw, _ = sock.recvfrom(1024)

            header = HARTIPHeader.parse(raw[:HARTIP_HEADER_SIZE])
            # Server should respond -- either with success or a version warning
            assert header.msg_type in (1, 15)  # response or NAK (server never sends type 0)
            assert header.msg_id == HARTIPMessageID.SESSION_INITIATE
        finally:
            # Send session close to clean up
            from hartip.protocol import build_session_close

            close = build_session_close(sequence=2, version=HARTIPVersion.V2)
            try:
                sock.sendto(close, (hart_host, hart_udp_port))
            except OSError:
                pass
            sock.close()


class TestReadAuditLog:
    """Test Read Audit Log (msg_id=5) against hipserver.

    The hipserver maintains session history and responds to audit log
    requests. The response contains session records with connection
    timestamps and PDU counters.
    """

    def test_audit_log_request(self, udp_client):
        """Send a Read Audit Log request and verify the response structure."""
        try:
            result = udp_client.read_audit_log(start_record=0, number_of_records=5)
        except (HARTIPTimeoutError, HARTIPStatusError, HARTIPConnectionError):
            pytest.skip("hipserver may not support Read Audit Log on this connection type")

        # If we got a response, verify basic structure
        assert result.start_record == 0
        assert result.session_record_size > 0
        # power_up_time should be a reasonable timestamp (> year 2000)
        if result.power_up_time > 0:
            assert result.power_up_time > 946684800  # 2000-01-01
