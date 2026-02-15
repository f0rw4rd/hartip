"""
Unit tests for HART-IP v2 protocol extensions.

Tests Direct PDU (msg_id=4), Read Audit Log (msg_id=5),
and associated constants/structures.
"""

from __future__ import annotations

import ipaddress
import struct

import pytest

from hartip.constants import (
    AUDIT_LOG_REQUEST_SIZE,
    DIRECT_PDU_CMD_HEADER_SIZE,
    DIRECT_PDU_HEADER_SIZE,
    HARTIP_HEADER_SIZE,
    HARTIP_V2_ALL_CIPHERS,
    HARTIP_V2_PSK_CIPHERS,
    HARTIP_V2_SRP_CIPHERS,
    SESSION_LOG_RECORD_SIZE,
    HARTIPMessageID,
    HARTIPMessageType,
    HARTIPServerStatus,
    HARTIPSessionStatus,
    HARTIPVersion,
)
from hartip.protocol import HARTIPHeader
from hartip.v2 import (
    AuditLogResponse,
    DirectPDU,
    DirectPDUCommand,
    SessionLogRecord,
    build_audit_log_request,
    build_direct_pdu_request,
    parse_audit_log_response,
    parse_direct_pdu_request,
    parse_direct_pdu_response,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestV2Constants:
    """Test HART-IP v2 constants and enums."""

    def test_version_v2(self):
        assert HARTIPVersion.V2 == 2

    def test_version_v1_unchanged(self):
        assert HARTIPVersion.V1 == 1

    def test_message_id_direct_pdu(self):
        assert HARTIPMessageID.DIRECT_PDU == 4

    def test_message_id_read_audit_log(self):
        assert HARTIPMessageID.READ_AUDIT_LOG == 5

    def test_direct_pdu_header_size(self):
        assert DIRECT_PDU_HEADER_SIZE == 2

    def test_direct_pdu_cmd_header_size(self):
        assert DIRECT_PDU_CMD_HEADER_SIZE == 3

    def test_audit_log_request_size(self):
        assert AUDIT_LOG_REQUEST_SIZE == 2

    def test_session_log_record_size(self):
        assert SESSION_LOG_RECORD_SIZE == 58

    def test_cipher_suites_defined(self):
        assert "PSK-AES128-GCM-SHA256" in HARTIP_V2_PSK_CIPHERS
        assert "PSK-AES128-CBC-SHA256" in HARTIP_V2_PSK_CIPHERS
        assert "PSK-AES128-CCM" in HARTIP_V2_PSK_CIPHERS
        assert "SRP-AES-128-CBC-SHA" in HARTIP_V2_SRP_CIPHERS
        # All ciphers is the union
        assert "PSK-AES128-GCM-SHA256" in HARTIP_V2_ALL_CIPHERS
        assert "SRP-AES-128-CBC-SHA" in HARTIP_V2_ALL_CIPHERS


class TestServerStatus:
    """Test HARTIPServerStatus flags."""

    def test_none(self):
        assert HARTIPServerStatus.NONE == 0

    def test_unable_to_locate_syslog(self):
        assert HARTIPServerStatus.UNABLE_TO_LOCATE_SYSLOG_SERVER == 0x0001

    def test_syslog_connection_failed(self):
        assert HARTIPServerStatus.SYSLOG_CONNECTION_FAILED == 0x0002

    def test_insecure_syslog(self):
        assert HARTIPServerStatus.INSECURE_SYSLOG_CONNECTION == 0x0004

    def test_combined_flags(self):
        combined = (
            HARTIPServerStatus.UNABLE_TO_LOCATE_SYSLOG_SERVER
            | HARTIPServerStatus.INSECURE_SYSLOG_CONNECTION
        )
        assert combined == 0x0005


class TestSessionStatus:
    """Test HARTIPSessionStatus flags."""

    def test_writes_occurred(self):
        assert HARTIPSessionStatus.WRITES_OCCURRED == 0x0001

    def test_bad_session_init(self):
        assert HARTIPSessionStatus.BAD_SESSION_INITIALIZATION == 0x0002

    def test_aborted_session(self):
        assert HARTIPSessionStatus.ABORTED_SESSION == 0x0004

    def test_session_timeout(self):
        assert HARTIPSessionStatus.SESSION_TIMEOUT == 0x0008

    def test_insecure_session(self):
        assert HARTIPSessionStatus.INSECURE_SESSION == 0x0010


# ---------------------------------------------------------------------------
# Direct PDU Command
# ---------------------------------------------------------------------------


class TestDirectPDUCommand:
    """Test DirectPDUCommand encoding/decoding."""

    def test_encode_request_no_data(self):
        cmd = DirectPDUCommand(command_number=0, data=b"")
        encoded = cmd.encode_request()
        assert encoded == b"\x00\x00\x00"  # cmd(2) + bc(1)=0

    def test_encode_request_with_data(self):
        cmd = DirectPDUCommand(command_number=48, data=b"\x01\x02\x03")
        encoded = cmd.encode_request()
        # cmd=48 -> 0x0030, bc=3, data=\x01\x02\x03
        assert encoded == b"\x00\x30\x03\x01\x02\x03"

    def test_encode_request_extended_command(self):
        cmd = DirectPDUCommand(command_number=541, data=b"\xaa")
        encoded = cmd.encode_request()
        # cmd=541 -> 0x021D, bc=1, data=\xAA
        assert encoded == b"\x02\x1d\x01\xaa"

    def test_encode_response(self):
        cmd = DirectPDUCommand(command_number=0, data=b"\x01\x02", response_code=0)
        encoded = cmd.encode_response()
        # cmd=0 -> 0x0000, bc=3 (rc + data), rc=0, data=\x01\x02
        assert encoded == b"\x00\x00\x03\x00\x01\x02"

    def test_is_response_false(self):
        cmd = DirectPDUCommand(command_number=0)
        assert not cmd.is_response

    def test_is_response_true(self):
        cmd = DirectPDUCommand(command_number=0, response_code=0)
        assert cmd.is_response


# ---------------------------------------------------------------------------
# Direct PDU Build/Parse
# ---------------------------------------------------------------------------


class TestBuildDirectPDU:
    """Test building Direct PDU requests."""

    def test_single_command(self):
        cmds = [DirectPDUCommand(command_number=0, data=b"")]
        frame = build_direct_pdu_request(sequence=1, commands=cmds)

        # Parse header
        header = HARTIPHeader.parse(frame[:HARTIP_HEADER_SIZE])
        assert header.version == HARTIPVersion.V2
        assert header.msg_type == HARTIPMessageType.REQUEST
        assert header.msg_id == HARTIPMessageID.DIRECT_PDU
        assert header.status == 0
        assert header.sequence == 1

        # Parse payload
        payload = frame[HARTIP_HEADER_SIZE:]
        assert payload[0] == 0  # device_status
        assert payload[1] == 0  # extended_status
        assert payload[2:4] == b"\x00\x00"  # command_number = 0
        assert payload[4] == 0  # byte_count = 0

    def test_multiple_commands(self):
        cmds = [
            DirectPDUCommand(command_number=0, data=b""),
            DirectPDUCommand(command_number=48, data=b"\x01\x02"),
        ]
        frame = build_direct_pdu_request(sequence=42, commands=cmds)

        header = HARTIPHeader.parse(frame[:HARTIP_HEADER_SIZE])
        assert header.msg_id == HARTIPMessageID.DIRECT_PDU
        assert header.sequence == 42

        payload = frame[HARTIP_HEADER_SIZE:]
        # device_status(1) + extended_status(1) + cmd0(2+1+0) + cmd48(2+1+2) = 10
        assert len(payload) == 10

    def test_no_commands_raises(self):
        with pytest.raises(ValueError, match="at least one command"):
            build_direct_pdu_request(sequence=1, commands=[])

    def test_v1_version_override(self):
        cmds = [DirectPDUCommand(command_number=0)]
        frame = build_direct_pdu_request(sequence=1, commands=cmds, version=HARTIPVersion.V1)
        header = HARTIPHeader.parse(frame[:HARTIP_HEADER_SIZE])
        assert header.version == HARTIPVersion.V1

    def test_custom_status_bytes(self):
        cmds = [DirectPDUCommand(command_number=0)]
        frame = build_direct_pdu_request(
            sequence=1, commands=cmds, device_status=0x40, extended_status=0x20
        )
        payload = frame[HARTIP_HEADER_SIZE:]
        assert payload[0] == 0x40
        assert payload[1] == 0x20


class TestParseDirectPDUResponse:
    """Test parsing Direct PDU responses."""

    def test_single_command_response(self):
        # device_status=0, extended_status=0, cmd0: number=0, bc=3, rc=0, data=\x01\x02
        payload = b"\x00\x00" + b"\x00\x00\x03\x00\x01\x02"
        result = parse_direct_pdu_response(payload)

        assert result.device_status == 0
        assert result.extended_status == 0
        assert len(result.commands) == 1
        assert result.commands[0].command_number == 0
        assert result.commands[0].response_code == 0
        assert result.commands[0].data == b"\x01\x02"

    def test_multi_command_response(self):
        # Two commands: cmd0 with rc=0 and cmd48 with rc=0
        payload = (
            b"\x40\x00"  # device_status=0x40, extended_status=0
            + b"\x00\x00\x01\x00"  # cmd0: number=0, bc=1, rc=0
            + b"\x00\x30\x03\x00\xaa\xbb"  # cmd48: number=48, bc=3, rc=0, data=\xAA\xBB
        )
        result = parse_direct_pdu_response(payload)

        assert result.device_status == 0x40
        assert len(result.commands) == 2

        assert result.commands[0].command_number == 0
        assert result.commands[0].response_code == 0
        assert result.commands[0].data == b""

        assert result.commands[1].command_number == 48
        assert result.commands[1].response_code == 0
        assert result.commands[1].data == b"\xaa\xbb"

    def test_zero_byte_count_command(self):
        # Command with byte_count=0 (no response code or data)
        payload = b"\x00\x00" + b"\x00\x00\x00"
        result = parse_direct_pdu_response(payload)
        assert len(result.commands) == 1
        assert result.commands[0].response_code == 0
        assert result.commands[0].data == b""

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            parse_direct_pdu_response(b"\x00")

    def test_truncated_command_raises(self):
        # device_status + extended_status + partial command header
        with pytest.raises(ValueError, match="truncated"):
            parse_direct_pdu_response(b"\x00\x00\x00\x00")

    def test_truncated_command_data_raises(self):
        # Command claims 5 bytes of data but only 2 remain
        payload = b"\x00\x00" + b"\x00\x00\x05\x00\x01"
        with pytest.raises(ValueError, match="truncated"):
            parse_direct_pdu_response(payload)


class TestParseDirectPDURequest:
    """Test parsing Direct PDU requests (no response_code)."""

    def test_single_request_command(self):
        payload = b"\x00\x00" + b"\x00\x00\x02\xaa\xbb"
        result = parse_direct_pdu_request(payload)

        assert len(result.commands) == 1
        assert result.commands[0].command_number == 0
        assert result.commands[0].response_code is None
        assert result.commands[0].data == b"\xaa\xbb"

    def test_empty_data_request(self):
        payload = b"\x00\x00" + b"\x00\x00\x00"
        result = parse_direct_pdu_request(payload)
        assert len(result.commands) == 1
        assert result.commands[0].data == b""
        assert not result.commands[0].is_response


class TestDirectPDURoundtrip:
    """Test build -> parse roundtrip for Direct PDU."""

    def test_roundtrip_single_command(self):
        cmds = [DirectPDUCommand(command_number=0, data=b"\x01\x02\x03")]
        frame = build_direct_pdu_request(sequence=5, commands=cmds)
        payload = frame[HARTIP_HEADER_SIZE:]

        # Parse as request (no response_code)
        result = parse_direct_pdu_request(payload)
        assert len(result.commands) == 1
        assert result.commands[0].command_number == 0
        assert result.commands[0].data == b"\x01\x02\x03"

    def test_roundtrip_multiple_commands(self):
        cmds = [
            DirectPDUCommand(command_number=0, data=b""),
            DirectPDUCommand(command_number=1, data=b"\xff"),
            DirectPDUCommand(command_number=541, data=b"\x01\x02\x03\x04"),
        ]
        frame = build_direct_pdu_request(
            sequence=10,
            commands=cmds,
            device_status=0x80,
            extended_status=0x04,
        )
        payload = frame[HARTIP_HEADER_SIZE:]
        result = parse_direct_pdu_request(payload)

        assert result.device_status == 0x80
        assert result.extended_status == 0x04
        assert len(result.commands) == 3
        assert result.commands[0].command_number == 0
        assert result.commands[0].data == b""
        assert result.commands[1].command_number == 1
        assert result.commands[1].data == b"\xff"
        assert result.commands[2].command_number == 541
        assert result.commands[2].data == b"\x01\x02\x03\x04"


# ---------------------------------------------------------------------------
# Read Audit Log
# ---------------------------------------------------------------------------


class TestBuildAuditLogRequest:
    """Test building Read Audit Log requests."""

    def test_structure(self):
        frame = build_audit_log_request(sequence=7, start_record=0, number_of_records=5)

        header = HARTIPHeader.parse(frame[:HARTIP_HEADER_SIZE])
        assert header.version == HARTIPVersion.V2
        assert header.msg_type == HARTIPMessageType.REQUEST
        assert header.msg_id == HARTIPMessageID.READ_AUDIT_LOG
        assert header.sequence == 7
        assert header.byte_count == HARTIP_HEADER_SIZE + 2

        payload = frame[HARTIP_HEADER_SIZE:]
        assert payload == b"\x00\x05"

    def test_start_record_offset(self):
        frame = build_audit_log_request(sequence=1, start_record=3, number_of_records=2)
        payload = frame[HARTIP_HEADER_SIZE:]
        assert payload == b"\x03\x02"


def _build_session_log_record(
    client_ipv4: str = "192.168.1.100",
    client_ipv6: str = "::1",
    client_port: int = 12345,
    server_port: int = 5094,
    connect_time: int = 1700000000,
    disconnect_time: int = 1700003600,
    session_status: int = 0x0001,  # WRITES_OCCURRED
    start_config: int = 10,
    end_config: int = 12,
    num_publish: int = 0,
    num_request: int = 50,
    num_response: int = 50,
) -> bytes:
    """Helper to build a raw session log record for testing."""
    ipv4_bytes = ipaddress.IPv4Address(client_ipv4).packed
    ipv6_bytes = ipaddress.IPv6Address(client_ipv6).packed
    return (
        ipv4_bytes
        + ipv6_bytes
        + struct.pack(">HH", client_port, server_port)
        + struct.pack(">Q", connect_time)
        + struct.pack(">Q", disconnect_time)
        + struct.pack(">H", session_status)
        + struct.pack(">HH", start_config, end_config)
        + struct.pack(">III", num_publish, num_request, num_response)
    )


def _build_audit_log_response(
    start_record: int = 0,
    number_of_records: int = 1,
    power_up_time: int = 1700000000,
    last_security_change: int = 1699999000,
    server_status: int = 0,
    session_record_size: int = SESSION_LOG_RECORD_SIZE,
    records: list[bytes] | None = None,
) -> bytes:
    """Helper to build a raw audit log response payload for testing."""
    header = (
        bytes([start_record, number_of_records])
        + struct.pack(">Q", power_up_time)
        + struct.pack(">Q", last_security_change)
        + struct.pack(">H", server_status)
        + struct.pack(">H", session_record_size)
    )
    if records is None:
        records = [_build_session_log_record() for _ in range(number_of_records)]
    return header + b"".join(records)


class TestParseAuditLogResponse:
    """Test parsing Read Audit Log responses."""

    def test_single_record(self):
        payload = _build_audit_log_response(
            number_of_records=1,
            power_up_time=1700000000,
            last_security_change=1699999000,
            server_status=0,
        )
        result = parse_audit_log_response(payload)

        assert result.start_record == 0
        assert result.number_of_records == 1
        assert result.power_up_time == 1700000000
        assert result.last_security_change == 1699999000
        assert result.server_status == 0
        assert result.session_record_size == SESSION_LOG_RECORD_SIZE
        assert len(result.records) == 1

    def test_record_fields(self):
        record_data = _build_session_log_record(
            client_ipv4="10.0.0.1",
            client_port=54321,
            server_port=5094,
            connect_time=1700000000,
            disconnect_time=1700003600,
            session_status=0x0011,  # WRITES_OCCURRED | INSECURE_SESSION
            start_config=10,
            end_config=15,
            num_request=100,
            num_response=100,
        )
        payload = _build_audit_log_response(records=[record_data])
        result = parse_audit_log_response(payload)

        rec = result.records[0]
        assert rec.client_ipv4 == "10.0.0.1"
        assert rec.client_port == 54321
        assert rec.server_port == 5094
        assert rec.connect_time == 1700000000
        assert rec.disconnect_time == 1700003600
        assert rec.start_config_count == 10
        assert rec.end_config_count == 15
        assert rec.num_request_pdu == 100
        assert rec.num_response_pdu == 100

    def test_session_status_flags(self):
        record_data = _build_session_log_record(
            session_status=0x0011,  # WRITES_OCCURRED | INSECURE_SESSION
        )
        payload = _build_audit_log_response(records=[record_data])
        result = parse_audit_log_response(payload)

        rec = result.records[0]
        assert rec.writes_occurred
        assert rec.insecure
        flags = rec.status_flags
        assert HARTIPSessionStatus.WRITES_OCCURRED in flags
        assert HARTIPSessionStatus.INSECURE_SESSION in flags

    def test_server_status_flags(self):
        payload = _build_audit_log_response(
            number_of_records=0,
            server_status=0x0005,
        )
        # With 0 records we need to adjust the helper
        result = parse_audit_log_response(payload)
        flags = result.server_status_flags
        assert HARTIPServerStatus.UNABLE_TO_LOCATE_SYSLOG_SERVER in flags
        assert HARTIPServerStatus.INSECURE_SYSLOG_CONNECTION in flags

    def test_multiple_records(self):
        records = [
            _build_session_log_record(client_ipv4="10.0.0.1", client_port=1001),
            _build_session_log_record(client_ipv4="10.0.0.2", client_port=1002),
            _build_session_log_record(client_ipv4="10.0.0.3", client_port=1003),
        ]
        payload = _build_audit_log_response(number_of_records=3, records=records)
        result = parse_audit_log_response(payload)

        assert len(result.records) == 3
        assert result.records[0].client_ipv4 == "10.0.0.1"
        assert result.records[1].client_ipv4 == "10.0.0.2"
        assert result.records[2].client_ipv4 == "10.0.0.3"
        assert result.records[0].client_port == 1001
        assert result.records[1].client_port == 1002
        assert result.records[2].client_port == 1003

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            parse_audit_log_response(b"\x00" * 10)

    def test_truncated_records_parsed_partially(self):
        """If records are truncated, parse what we can."""
        record = _build_session_log_record()
        # Claim 2 records but only provide 1
        payload = _build_audit_log_response(number_of_records=2, records=[record])
        result = parse_audit_log_response(payload)
        # Should parse 1 of the 2 claimed records
        assert len(result.records) == 1

    def test_zero_records(self):
        payload = _build_audit_log_response(number_of_records=0, records=[])
        result = parse_audit_log_response(payload)
        assert result.number_of_records == 0
        assert len(result.records) == 0

    def test_ipv6_address_parsing(self):
        record_data = _build_session_log_record(
            client_ipv6="fe80::1",
        )
        payload = _build_audit_log_response(records=[record_data])
        result = parse_audit_log_response(payload)
        assert result.records[0].client_ipv6 == "fe80::1"


class TestSessionLogRecord:
    """Test SessionLogRecord dataclass."""

    def test_default_values(self):
        rec = SessionLogRecord()
        assert rec.client_ipv4 == "0.0.0.0"
        assert rec.client_ipv6 == "::"
        assert rec.client_port == 0
        assert not rec.writes_occurred
        assert not rec.insecure

    def test_status_flag_decoding(self):
        rec = SessionLogRecord(session_status=0x0005)  # WRITES | ABORTED
        flags = rec.status_flags
        assert HARTIPSessionStatus.WRITES_OCCURRED in flags
        assert HARTIPSessionStatus.ABORTED_SESSION in flags
        assert rec.writes_occurred


class TestAuditLogResponse:
    """Test AuditLogResponse dataclass."""

    def test_default_values(self):
        resp = AuditLogResponse()
        assert resp.start_record == 0
        assert resp.number_of_records == 0
        assert resp.server_status_flags == HARTIPServerStatus.NONE

    def test_server_status_decoding(self):
        resp = AuditLogResponse(server_status=0x0003)
        flags = resp.server_status_flags
        assert HARTIPServerStatus.UNABLE_TO_LOCATE_SYSLOG_SERVER in flags
        assert HARTIPServerStatus.SYSLOG_CONNECTION_FAILED in flags


# ---------------------------------------------------------------------------
# DirectPDU iteration support
# ---------------------------------------------------------------------------


class TestDirectPDUIteration:
    """Test DirectPDU __iter__, __len__, __getitem__."""

    def test_iterate_over_commands(self):
        pdu = DirectPDU(
            commands=[
                DirectPDUCommand(command_number=0, data=b""),
                DirectPDUCommand(command_number=48, data=b"\x01"),
            ]
        )
        cmd_nums = [cmd.command_number for cmd in pdu]
        assert cmd_nums == [0, 48]

    def test_len(self):
        pdu = DirectPDU(
            commands=[
                DirectPDUCommand(command_number=0),
                DirectPDUCommand(command_number=1),
                DirectPDUCommand(command_number=2),
            ]
        )
        assert len(pdu) == 3

    def test_len_empty(self):
        pdu = DirectPDU()
        assert len(pdu) == 0

    def test_getitem(self):
        pdu = DirectPDU(
            commands=[
                DirectPDUCommand(command_number=0),
                DirectPDUCommand(command_number=48),
            ]
        )
        assert pdu[0].command_number == 0
        assert pdu[1].command_number == 48

    def test_getitem_negative_index(self):
        pdu = DirectPDU(
            commands=[
                DirectPDUCommand(command_number=0),
                DirectPDUCommand(command_number=48),
            ]
        )
        assert pdu[-1].command_number == 48

    def test_getitem_out_of_range(self):
        pdu = DirectPDU(commands=[DirectPDUCommand(command_number=0)])
        with pytest.raises(IndexError):
            _ = pdu[5]


# ---------------------------------------------------------------------------
# Client v2 parameter tests
# ---------------------------------------------------------------------------


class TestClientV2Init:
    """Test HARTIPClient v2 initialization parameters."""

    def test_default_version_is_v1(self):
        from hartip.client import HARTIPClient

        client = HARTIPClient("127.0.0.1")
        assert client.version == HARTIPVersion.V1
        assert not client._use_tls

    def test_v2_tcp_enables_tls(self):
        from hartip.client import HARTIPClient

        client = HARTIPClient("127.0.0.1", protocol="tcp", version=2)
        assert client.version == HARTIPVersion.V2
        assert client._use_tls

    def test_v2_udp_no_tls(self):
        import warnings

        from hartip.client import HARTIPClient

        # DTLS not supported in stdlib, so TLS is not auto-enabled for UDP
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            client = HARTIPClient("127.0.0.1", protocol="udp", version=2)
        assert client.version == HARTIPVersion.V2
        assert not client._use_tls

    def test_explicit_tls_override(self):
        from hartip.client import HARTIPClient

        # Explicitly disable TLS even with v2
        client = HARTIPClient("127.0.0.1", protocol="tcp", version=2, tls=False)
        assert not client._use_tls

        # Explicitly enable TLS with v1
        client = HARTIPClient("127.0.0.1", protocol="tcp", version=1, tls=True)
        assert client._use_tls

    def test_psk_parameters_stored(self):
        from hartip.client import HARTIPClient

        client = HARTIPClient(
            "127.0.0.1",
            protocol="tcp",
            version=2,
            psk_identity="test-client",
            psk_key=b"\x00" * 16,
        )
        assert client.psk_identity == "test-client"
        assert client.psk_key == b"\x00" * 16
