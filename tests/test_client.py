"""Tests for HART-IP client (unit tests with mocked sockets)."""

import struct
from unittest.mock import MagicMock, patch

import pytest

from hartip.client import HARTIPClient, HARTIPResponse
from hartip.constants import HARTIP_HEADER_SIZE, HARTFrameType, HARTIPMessageType, HARTIPStatus
from hartip.device import DeviceInfo, Variable, parse_cmd0, parse_cmd1, parse_cmd3
from hartip.exceptions import HARTIPConnectionError, HARTIPStatusError
from hartip.protocol import HARTIPHeader, build_pdu, xor_checksum


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_session_init_response(status: int = 0) -> bytes:
    """Build a synthetic Session Initiate response."""
    payload = struct.pack(">BI", 1, 30000)
    total = HARTIP_HEADER_SIZE + len(payload)
    hdr = HARTIPHeader.build(
        dict(
            version=1,
            msg_type=HARTIPMessageType.RESPONSE,
            msg_id=0,
            status=status,
            sequence=1,
            byte_count=total,
        )
    )
    return hdr + payload


def _build_session_close_response() -> bytes:
    """Build a synthetic Session Close response."""
    return HARTIPHeader.build(
        dict(
            version=1,
            msg_type=HARTIPMessageType.RESPONSE,
            msg_id=1,
            status=0,
            sequence=1,
            byte_count=HARTIP_HEADER_SIZE,
        )
    )


def _build_mock_response(
    command: int = 0,
    response_code: int = 0,
    device_status: int = 0,
    payload: bytes = b"",
    status: int = 0,
) -> bytes:
    """Build a synthetic HART-IP command response for testing."""
    data = bytes([response_code, device_status]) + payload
    pdu = build_pdu(HARTFrameType.SHORT_FRAME, b"\x00", command, data)
    total = HARTIP_HEADER_SIZE + len(pdu)
    hdr = HARTIPHeader.build(
        dict(
            version=1,
            msg_type=HARTIPMessageType.RESPONSE,
            msg_id=3,
            status=status,
            sequence=1,
            byte_count=total,
        )
    )
    return hdr + pdu


_ADDR = ("127.0.0.1", 5094)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHARTIPResponse:
    def test_success(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None, response_code=0)
        assert resp.success

    def test_failure(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None, response_code=1)
        assert not resp.success
        assert resp.error_message == "UNDEFINED_COMMAND"


class TestHARTIPClient:
    def test_context_manager(self) -> None:
        session_resp = _build_session_init_response()
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session_resp, _ADDR),
                (close_resp, _ADDR),
            ]
            with HARTIPClient("127.0.0.1", protocol="udp") as client:
                assert client.connected
                assert client.session_active
            assert not client.connected
            assert not client.session_active

    def test_connect_failure(self) -> None:
        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = OSError("refused")
            mock_sock_cls.return_value = mock_sock
            client = HARTIPClient("127.0.0.1", protocol="tcp")
            with pytest.raises(HARTIPConnectionError):
                client.connect()

    def test_session_init_failure(self) -> None:
        session_resp = _build_session_init_response(status=HARTIPStatus.INVALID_SESSION)

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session_resp, _ADDR),
            ]
            client = HARTIPClient("127.0.0.1", protocol="udp")
            with pytest.raises(HARTIPConnectionError, match="Session initiate failed"):
                client.connect()

    def test_send_command_udp(self) -> None:
        session_resp = _build_session_init_response()
        cmd_resp = _build_mock_response(command=0, payload=b"\x00" * 12)
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session_resp, _ADDR),
                (cmd_resp, _ADDR),
                (close_resp, _ADDR),
            ]

            client = HARTIPClient("127.0.0.1", protocol="udp")
            client.connect()
            resp = client.send_command(0)
            assert resp.response_code == 0
            client.close()

    def test_send_command_requires_session(self) -> None:
        client = HARTIPClient("127.0.0.1", protocol="udp")
        with pytest.raises(HARTIPConnectionError, match="Not connected"):
            client.send_command(0)

    def test_status_error_raised(self) -> None:
        session_resp = _build_session_init_response()
        cmd_resp = _build_mock_response(status=HARTIPStatus.BUFFER_OVERFLOW)
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session_resp, _ADDR),
                (cmd_resp, _ADDR),
                (close_resp, _ADDR),
            ]

            client = HARTIPClient("127.0.0.1", protocol="udp")
            client.connect()
            with pytest.raises(HARTIPStatusError):
                client.send_command(0)
            client.close()

    def test_sequence_wraps(self) -> None:
        client = HARTIPClient("127.0.0.1")
        client._sequence = 0xFFFE
        assert client._next_sequence() == 0xFFFF
        assert client._next_sequence() == 0x0000


class TestParseCmd0:
    def test_legacy_format(self) -> None:
        # Standard 12-byte Command 0 response
        payload = bytes(
            [
                0x00,  # expansion code
                0x26,  # manufacturer_id = Rosemount
                0x01,  # device_type
                0x05,  # num_preambles
                0x05,  # hart_revision
                0x03,  # device_revision
                0x02,  # software_revision
                0x10,  # hardware_revision(5b) | physical_signaling(3b)
                0x00,  # flags
                0x01,
                0x02,
                0x03,  # device_id (24-bit)
            ]
        )
        info = parse_cmd0(payload)
        assert info.manufacturer_id == 0x26
        assert "Rosemount" in info.manufacturer_name
        assert info.device_id == 0x010203
        assert info.hart_revision == 5

    def test_hart7_extended(self) -> None:
        # HART 7 response with extended fields (expansion code 254)
        payload = bytes(
            [
                254,  # expansion code (HART 7)
                0x03,  # manufacturer_id
                0x02,  # device_type
                0x05,  # num_preambles
                0x07,  # hart_revision = 7
                0x10,  # device_revision
                0x05,  # software_revision
                0x28,  # hardware_revision(5b) | physical_signaling(3b)
                0x00,  # flags
                0x00,
                0xAB,
                0xCD,  # device_id
                0x05,  # num_response_preambles
                0x03,  # max_device_vars
                0x00,
                0x01,  # config_change_counter
                0x00,  # extended_field_device_status
            ]
        )
        info = parse_cmd0(payload)
        assert info.manufacturer_id == 3
        assert info.device_id == 0x00ABCD
        assert info.hart_revision == 7
        assert info.num_response_preambles == 5
        assert info.config_change_counter == 1

    def test_too_short(self) -> None:
        info = parse_cmd0(b"\x00\x01")
        assert info.manufacturer_id == 0


class TestParseCmd1:
    def test_valid(self) -> None:
        # unit=7 (bar), value=1.5
        payload = bytes([7]) + struct.pack(">f", 1.5)
        var = parse_cmd1(payload)
        assert var is not None
        assert var.unit_code == 7
        assert var.unit_name == "bar"
        assert abs(var.value - 1.5) < 0.001

    def test_too_short(self) -> None:
        assert parse_cmd1(b"\x07\x00") is None


class TestParseCmd3:
    def test_four_variables(self) -> None:
        payload = struct.pack(">f", 4.0)  # current
        for unit, val in [(7, 1.0), (32, 25.0), (57, 50.0), (39, 4.0)]:
            payload += bytes([unit]) + struct.pack(">f", val)
        variables = parse_cmd3(payload)
        assert len(variables) == 4
        assert variables[0].label == "PV"
        assert variables[0].unit_name == "bar"
        assert variables[1].label == "SV"
        assert variables[1].unit_name == "degC"
