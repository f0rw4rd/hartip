"""Tests for HART-IP client (unit tests with mocked sockets)."""

import struct
import threading
import time
import warnings
from unittest.mock import MagicMock, patch

import pytest

from hartip.client import HARTIPClient, HARTIPResponse
from hartip.constants import (
    HARTIP_HEADER_SIZE,
    HARTIP_V2_PSK_CIPHERS,
    HARTFrameType,
    HARTIPMessageType,
    HARTIPStatus,
    HARTResponseCode,
)
from hartip.device import DeviceInfo, Variable, parse_cmd0, parse_cmd1, parse_cmd3
from hartip.exceptions import (
    HARTCommunicationError,
    HARTIPConnectionError,
    HARTIPStatusError,
    HARTIPTLSError,
    HARTResponseError,
)
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
        session_resp = _build_session_init_response(status=HARTIPStatus.ERROR_TOO_FEW_DATA_BYTES)

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
        cmd_resp = _build_mock_response(status=HARTIPStatus.WARNING_SET_TO_NEAREST_VALUE)
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
        result = parse_cmd3(payload)
        assert result["loop_current"] == 4.0
        variables = result["variables"]
        assert len(variables) == 4
        assert variables[0].label == "PV"
        assert variables[0].unit_name == "bar"
        assert variables[1].label == "SV"
        assert variables[1].unit_name == "degC"


# ---------------------------------------------------------------------------
# HARTIPResponse – new comm_error field
# ---------------------------------------------------------------------------


class TestHARTIPResponseCommError:
    def test_comm_error_not_success(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None, response_code=0x90, comm_error=True)
        assert resp.comm_error is True
        assert resp.success is False

    def test_comm_error_message(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None, response_code=0xC0, comm_error=True)
        assert "Communication error" in resp.error_message

    def test_no_comm_error_success(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None, response_code=0, comm_error=False)
        assert resp.success is True
        assert resp.comm_error is False

    def test_unknown_error_code(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None, response_code=250)
        assert "Unknown error code" in resp.error_message


# ---------------------------------------------------------------------------
# Client – double-connect closes existing socket
# ---------------------------------------------------------------------------


class TestDoubleConnect:
    def test_close_called_on_reconnect(self) -> None:
        session_resp = _build_session_init_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock1 = MagicMock()
            mock_sock2 = MagicMock()
            mock_sock_cls.side_effect = [mock_sock1, mock_sock2]
            mock_sock1.recvfrom.return_value = (session_resp, _ADDR)
            mock_sock2.recvfrom.return_value = (session_resp, _ADDR)

            client = HARTIPClient("127.0.0.1", protocol="udp")
            client.connect()
            assert client.connected
            client.connect()  # Should close old socket first
            mock_sock1.close.assert_called()


# ---------------------------------------------------------------------------
# Client – use_long_frame without unique_addr
# ---------------------------------------------------------------------------


class TestUseLongFrame:
    def test_raises_without_unique_addr(self) -> None:
        session_resp = _build_session_init_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.return_value = (session_resp, _ADDR)

            client = HARTIPClient("127.0.0.1", protocol="udp")
            client.connect()
            with pytest.raises(ValueError, match="unique_addr"):
                client.send_command(0, use_long_frame=True)

    def test_works_with_unique_addr(self) -> None:
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
            addr = bytes([0x80, 0x26, 0x01, 0x02, 0x03])
            resp = client.send_command(0, use_long_frame=True, unique_addr=addr)
            assert resp.response_code == 0
            client.close()


# ---------------------------------------------------------------------------
# Client – extended command (cmd > 253)
# ---------------------------------------------------------------------------


class TestExtendedCommand:
    def test_cmd_768_wrapped_in_cmd_31(self) -> None:
        session_resp = _build_session_init_response()
        cmd_resp = _build_mock_response(command=31, payload=b"\x00" * 4)
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
            resp = client.send_command(768)  # Should wrap in cmd 31
            # Verify the sent frame contains command 31
            sent_frame = mock_sock.sendto.call_args_list[-1][0][0]
            pdu_bytes = sent_frame[HARTIP_HEADER_SIZE:]
            # pdu_bytes: delimiter(1) + addr(1) + cmd(1) + bc(1) + data + cksum(1)
            assert pdu_bytes[2] == 31  # wire command is 31
            # First 2 data bytes should be 0x0300 (768 big-endian)
            data_start = 4  # after delimiter, addr, cmd, byte_count
            assert pdu_bytes[data_start] == 0x03
            assert pdu_bytes[data_start + 1] == 0x00
            client.close()


# ---------------------------------------------------------------------------
# Client – communication error detection
# ---------------------------------------------------------------------------


class TestCommErrorDetection:
    def test_comm_error_in_response(self) -> None:
        session_resp = _build_session_init_response()
        # Build response with MSB set in response code byte
        cmd_resp = _build_mock_response(command=0, response_code=0xC0)
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
            assert resp.comm_error is True
            assert resp.response_code == 0xC0
            assert not resp.success
            client.close()


# ---------------------------------------------------------------------------
# Client – convenience wrappers
# ---------------------------------------------------------------------------


class TestConvenienceMethods:
    def _make_connected_client(self, mock_sock):
        session_resp = _build_session_init_response()
        mock_sock.recvfrom.side_effect = [
            (session_resp, _ADDR),
        ]
        client = HARTIPClient("127.0.0.1", protocol="udp")
        client.connect()
        return client

    def test_read_unique_id(self) -> None:
        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            client = self._make_connected_client(mock_sock)
            cmd_resp = _build_mock_response(command=0, payload=b"\x00" * 12)
            mock_sock.recvfrom.side_effect = [(cmd_resp, _ADDR)]
            resp = client.read_unique_id()
            assert resp.response_code == 0

    def test_read_primary_variable(self) -> None:
        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            client = self._make_connected_client(mock_sock)
            cmd_resp = _build_mock_response(command=1, payload=bytes([7]) + struct.pack(">f", 1.5))
            mock_sock.recvfrom.side_effect = [(cmd_resp, _ADDR)]
            resp = client.read_primary_variable()
            assert resp.response_code == 0

    def test_read_device_vars_status(self) -> None:
        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            client = self._make_connected_client(mock_sock)
            cmd_resp = _build_mock_response(command=9, payload=b"\x00" * 9)
            mock_sock.recvfrom.side_effect = [(cmd_resp, _ADDR)]
            resp = client.read_device_vars_status()
            assert resp.response_code == 0

    def test_read_message(self) -> None:
        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            client = self._make_connected_client(mock_sock)
            cmd_resp = _build_mock_response(command=12, payload=b"\x00" * 24)
            mock_sock.recvfrom.side_effect = [(cmd_resp, _ADDR)]
            resp = client.read_message()
            assert resp.response_code == 0

    def test_read_pv_info(self) -> None:
        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            client = self._make_connected_client(mock_sock)
            cmd_resp = _build_mock_response(command=14, payload=b"\x00" * 16)
            mock_sock.recvfrom.side_effect = [(cmd_resp, _ADDR)]
            resp = client.read_pv_info()
            assert resp.response_code == 0


# ---------------------------------------------------------------------------
# Client – delayed-response retry
# ---------------------------------------------------------------------------


class TestDelayedResponse:
    def test_dr_retry_succeeds(self) -> None:
        session_resp = _build_session_init_response()
        # First response: DR_RUNNING (code 34)
        dr_resp = _build_mock_response(command=0, response_code=34, payload=b"\x00" * 12)
        # Second response: success
        ok_resp = _build_mock_response(command=0, response_code=0, payload=b"\x00" * 12)
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session_resp, _ADDR),
                (dr_resp, _ADDR),     # initial command → DR
                (ok_resp, _ADDR),     # retry → success
                (close_resp, _ADDR),
            ]

            client = HARTIPClient(
                "127.0.0.1", protocol="udp",
                dr_retries=5, dr_retry_delay=1,  # 1ms delay for testing
            )
            client.connect()
            resp = client.send_command(0)
            assert resp.response_code == 0
            assert resp.success
            client.close()


# ---------------------------------------------------------------------------
# HARTIPResponse – __repr__
# ---------------------------------------------------------------------------


class TestHARTIPResponseRepr:
    def test_repr_with_pdu(self) -> None:
        class FakePdu:
            command = 0
        resp = HARTIPResponse(header=None, pdu=FakePdu(), response_code=0, payload=b"\x01\x02")
        r = repr(resp)
        assert "cmd=0" in r
        assert "rc=0" in r
        assert "2B" in r

    def test_repr_without_pdu(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None, response_code=0)
        r = repr(resp)
        assert "cmd=?" in r

    def test_repr_error(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None, response_code=1)
        r = repr(resp)
        assert "UNDEFINED_COMMAND" in r

    def test_repr_comm_error(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None, response_code=0xC0, comm_error=True)
        r = repr(resp)
        assert "Communication error" in r


# ---------------------------------------------------------------------------
# HARTIPResponse – raise_for_error
# ---------------------------------------------------------------------------


class TestRaiseForError:
    def test_success_does_not_raise(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None, response_code=0)
        resp.raise_for_error()  # should not raise

    def test_comm_error_raises_communication_error(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None, response_code=0xC0, comm_error=True)
        with pytest.raises(HARTCommunicationError) as exc_info:
            resp.raise_for_error()
        assert exc_info.value.flags == 0xC0

    def test_response_code_raises_response_error(self) -> None:
        class FakePdu:
            command = 48
        resp = HARTIPResponse(header=None, pdu=FakePdu(), response_code=1)
        with pytest.raises(HARTResponseError) as exc_info:
            resp.raise_for_error()
        assert exc_info.value.code == 1
        assert exc_info.value.command == 48

    def test_response_error_without_pdu(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None, response_code=5)
        with pytest.raises(HARTResponseError) as exc_info:
            resp.raise_for_error()
        assert exc_info.value.code == 5


# ---------------------------------------------------------------------------
# HARTIPResponse – error_code property
# ---------------------------------------------------------------------------


class TestErrorCodeProperty:
    def test_known_code(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None, response_code=1)
        assert resp.error_code == HARTResponseCode.UNDEFINED_COMMAND

    def test_unknown_code(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None, response_code=250)
        assert resp.error_code is None

    def test_success_code(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None, response_code=0)
        assert resp.error_code == HARTResponseCode.SUCCESS

    def test_comm_error_returns_none(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None, response_code=0x80, comm_error=True)
        assert resp.error_code is None


# ---------------------------------------------------------------------------
# Client – __repr__ (credential safety)
# ---------------------------------------------------------------------------


class TestClientRepr:
    def test_repr_basic(self) -> None:
        client = HARTIPClient("192.168.1.1")
        r = repr(client)
        assert "192.168.1.1" in r
        assert "udp" in r

    def test_repr_with_tls(self) -> None:
        client = HARTIPClient("192.168.1.1", protocol="tcp", version=2)
        r = repr(client)
        assert "tls=True" in r

    def test_repr_redacts_psk_key(self) -> None:
        client = HARTIPClient(
            "192.168.1.1",
            protocol="tcp",
            version=2,
            psk_identity="admin",
            psk_key=b"\x00" * 16,
        )
        r = repr(client)
        assert "admin" in r
        assert "psk_key=<redacted>" in r
        assert b"\x00".hex() not in r  # ensure actual key bytes are not in repr

    def test_repr_no_tls_no_psk(self) -> None:
        client = HARTIPClient("10.0.0.1", protocol="udp", version=1)
        r = repr(client)
        assert "tls" not in r
        assert "psk" not in r


# ---------------------------------------------------------------------------
# Client – warnings
# ---------------------------------------------------------------------------


class TestClientWarnings:
    def test_v2_udp_dtls_warning(self) -> None:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            HARTIPClient("127.0.0.1", protocol="udp", version=2)
            assert len(w) == 1
            assert "DTLS" in str(w[0].message)

    def test_ssl_context_with_psk_warning(self) -> None:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            HARTIPClient(
                "127.0.0.1",
                protocol="tcp",
                version=2,
                psk_identity="test",
                psk_key=b"\x00" * 16,
                ssl_context=ctx,
            )
            # Should have both the ssl_context+psk warning
            psk_warnings = [x for x in w if "psk_identity" in str(x.message)]
            assert len(psk_warnings) == 1

    def test_no_warning_normal_usage(self) -> None:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            HARTIPClient("127.0.0.1", protocol="udp", version=1)
            assert len(w) == 0


# ---------------------------------------------------------------------------
# Client – TLS error wrapping
# ---------------------------------------------------------------------------


class TestTLSErrorWrapping:
    def test_tls_handshake_failure_raises_tls_error(self) -> None:
        """TLS handshake failure should raise HARTIPTLSError, not HARTIPConnectionError."""
        import ssl

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            # Make wrap_socket raise SSLError
            with patch("hartip.client.ssl.SSLContext") as mock_ctx_cls:
                mock_ctx = MagicMock()
                mock_ctx_cls.return_value = mock_ctx
                mock_ctx.check_hostname = False
                mock_ctx.wrap_socket.side_effect = ssl.SSLError("handshake failed")

                client = HARTIPClient("127.0.0.1", protocol="tcp", tls=True)
                with pytest.raises(HARTIPTLSError, match="handshake failed"):
                    client.connect()

    def test_tls_error_caught_by_connection_error(self) -> None:
        """HARTIPTLSError should be catchable as HARTIPConnectionError."""
        import ssl

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            with patch("hartip.client.ssl.SSLContext") as mock_ctx_cls:
                mock_ctx = MagicMock()
                mock_ctx_cls.return_value = mock_ctx
                mock_ctx.check_hostname = False
                mock_ctx.wrap_socket.side_effect = ssl.SSLError("bad cert")

                client = HARTIPClient("127.0.0.1", protocol="tcp", tls=True)
                with pytest.raises(HARTIPConnectionError):
                    client.connect()


# ---------------------------------------------------------------------------
# Client – ciphers parameter
# ---------------------------------------------------------------------------


class TestCiphersParameter:
    def test_custom_ciphers_stored(self) -> None:
        client = HARTIPClient(
            "127.0.0.1",
            protocol="tcp",
            version=2,
            ciphers=HARTIP_V2_PSK_CIPHERS,
        )
        assert client._ciphers == HARTIP_V2_PSK_CIPHERS

    def test_default_ciphers_is_none(self) -> None:
        client = HARTIPClient("127.0.0.1")
        assert client._ciphers is None


# ---------------------------------------------------------------------------
# Client – convenience methods with unique_addr
# ---------------------------------------------------------------------------


class TestConvenienceUniqueAddr:
    def _make_connected_client(self, mock_sock):
        session_resp = _build_session_init_response()
        mock_sock.recvfrom.side_effect = [
            (session_resp, _ADDR),
        ]
        client = HARTIPClient("127.0.0.1", protocol="udp")
        client.connect()
        return client

    def test_read_unique_id_with_unique_addr(self) -> None:
        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            client = self._make_connected_client(mock_sock)
            cmd_resp = _build_mock_response(command=0, payload=b"\x00" * 12)
            mock_sock.recvfrom.side_effect = [(cmd_resp, _ADDR)]
            addr = bytes([0x80, 0x26, 0x01, 0x02, 0x03])
            resp = client.read_unique_id(unique_addr=addr)
            assert resp.response_code == 0


# ---------------------------------------------------------------------------
# Client – send_command auto-detect long frame
# ---------------------------------------------------------------------------


class TestAutoDetectLongFrame:
    def test_unique_addr_implies_long_frame(self) -> None:
        """Passing unique_addr without use_long_frame=True should still use long frame."""
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
            addr = bytes([0x80, 0x26, 0x01, 0x02, 0x03])
            resp = client.send_command(0, unique_addr=addr)
            assert resp.response_code == 0
            client.close()


# ---------------------------------------------------------------------------
# Client – cert_validator callback
# ---------------------------------------------------------------------------


class TestCertValidator:
    def test_validator_accepted(self) -> None:
        """cert_validator returning True should allow the connection."""
        calls = []

        def _accept(cert):
            calls.append(cert)
            return True

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            with patch("hartip.client.ssl.SSLContext") as mock_ctx_cls:
                mock_ctx = MagicMock()
                mock_ctx_cls.return_value = mock_ctx
                mock_ctx.check_hostname = False
                tls_sock = MagicMock()
                tls_sock.getpeercert.return_value = {"subject": "test"}
                mock_ctx.wrap_socket.return_value = tls_sock
                # Make session init succeed
                session_resp = _build_session_init_response()
                tls_sock.recv.return_value = session_resp

                client = HARTIPClient(
                    "127.0.0.1", protocol="tcp", tls=True, cert_validator=_accept
                )
                client.connect()
                assert len(calls) == 1
                assert calls[0] == {"subject": "test"}
                client.close()

    def test_validator_rejected_false(self) -> None:
        """cert_validator returning False should raise HARTIPTLSError."""

        def _reject(_cert):
            return False

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            with patch("hartip.client.ssl.SSLContext") as mock_ctx_cls:
                mock_ctx = MagicMock()
                mock_ctx_cls.return_value = mock_ctx
                mock_ctx.check_hostname = False
                tls_sock = MagicMock()
                tls_sock.getpeercert.return_value = {"subject": "bad"}
                mock_ctx.wrap_socket.return_value = tls_sock

                client = HARTIPClient(
                    "127.0.0.1", protocol="tcp", tls=True, cert_validator=_reject
                )
                with pytest.raises(HARTIPTLSError, match="rejected by cert_validator"):
                    client.connect()
                tls_sock.close.assert_called()

    def test_validator_raises_exception(self) -> None:
        """cert_validator raising should wrap in HARTIPTLSError."""

        def _crash(_cert):
            raise ValueError("fingerprint mismatch")

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            with patch("hartip.client.ssl.SSLContext") as mock_ctx_cls:
                mock_ctx = MagicMock()
                mock_ctx_cls.return_value = mock_ctx
                mock_ctx.check_hostname = False
                tls_sock = MagicMock()
                tls_sock.getpeercert.return_value = {}
                mock_ctx.wrap_socket.return_value = tls_sock

                client = HARTIPClient(
                    "127.0.0.1", protocol="tcp", tls=True, cert_validator=_crash
                )
                with pytest.raises(HARTIPTLSError, match="fingerprint mismatch"):
                    client.connect()
                tls_sock.close.assert_called()

    def test_no_validator_by_default(self) -> None:
        """Without cert_validator, no post-handshake check runs."""
        client = HARTIPClient("127.0.0.1")
        assert client._cert_validator is None
