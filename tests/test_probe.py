"""Unit tests for hartip.probe.probe_server_version."""

from __future__ import annotations

import socket
import struct
from unittest.mock import MagicMock, patch

import pytest

from hartip import probe_server_version
from hartip.constants import HARTIPMessageID, HARTIPStatus
from hartip.exceptions import HARTFrameError, HARTIPConnectionError, HARTIPTimeoutError


def _reply(
    version: int = 2, status: int = 0, msg_id: int = 0, sequence: int = 1, body: bytes = b""
) -> bytes:
    """A Session Initiate response: header (msg_type 1) plus *body*."""
    return struct.pack(">BBBBHH", version, 1, msg_id, status, sequence, 8 + len(body)) + body


# Session Initiate response body: master type, inactivity timer (ms).
_INIT_BODY = bytes.fromhex("01 0000ea60")


def _stream(data: bytes):
    """``recv`` side effect serving *data*, then EOF."""
    buf = bytearray(data)

    def recv(n: int) -> bytes:
        chunk = bytes(buf[:n])
        del buf[:n]
        return chunk

    return recv


@pytest.fixture
def sock():
    with patch("hartip.probe.socket.socket") as sock_cls:
        yield sock_cls.return_value


class TestProbe:
    def test_v2_server(self, sock) -> None:
        sock.recv.side_effect = _stream(_reply(version=2, body=_INIT_BODY))
        assert probe_server_version("10.0.0.1", 5094, timeout=1.0) == 2
        sock.settimeout.assert_called_once_with(1.0)
        sock.connect.assert_called_once_with(("10.0.0.1", 5094))
        init, close = (c.args[0] for c in sock.sendall.call_args_list)
        assert init[:6] == bytes([2, 0, HARTIPMessageID.SESSION_INITIATE, 0, 0, 1])
        assert close[:6] == bytes([2, 0, HARTIPMessageID.SESSION_CLOSE, 0, 0, 2])
        sock.close.assert_called_once()

    def test_v1_server_refuses_security(self, sock) -> None:
        sock.recv.side_effect = _stream(
            _reply(version=1, status=HARTIPStatus.ERROR_SECURITY_NOT_INITIALIZED)
        )
        assert probe_server_version("10.0.0.1") == 1

    def test_v1_server_answering_success(self, sock) -> None:
        sock.recv.side_effect = _stream(_reply(version=1, body=_INIT_BODY))
        assert probe_server_version("10.0.0.1") == 1

    def test_short_body_is_harmless(self, sock) -> None:
        """EOF while draining the body still yields the verdict from the header."""
        sock.recv.side_effect = _stream(_reply(body=_INIT_BODY)[:10])
        assert probe_server_version("10.0.0.1") == 2

    def test_header_split_across_reads(self, sock) -> None:
        data = _reply(body=_INIT_BODY)
        chunks = [data[:3], data[3:8], data[8:], b""]
        sock.recv.side_effect = lambda _n: chunks.pop(0)
        assert probe_server_version("10.0.0.1") == 2

    @pytest.mark.parametrize(
        ("msg_id", "sequence"),
        [(HARTIPMessageID.KEEP_ALIVE, 1), (HARTIPMessageID.SESSION_INITIATE, 7)],
    )
    def test_reply_to_something_else(self, sock, msg_id, sequence) -> None:
        sock.recv.side_effect = _stream(_reply(msg_id=msg_id, sequence=sequence))
        with pytest.raises(HARTFrameError, match="Unexpected reply to version probe"):
            probe_server_version("10.0.0.1")
        sock.close.assert_called_once()

    def test_eof_before_header(self, sock) -> None:
        sock.recv.side_effect = _stream(b"\x02\x01")
        with pytest.raises(HARTIPConnectionError, match="Connection closed"):
            probe_server_version("10.0.0.1")
        sock.close.assert_called_once()

    def test_timeout(self, sock) -> None:
        sock.recv.side_effect = TimeoutError()
        with pytest.raises(HARTIPTimeoutError, match="timed out"):
            probe_server_version("10.0.0.1")
        sock.close.assert_called_once()

    def test_socket_error_while_probing(self, sock) -> None:
        sock.sendall.side_effect = ConnectionResetError("reset")
        with pytest.raises(HARTIPConnectionError, match="Version probe failed"):
            probe_server_version("10.0.0.1")
        sock.close.assert_called_once()

    def test_connect_refused(self, sock) -> None:
        sock.connect.side_effect = ConnectionRefusedError("refused")
        with pytest.raises(HARTIPConnectionError, match=r"Failed to connect to 10\.0\.0\.1:5094"):
            probe_server_version("10.0.0.1")
        sock.close.assert_called_once()
        sock.sendall.assert_not_called()

    def test_close_frame_failure_ignored(self, sock) -> None:
        sock.recv.side_effect = _stream(_reply(body=_INIT_BODY))
        sock.sendall.side_effect = [None, BrokenPipeError()]
        assert probe_server_version("10.0.0.1") == 2
        sock.close.assert_called_once()

    def test_creates_tcp_socket(self) -> None:
        with patch("hartip.probe.socket.socket") as sock_cls:
            sock_cls.return_value = MagicMock()
            sock_cls.return_value.recv.side_effect = _stream(_reply())
            probe_server_version("10.0.0.1")
        sock_cls.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
