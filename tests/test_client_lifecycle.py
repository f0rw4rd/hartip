"""HARTIPClient connection lifecycle: STARTTLS upgrade, keep-alive, teardown."""

from __future__ import annotations

import ssl
import struct
import threading
from unittest.mock import MagicMock, patch

import pytest

from hartip import client as client_module
from hartip._commands import UNSET
from hartip.client import HARTIPClient
from hartip.constants import HARTIPMessageID
from hartip.exceptions import HARTIPConnectionError, HARTIPTimeoutError, HARTIPTLSError
from hartip.probe import probe_server_version
from hartip.response import HARTIPResponse
from hartip.v2 import DirectPDUCommand

_ADDR = ("127.0.0.1", 5094)


def _answer(request: bytes) -> bytes:
    """Success reply to a session-level request, echoing its id and sequence."""
    msg_id = request[2]
    body = struct.pack(">BI", 1, 30000) if msg_id == HARTIPMessageID.SESSION_INITIATE else b""
    return (
        request[:1]
        + bytes([1, msg_id, 0])
        + request[4:6]
        + (8 + len(body)).to_bytes(2, "big")
        + body
    )


def _udp_responder(sock):
    def recvfrom(_bufsize):
        return _answer(sock.sendto.call_args[0][0]), _ADDR

    return recvfrom


def _tcp_responder(sock):
    buf = bytearray()

    def recv(n):
        if not buf:
            buf.extend(_answer(sock.sendall.call_args[0][0]))
        chunk = bytes(buf[:n])
        del buf[:n]
        return chunk

    return recv


def _sent_ids(method) -> list[int]:
    return [c.args[0][2] for c in method.call_args_list]


class TestStartTLS:
    def test_session_initiate_plaintext_then_upgrade(self) -> None:
        with (
            patch("hartip.client.socket.socket") as sock_cls,
            patch("hartip.client.ssl.SSLContext") as ctx_cls,
        ):
            raw = sock_cls.return_value
            raw.recv.side_effect = _tcp_responder(raw)
            ctx = ctx_cls.return_value
            ctx.check_hostname = False
            tls = MagicMock(spec=ssl.SSLSocket)
            tls.recv.side_effect = _tcp_responder(tls)
            ctx.wrap_socket.return_value = tls

            client = HARTIPClient("127.0.0.1", protocol="tcp", version=2)
            client.connect()
            assert client._socket is tls
            ctx.wrap_socket.assert_called_once_with(raw, server_hostname=None)
            assert _sent_ids(raw.sendall) == [HARTIPMessageID.SESSION_INITIATE]

            client.close()
        assert _sent_ids(tls.sendall) == [HARTIPMessageID.SESSION_CLOSE]
        tls.unwrap.assert_called_once()
        tls.close.assert_called_once()
        assert not client.connected

    def test_upgrade_failure_closes_client(self) -> None:
        with (
            patch("hartip.client.socket.socket") as sock_cls,
            patch("hartip.client.ssl.SSLContext") as ctx_cls,
        ):
            raw = sock_cls.return_value
            raw.recv.side_effect = _tcp_responder(raw)
            ctx = ctx_cls.return_value
            ctx.check_hostname = False
            ctx.wrap_socket.side_effect = ssl.SSLError("no shared cipher")

            client = HARTIPClient("127.0.0.1", protocol="tcp", version=2)
            with pytest.raises(HARTIPTLSError, match="no shared cipher"):
                client.connect()
        assert not client.connected
        assert not client.session_active
        assert client._socket is None
        raw.close.assert_called()

    def test_tcp_connect_failure_closes_socket(self) -> None:
        with patch("hartip.client.socket.socket") as sock_cls:
            raw = sock_cls.return_value
            raw.connect.side_effect = ConnectionRefusedError("refused")
            client = HARTIPClient("127.0.0.1", protocol="tcp")
            with pytest.raises(HARTIPConnectionError, match="Failed to connect"):
                client.connect()
        raw.close.assert_called_once()
        assert not client.connected


class TestKeepAlive:
    def _connect(self, sock_cls, *, on_keepalive=None) -> tuple[HARTIPClient, MagicMock]:
        sock = sock_cls.return_value
        respond = _udp_responder(sock)

        def recvfrom(bufsize):
            reply = respond(bufsize)
            if reply[0][2] == HARTIPMessageID.KEEP_ALIVE and on_keepalive is not None:
                on_keepalive()
            return reply

        sock.recvfrom.side_effect = recvfrom
        client = HARTIPClient("127.0.0.1", auto_keepalive=True, inactivity_timer=20)
        client.connect()
        return client, sock

    def test_sends_keepalives_until_closed(self) -> None:
        seen = []
        enough = threading.Event()

        def on_keepalive():
            seen.append(1)
            if len(seen) >= 2:
                enough.set()

        with patch("hartip.client.socket.socket") as sock_cls:
            client, sock = self._connect(sock_cls, on_keepalive=on_keepalive)
            assert enough.wait(timeout=5)
            client.close()
        assert client._keepalive_thread is None
        ids = _sent_ids(sock.sendto)
        assert ids[0] == HARTIPMessageID.SESSION_INITIATE
        assert ids[-1] == HARTIPMessageID.SESSION_CLOSE
        assert ids.count(HARTIPMessageID.KEEP_ALIVE) >= 2

    def test_failure_stops_thread(self) -> None:
        with patch("hartip.client.socket.socket") as sock_cls:
            client, sock = self._connect(sock_cls)
            thread = client._keepalive_thread
            assert thread is not None
            sock.recvfrom.side_effect = OSError("network down")
            thread.join(timeout=5)
            assert not thread.is_alive()
            client.close()

    def test_inactive_session_stops_thread(self) -> None:
        with patch("hartip.client.socket.socket") as sock_cls:
            client, _sock = self._connect(sock_cls)
            thread = client._keepalive_thread
            assert thread is not None
            client._session_active = False
            thread.join(timeout=5)
            assert not thread.is_alive()
            client.close()

    def test_not_started_without_timer(self) -> None:
        with patch("hartip.client.socket.socket") as sock_cls:
            sock = sock_cls.return_value
            sock.recvfrom.side_effect = _udp_responder(sock)
            client = HARTIPClient("127.0.0.1", auto_keepalive=True, inactivity_timer=0)
            client.connect()
            assert client._keepalive_thread is None
            client.close()


class TestTeardown:
    def test_close_ignores_socket_errors(self) -> None:
        with patch("hartip.client.socket.socket") as sock_cls:
            sock = sock_cls.return_value
            sock.recvfrom.side_effect = _udp_responder(sock)
            client = HARTIPClient("127.0.0.1")
            client.connect()
            sock.close.side_effect = OSError("already closed")
            client.close()
        assert not client.connected

    def test_tls_shutdown_error_still_closes(self) -> None:
        tls = MagicMock(spec=ssl.SSLSocket)
        tls.unwrap.side_effect = ssl.SSLError("bad shutdown")
        client_module._close_socket(tls)
        tls.close.assert_called_once()

    def test_exchange_without_socket(self) -> None:
        client = HARTIPClient("127.0.0.1")
        with pytest.raises(HARTIPConnectionError, match="Not connected"):
            client._send_recv_unlocked(bytes(8))

    def test_udp_resolution_failure(self) -> None:
        client = HARTIPClient("host.invalid")
        with (
            patch("hartip._transport.socket.getaddrinfo", side_effect=OSError("no such host")),
            pytest.raises(HARTIPConnectionError, match="no such host"),
        ):
            client.connect()
        assert not client.connected


class TestCompatibleImports:
    def test_names_still_importable_from_client(self) -> None:
        assert client_module.HARTIPResponse is HARTIPResponse
        assert client_module.probe_server_version is probe_server_version
        assert client_module._UNSET is UNSET


def _pdu_reply(request: bytes, response_code: int) -> bytes:
    """Pass-through reply echoing the command of *request* with *response_code*."""
    # No preambles: delimiter, 1- or 5-byte address, then the command.
    command = request[10] if request[8] == 0x02 else request[14]
    data = bytes([response_code, 0])
    pdu = bytes([0x06, 0x80, command, len(data)]) + data
    pdu += bytes([_xor(pdu)])
    return request[:1] + bytes([1, 3, 0]) + request[4:6] + (8 + len(pdu)).to_bytes(2, "big") + pdu


def _xor(data: bytes) -> int:
    out = 0
    for b in data:
        out ^= b
    return out


def _connected_udp(sock_cls, reply_rc: int = 0, **kwargs) -> tuple[HARTIPClient, MagicMock]:
    sock = sock_cls.return_value

    def recvfrom(_bufsize):
        request = sock.sendto.call_args[0][0]
        if request[2] == HARTIPMessageID.HART_PDU:
            return _pdu_reply(request, reply_rc), _ADDR
        return _answer(request), _ADDR

    sock.recvfrom.side_effect = recvfrom
    client = HARTIPClient("127.0.0.1", **kwargs)
    client.connect()
    return client, sock


class TestRequests:
    def test_wrapper_sends_its_command(self) -> None:
        with patch("hartip.client.socket.socket") as sock_cls:
            client, sock = _connected_udp(sock_cls)
            assert client.perform_self_test().success
            request = sock.sendto.call_args_list[-1].args[0]
            client.close()
        assert request[8:11] == bytes([0x02, 0x80, 41])  # delimiter, address, command

    def test_delayed_response_backs_off_then_gives_up(self) -> None:
        with (
            patch("hartip.client.socket.socket") as sock_cls,
            patch("hartip.client.time.sleep") as sleep,
        ):
            client, sock = _connected_udp(sock_cls, reply_rc=32, dr_retries=4, dr_retry_delay=10)
            resp = client.read_primary_variable()
            client.close()
        assert resp.response_code == 32
        assert [c.args[0] for c in sleep.call_args_list] == [0.01, 0.01, 0.02, 0.04]
        assert _sent_ids(sock.sendto).count(HARTIPMessageID.HART_PDU) == 5

    def test_delayed_response_without_retries(self) -> None:
        with patch("hartip.client.socket.socket") as sock_cls:
            client, _sock = _connected_udp(sock_cls, reply_rc=32, dr_retries=0)
            with pytest.raises(HARTIPTimeoutError, match="retry limit"):
                client.read_primary_variable()
            client.close()

    def test_direct_pdu_round_trip(self) -> None:
        with patch("hartip.client.socket.socket") as sock_cls:
            sock = sock_cls.return_value

            def recvfrom(_bufsize):
                request = sock.sendto.call_args[0][0]
                if request[2] != HARTIPMessageID.DIRECT_PDU:
                    return _answer(request), _ADDR
                # device status, extended status, then command 0 with rc 0, status 0x40
                body = bytes.fromhex("00000000020040")
                header = request[:1] + bytes([1, 4, 0]) + request[4:6]
                return header + (8 + len(body)).to_bytes(2, "big") + body, _ADDR

            sock.recvfrom.side_effect = recvfrom
            with pytest.warns(UserWarning, match="DTLS"):
                client = HARTIPClient("127.0.0.1", version=2)
            client.connect()
            result = client.send_direct_pdu([DirectPDUCommand(command_number=0)])
            client.close()
        assert [c.command_number for c in result.commands] == [0]
        assert result.commands[0].response_code == 0
