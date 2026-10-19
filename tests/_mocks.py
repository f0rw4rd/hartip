"""Socket fakes shared by the unit tests.

Scripted replies are stamped with the sequence number of the frame the
client sent last, the way a real server echoes it.  Tests that need a
specific (for example stale) sequence number build the reply themselves
and skip these helpers.
"""

from __future__ import annotations

from collections.abc import Iterable


def restamp(reply: bytes, request: bytes | None) -> bytes:
    """Return *reply* with the sequence number of *request* (bytes 4-5)."""
    if request is None or len(reply) < 8 or len(request) < 8:
        return reply
    return reply[:4] + request[4:6] + reply[6:]


def _last_sent(method) -> bytes | None:
    if method.call_args is None:
        return None
    return method.call_args[0][0]


def echo_seq(sock, replies: Iterable):
    """``recvfrom`` side effect for a mocked UDP socket.

    *replies* yields ``(frame, addr)`` tuples or exceptions to raise.
    """
    it = iter(replies)

    def _recvfrom(_bufsize):
        item = next(it)
        if isinstance(item, BaseException) or (
            isinstance(item, type) and issubclass(item, BaseException)
        ):
            raise item
        frame, addr = item
        return restamp(frame, _last_sent(sock.sendto)), addr

    return _recvfrom


def tcp_echo_seq(sock, frames: Iterable[bytes]):
    """``recv`` side effect for a mocked TCP socket.

    Serves *frames* as a byte stream, honouring the requested size, and
    stamps each frame with the sequence number of the last ``sendall``.
    """
    it = iter(frames)
    buf = bytearray()

    def _recv(n):
        if not buf:
            frame = next(it, None)
            if frame is None:
                return b""
            buf.extend(restamp(frame, _last_sent(sock.sendall)))
        chunk = bytes(buf[:n])
        del buf[:n]
        return chunk

    return _recv
