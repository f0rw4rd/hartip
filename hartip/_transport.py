"""
HART-IP frame I/O on a connected socket.

Reads whole HART-IP messages from a TCP stream or UDP datagrams and
decides whether a received frame answers an outstanding request.
"""

from __future__ import annotations

import enum
import logging
import socket

from .constants import HARTIP_HEADER_SIZE, HARTIPMessageType
from .exceptions import HARTFrameError, HARTIPConnectionError
from .protocol import MessageHeader, parse_header

logger = logging.getLogger(__name__)

UDPPeer = tuple[str, int]
"""``(address, port)`` of the UDP server; replies from elsewhere are dropped."""

_REPLY_TYPES = frozenset(
    {HARTIPMessageType.RESPONSE, HARTIPMessageType.ERROR, HARTIPMessageType.NAK}
)


class FrameKind(enum.Enum):
    """How a received frame relates to the request being waited on."""

    REPLY = enum.auto()  # answers the request
    PUBLISH = enum.auto()  # unsolicited burst-mode data
    STALE = enum.auto()  # anything else, e.g. a late reply to an earlier request


def classify_frame(header: MessageHeader, sequence: int, msg_id: int) -> FrameKind:
    """Classify a received frame against the request ``(sequence, msg_id)``.

    A reply answers the request when it is a Response, Error or NAK
    message carrying the request's sequence number and message id.
    """
    if header.msg_type == HARTIPMessageType.PUBLISH:
        return FrameKind.PUBLISH
    if header.msg_type in _REPLY_TYPES and header.sequence == sequence and header.msg_id == msg_id:
        return FrameKind.REPLY
    return FrameKind.STALE


def resolve_udp_peer(host: str, port: int) -> UDPPeer:
    """Resolve ``host:port`` to the IPv4 address replies must come from."""
    address, peer_port = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4][:2]
    return str(address), int(peer_port)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes from a TCP socket.

    Raises:
        HARTIPConnectionError: The peer closed the connection first.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise HARTIPConnectionError("Connection closed")
        buf.extend(chunk)
    return bytes(buf)


def recv_tcp_frame(sock: socket.socket) -> bytes:
    """Read one complete HART-IP message from a TCP stream.

    Raises:
        HARTFrameError: ``byte_count`` is below the header size, which
            leaves the stream position unknown.
        HARTIPConnectionError: The peer closed the connection.
    """
    header_data = recv_exact(sock, HARTIP_HEADER_SIZE)
    header = parse_header(header_data)
    if header.byte_count < HARTIP_HEADER_SIZE:
        raise HARTFrameError(
            f"HART-IP byte_count={header.byte_count} is smaller than the "
            f"{HARTIP_HEADER_SIZE}-byte header"
        )
    return header_data + recv_exact(sock, header.payload_len)


def recv_udp_frame(sock: socket.socket, peer: UDPPeer) -> bytes | None:
    """Receive one datagram, cut to its ``byte_count``.

    Returns ``None`` for a datagram that cannot be a reply: from another
    address, shorter than a HART-IP header, or with ``byte_count`` below
    the header size.
    """
    raw, addr = sock.recvfrom(65535)
    if (addr[0], addr[1]) != peer:
        logger.debug("Dropping datagram from unexpected source %s", addr)
        return None
    if len(raw) < HARTIP_HEADER_SIZE:
        logger.debug("Dropping %d-byte datagram, shorter than a HART-IP header", len(raw))
        return None
    byte_count = int.from_bytes(raw[6:8], "big")
    if byte_count < HARTIP_HEADER_SIZE:
        logger.debug("Dropping datagram with byte_count=%d", byte_count)
        return None
    return raw[:byte_count]
