"""
Integration tests for construct-based protocol structs against live hipserver.

Validates that our construct definitions correctly parse real hipserver frames.
"""

from __future__ import annotations

import socket

import pytest

from hartip.constants import HARTIP_HEADER_SIZE, HARTFrameType, HARTIPMessageType, HARTIPStatus
from hartip.protocol import (
    HARTIPHeader,
    HARTPdu,
    build_request,
    build_session_init,
    xor_checksum,
)

from .conftest import HART_HOST, HART_UDP_PORT, skip_no_hipserver, skip_no_udp

pytestmark = [
    pytest.mark.integration,
    skip_no_hipserver,
    skip_no_udp,
]


class TestRawFrameParsing:
    """Send raw bytes and parse the response with construct structs."""

    def _make_session_udp(self, timeout: float = 5.0) -> socket.socket:
        """Create a UDP socket with an active HART-IP session."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # Establish session
        frame = build_session_init(sequence=0)
        sock.sendto(frame, (HART_HOST, HART_UDP_PORT))
        data, _ = sock.recvfrom(1024)
        header = HARTIPHeader.parse(data[:HARTIP_HEADER_SIZE])
        assert header.status == HARTIPStatus.SUCCESS, f"Session init failed: status={header.status}"
        return sock

    def _send_cmd(self, sock: socket.socket, sequence: int, command: int = 0) -> bytes:
        """Send a HART command and return the raw response."""
        frame = build_request(
            sequence=sequence,
            delimiter=HARTFrameType.SHORT_FRAME,
            address=b"\x00",
            command=command,
        )
        sock.sendto(frame, (HART_HOST, HART_UDP_PORT))
        data, _ = sock.recvfrom(1024)
        return data

    def test_header_parses_correctly(self):
        """Build a request, send it, parse the response header."""
        sock = self._make_session_udp()
        try:
            raw = self._send_cmd(sock, sequence=1)
            assert len(raw) >= HARTIP_HEADER_SIZE

            header = HARTIPHeader.parse(raw[:HARTIP_HEADER_SIZE])
            assert header.version == 1
            assert header.msg_type == HARTIPMessageType.RESPONSE
            assert header.status == HARTIPStatus.SUCCESS
            assert header.byte_count == len(raw)
            assert header.payload_len == len(raw) - HARTIP_HEADER_SIZE
        finally:
            sock.close()

    def test_pdu_parses_correctly(self):
        """Parse the PDU portion of a live response."""
        sock = self._make_session_udp()
        try:
            raw = self._send_cmd(sock, sequence=2)
            assert len(raw) > HARTIP_HEADER_SIZE

            pdu = HARTPdu.parse(raw[HARTIP_HEADER_SIZE:])
            assert pdu.command == 0
            assert pdu.delimiter in (
                HARTFrameType.SHORT_FRAME,
                HARTFrameType.LONG_FRAME,
                HARTFrameType.ACK_SHORT,
                HARTFrameType.ACK_LONG,
            )
            assert pdu.byte_count == len(pdu.data)
        finally:
            sock.close()

    def test_checksum_valid(self):
        """Verify the response PDU checksum is correct."""
        sock = self._make_session_udp()
        try:
            raw = self._send_cmd(sock, sequence=3)
            pdu_bytes = raw[HARTIP_HEADER_SIZE:]
            expected = xor_checksum(pdu_bytes[:-1])
            assert expected == pdu_bytes[-1]
        finally:
            sock.close()

    def test_byte_count_is_total_length(self):
        """Verify that header byte_count == total message length."""
        sock = self._make_session_udp()
        try:
            raw = self._send_cmd(sock, sequence=4)
            header = HARTIPHeader.parse(raw[:HARTIP_HEADER_SIZE])
            assert header.byte_count == len(raw)
        finally:
            sock.close()
