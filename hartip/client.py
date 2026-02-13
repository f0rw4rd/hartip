"""
HART-IP client for TCP and UDP communication.

Provides a synchronous client that handles:
- TCP and UDP socket management
- HART-IP frame encoding/decoding (using construct structs)
- Transaction ID and sequence management
- Response parsing with checksum validation
"""

from __future__ import annotations

import socket
import threading
from typing import Optional

from .constants import (
    HARTIP_HEADER_SIZE,
    HARTIP_TCP_PORT,
    HARTIP_UDP_PORT,
    HARTCommand,
    HARTFrameType,
    HARTIPMessageType,
    HARTIPStatus,
    HARTResponseCode,
)
from .device import DeviceInfo, Variable, parse_cmd0, parse_cmd1, parse_cmd2, parse_cmd3
from .exceptions import (
    HARTChecksumError,
    HARTIPConnectionError,
    HARTIPStatusError,
    HARTIPTimeoutError,
    HARTProtocolError,
)
from .protocol import HARTIPHeader, HARTPdu, build_request, parse_response, xor_checksum


class HARTIPResponse:
    """Parsed HART-IP response."""

    __slots__ = ("header", "pdu", "response_code", "device_status", "payload")

    def __init__(
        self,
        header: object,
        pdu: object,
        response_code: int = 0,
        device_status: int = 0,
        payload: bytes = b"",
    ):
        self.header = header
        self.pdu = pdu
        self.response_code = response_code
        self.device_status = device_status
        self.payload = payload

    @property
    def success(self) -> bool:
        return self.response_code == HARTResponseCode.SUCCESS

    @property
    def error_message(self) -> str:
        try:
            return HARTResponseCode(self.response_code).name
        except ValueError:
            return f"Unknown error code: {self.response_code}"


class HARTIPClient:
    """Synchronous HART-IP client over TCP or UDP.

    Usage::

        with HARTIPClient("192.168.1.100") as client:
            resp = client.send_command(HARTCommand.READ_UNIQUE_ID)
            info = parse_cmd0(resp.payload)
    """

    def __init__(
        self,
        host: str,
        port: Optional[int] = None,
        protocol: str = "udp",
        timeout: float = 5.0,
    ):
        self.host = host
        self.protocol = protocol.lower()
        self.port = port or (HARTIP_TCP_PORT if self.protocol == "tcp" else HARTIP_UDP_PORT)
        self.timeout = timeout

        self._socket: Optional[socket.socket] = None
        self._connected = False
        self._msg_id = 0
        self._sequence = 0
        self._lock = threading.Lock()

    # -- connection lifecycle ------------------------------------------------

    def connect(self) -> None:
        """Open the transport connection.

        Raises:
            HARTIPConnectionError: On socket failure.
        """
        try:
            if self.protocol == "tcp":
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.settimeout(self.timeout)
                self._socket.connect((self.host, self.port))
            else:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._socket.settimeout(self.timeout)
            self._connected = True
        except OSError as exc:
            self._connected = False
            raise HARTIPConnectionError(f"Failed to connect to {self.host}:{self.port}: {exc}")

    def close(self) -> None:
        """Close the transport connection."""
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    def __enter__(self) -> HARTIPClient:
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- ID generators -------------------------------------------------------

    def _next_msg_id(self) -> int:
        with self._lock:
            self._msg_id = (self._msg_id + 1) & 0xFF
            return self._msg_id

    def _next_sequence(self) -> int:
        with self._lock:
            self._sequence = (self._sequence + 1) & 0xFFFF
            return self._sequence

    # -- send / receive ------------------------------------------------------

    def send_command(
        self,
        command: int,
        address: int = 0,
        data: bytes = b"",
        use_long_frame: bool = False,
        unique_addr: Optional[bytes] = None,
    ) -> HARTIPResponse:
        """Send a HART command and receive the response.

        Args:
            command: HART command number.
            address: Polling address (0-15) for short frame.
            data: Command payload bytes.
            use_long_frame: Use 5-byte unique address.
            unique_addr: Explicit 5-byte unique address.

        Returns:
            Parsed :class:`HARTIPResponse`.

        Raises:
            HARTIPConnectionError: Not connected.
            HARTIPTimeoutError: No response within timeout.
            HARTIPStatusError: HART-IP header status != 0.
            HARTChecksumError: PDU checksum invalid.
        """
        if not self._connected or not self._socket:
            raise HARTIPConnectionError("Not connected")

        if use_long_frame and unique_addr:
            delimiter = HARTFrameType.LONG_FRAME
            addr_bytes = unique_addr[:5]
        else:
            delimiter = HARTFrameType.SHORT_FRAME
            addr_bytes = bytes([address & 0x0F])

        frame = build_request(
            msg_id=self._next_msg_id(),
            sequence=self._next_sequence(),
            delimiter=delimiter,
            address=addr_bytes,
            command=command,
            data=data,
        )

        try:
            if self.protocol == "tcp":
                self._socket.sendall(frame)
                raw = self._recv_tcp()
            else:
                self._socket.sendto(frame, (self.host, self.port))
                raw, _ = self._socket.recvfrom(1024)
        except TimeoutError as exc:
            raise HARTIPTimeoutError(f"Command {command} timed out") from exc
        except OSError as exc:
            raise HARTIPConnectionError(f"Communication error: {exc}") from exc

        return self._parse(raw)

    def _recv_tcp(self) -> bytes:
        """Receive a complete HART-IP message over TCP."""
        header_data = self._recv_exact(HARTIP_HEADER_SIZE)
        header = HARTIPHeader.parse(header_data)
        payload_len = max(0, header.byte_count - HARTIP_HEADER_SIZE)
        if payload_len > 65536:
            raise HARTProtocolError(f"Payload too large: {payload_len}")
        if payload_len > 0:
            payload_data = self._recv_exact(payload_len)
            return header_data + payload_data
        return header_data

    def _recv_exact(self, n: int) -> bytes:
        """Read exactly *n* bytes from the TCP socket."""
        buf = b""
        while len(buf) < n:
            chunk = self._socket.recv(n - len(buf))
            if not chunk:
                raise HARTIPConnectionError("Connection closed")
            buf += chunk
        return buf

    def _parse(self, data: bytes) -> HARTIPResponse:
        """Parse raw HART-IP bytes into an :class:`HARTIPResponse`."""
        result = parse_response(data)
        header = result["header"]
        pdu = result["pdu"]

        if header.status != HARTIPStatus.SUCCESS:
            try:
                name = HARTIPStatus(header.status).name
            except ValueError:
                name = f"status {header.status}"
            raise HARTIPStatusError(f"HART-IP error: {name}", header.status)

        if pdu is None:
            return HARTIPResponse(header=header, pdu=None)

        # Validate checksum
        pdu_bytes = data[HARTIP_HEADER_SIZE:]
        frame_without_cksum = pdu_bytes[: -1]
        expected = xor_checksum(frame_without_cksum)
        if expected != pdu.checksum:
            raise HARTChecksumError(expected, pdu.checksum)

        response_code = 0
        device_status = 0
        payload = b""
        if pdu.byte_count >= 2:
            response_code = pdu.data[0]
            device_status = pdu.data[1]
            payload = bytes(pdu.data[2:])
        elif pdu.byte_count == 1:
            response_code = pdu.data[0]

        return HARTIPResponse(
            header=header,
            pdu=pdu,
            response_code=response_code,
            device_status=device_status,
            payload=payload,
        )

    # -- convenience wrappers ------------------------------------------------

    def read_unique_id(self, address: int = 0) -> HARTIPResponse:
        """Command 0: Read Unique Identifier."""
        return self.send_command(HARTCommand.READ_UNIQUE_ID, address)

    def read_primary_variable(self, address: int = 0) -> HARTIPResponse:
        """Command 1: Read Primary Variable."""
        return self.send_command(HARTCommand.READ_PRIMARY_VARIABLE, address)

    def read_current_and_percent(self, address: int = 0) -> HARTIPResponse:
        """Command 2: Read Loop Current and Percent of Range."""
        return self.send_command(HARTCommand.READ_CURRENT_AND_PERCENT, address)

    def read_dynamic_variables(self, address: int = 0) -> HARTIPResponse:
        """Command 3: Read Dynamic Variables."""
        return self.send_command(HARTCommand.READ_DYNAMIC_VARS, address)

    def read_tag_descriptor_date(self, address: int = 0) -> HARTIPResponse:
        """Command 13: Read Tag, Descriptor, Date."""
        return self.send_command(HARTCommand.READ_TAG_DESCRIPTOR_DATE, address)

    def read_long_tag(self, address: int = 0) -> HARTIPResponse:
        """Command 20: Read Long Tag (HART 6+)."""
        return self.send_command(HARTCommand.READ_LONG_TAG, address)

    def read_additional_status(self, address: int = 0) -> HARTIPResponse:
        """Command 48: Read Additional Transmitter Status."""
        return self.send_command(HARTCommand.READ_ADDITIONAL_STATUS, address)

    def read_output_info(self, address: int = 0) -> HARTIPResponse:
        """Command 15: Read Output Information."""
        return self.send_command(HARTCommand.READ_OUTPUT_INFO, address)

    def perform_self_test(self, address: int = 0) -> HARTIPResponse:
        """Command 41: Perform Device Self-Test."""
        return self.send_command(HARTCommand.PERFORM_SELF_TEST, address)
