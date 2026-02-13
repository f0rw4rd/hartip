"""
HART-IP client for TCP and UDP communication.

Provides a synchronous client that handles:
- Session management (initiate / close / keep-alive)
- HART PDU pass-through (msg_id=3)
- TCP and UDP socket management
- HART-IP frame encoding/decoding (using construct structs)
- Sequence number management
- Response parsing with checksum validation
- Extended command support (cmd > 253 via Command 31)
- Delayed-response retry logic
- Optional automatic keep-alive
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Optional

from .constants import (
    CMD_EXTENDED_CMD,
    COMM_ERROR_MASK,
    DEFAULT_INACTIVITY_TIMER,
    DR_MAX_RETRIES,
    DR_RETRY_CODES,
    DR_RETRY_DELAY_MS,
    HARTIP_HEADER_SIZE,
    HARTIP_TCP_PORT,
    HARTIP_UDP_PORT,
    MASTER_TYPE_PRIMARY,
    MAX_SINGLE_BYTE_CMD,
    HARTCommand,
    HARTFrameType,
    HARTIPMessageID,
    HARTIPMessageType,
    HARTIPStatus,
    HARTResponseCode,
)
from .exceptions import (
    HARTChecksumError,
    HARTCommunicationError,
    HARTIPConnectionError,
    HARTIPStatusError,
    HARTIPTimeoutError,
    HARTProtocolError,
)
from .protocol import (
    HARTIPHeader,
    HARTPdu,
    build_keep_alive,
    build_pdu,
    build_request,
    build_session_close,
    build_session_init,
    parse_response,
    xor_checksum,
)

logger = logging.getLogger(__name__)


class HARTIPResponse:
    """Parsed HART-IP response."""

    __slots__ = (
        "header",
        "pdu",
        "response_code",
        "device_status",
        "payload",
        "comm_error",
    )

    def __init__(
        self,
        header: object,
        pdu: object,
        response_code: int = 0,
        device_status: int = 0,
        payload: bytes = b"",
        comm_error: bool = False,
    ):
        self.header = header
        self.pdu = pdu
        self.response_code = response_code
        self.device_status = device_status
        self.payload = payload
        self.comm_error = comm_error

    @property
    def success(self) -> bool:
        return self.response_code == HARTResponseCode.SUCCESS and not self.comm_error

    @property
    def error_message(self) -> str:
        if self.comm_error:
            return f"Communication error (flags=0x{self.response_code:02X})"
        try:
            return HARTResponseCode(self.response_code).name
        except ValueError:
            return f"Unknown error code: {self.response_code}"


class HARTIPClient:
    """Synchronous HART-IP client over TCP or UDP.

    A HART-IP session is established automatically on :meth:`connect`
    and torn down on :meth:`close`.

    Args:
        host: Target device hostname or IP address.
        port: Target port (default 5094).
        protocol: ``"tcp"`` or ``"udp"`` (default ``"udp"``).
        timeout: Socket timeout in seconds.
        master_type: 1=primary master, 0=secondary master.
        inactivity_timer: Session inactivity timeout in milliseconds.
        auto_keepalive: If True, start a background thread that sends
            keep-alive frames at ``inactivity_timer / 2`` interval.
        dr_retries: Maximum delayed-response retries (default 100).
        dr_retry_delay: Base delay between DR retries in milliseconds (default 20).

    Usage::

        from hartip import HARTIPClient, parse_cmd0

        with HARTIPClient("192.168.1.100") as client:
            resp = client.read_unique_id()
            info = parse_cmd0(resp.payload)
    """

    def __init__(
        self,
        host: str,
        port: Optional[int] = None,
        protocol: str = "udp",
        timeout: float = 5.0,
        master_type: int = MASTER_TYPE_PRIMARY,
        inactivity_timer: int = DEFAULT_INACTIVITY_TIMER,
        auto_keepalive: bool = False,
        dr_retries: int = DR_MAX_RETRIES,
        dr_retry_delay: int = DR_RETRY_DELAY_MS,
    ):
        self.host = host
        self.protocol = protocol.lower()
        self.port = port or (HARTIP_TCP_PORT if self.protocol == "tcp" else HARTIP_UDP_PORT)
        self.timeout = timeout
        self.master_type = master_type
        self.inactivity_timer = inactivity_timer
        self.auto_keepalive = auto_keepalive
        self.dr_retries = dr_retries
        self.dr_retry_delay = dr_retry_delay

        self._socket: Optional[socket.socket] = None
        self._connected = False
        self._session_active = False
        self._sequence = 0
        self._lock = threading.Lock()

        # Keep-alive thread state
        self._keepalive_thread: Optional[threading.Thread] = None
        self._keepalive_stop = threading.Event()

    # -- connection lifecycle ------------------------------------------------

    def connect(self) -> None:
        """Open the transport connection and initiate a HART-IP session.

        If already connected, the existing connection is closed first to
        avoid leaking the socket.

        Raises:
            HARTIPConnectionError: On socket or session failure.
        """
        # Fix #1: Close existing connection before creating a new one
        if self._connected or self._socket is not None:
            self.close()

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

        # Initiate HART-IP session
        self._initiate_session()

        # Fix #6: Start keep-alive thread if requested
        if self.auto_keepalive and self.inactivity_timer > 0:
            self._start_keepalive()

    def _initiate_session(self) -> None:
        """Send Session Initiate (msg_id=0) and validate the response."""
        frame = build_session_init(
            sequence=self._next_sequence(),
            master_type=self.master_type,
            inactivity_timer=self.inactivity_timer,
        )
        raw = self._send_recv(frame)
        header = HARTIPHeader.parse(raw[:HARTIP_HEADER_SIZE])

        if header.status != HARTIPStatus.SUCCESS:
            try:
                name = HARTIPStatus(header.status).name
            except ValueError:
                name = f"status {header.status}"
            self.close()
            raise HARTIPConnectionError(f"Session initiate failed: {name}")

        self._session_active = True

    def _close_session(self) -> None:
        """Send Session Close (msg_id=1) if session is active."""
        if not self._session_active or not self._socket:
            return
        try:
            frame = build_session_close(sequence=self._next_sequence())
            self._send_recv(frame)
        except (OSError, HARTIPTimeoutError):
            pass  # best-effort
        self._session_active = False

    def close(self) -> None:
        """Close the HART-IP session and transport connection."""
        # Stop keep-alive thread first
        self._stop_keepalive()

        self._close_session()
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

    @property
    def session_active(self) -> bool:
        return self._session_active

    def __enter__(self) -> HARTIPClient:
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- keep-alive ----------------------------------------------------------

    def _start_keepalive(self) -> None:
        """Start the background keep-alive daemon thread."""
        self._keepalive_stop.clear()
        interval = self.inactivity_timer / 2000.0  # convert ms to seconds, send at half
        self._keepalive_thread = threading.Thread(
            target=self._keepalive_loop,
            args=(interval,),
            daemon=True,
            name="hartip-keepalive",
        )
        self._keepalive_thread.start()

    def _stop_keepalive(self) -> None:
        """Signal the keep-alive thread to stop and wait for it."""
        if self._keepalive_thread is not None:
            self._keepalive_stop.set()
            self._keepalive_thread.join(timeout=2.0)
            self._keepalive_thread = None

    def _keepalive_loop(self, interval: float) -> None:
        """Background loop that sends keep-alive frames periodically."""
        while not self._keepalive_stop.wait(timeout=interval):
            if not self._connected or not self._session_active or not self._socket:
                break
            try:
                frame = build_keep_alive(sequence=self._next_sequence())
                self._send_recv(frame)
            except (OSError, HARTIPTimeoutError, HARTIPConnectionError):
                logger.debug("Keep-alive failed, stopping keep-alive thread")
                break

    # -- sequence generator --------------------------------------------------

    def _next_sequence(self) -> int:
        """Generate the next sequence number (thread-safe)."""
        with self._lock:
            self._sequence = (self._sequence + 1) & 0xFFFF
            return self._sequence

    def _next_sequence_unlocked(self) -> int:
        """Generate the next sequence number (caller must hold _lock)."""
        self._sequence = (self._sequence + 1) & 0xFFFF
        return self._sequence

    # -- send / receive ------------------------------------------------------

    def _send_recv_unlocked(self, frame: bytes) -> bytes:
        """Send a frame and receive the response (caller must hold _lock)."""
        try:
            if self.protocol == "tcp":
                self._socket.sendall(frame)
                return self._recv_tcp()
            else:
                self._socket.sendto(frame, (self.host, self.port))
                raw, _ = self._socket.recvfrom(1024)
                return raw
        except TimeoutError as exc:
            raise HARTIPTimeoutError("Operation timed out") from exc
        except OSError as exc:
            raise HARTIPConnectionError(f"Communication error: {exc}") from exc

    def _send_recv(self, frame: bytes) -> bytes:
        """Send a frame and receive the response (thread-safe).

        Fix #2: All send/receive operations are serialized under _lock
        to prevent response mix-ups in multi-threaded usage.
        """
        with self._lock:
            return self._send_recv_unlocked(frame)

    def send_command(
        self,
        command: int,
        address: int = 0,
        data: bytes = b"",
        use_long_frame: bool = False,
        unique_addr: Optional[bytes] = None,
    ) -> HARTIPResponse:
        """Send a HART command and receive the response.

        The command is wrapped in a HART-IP pass-through frame (msg_id=3).
        Commands > 253 are automatically wrapped using the Command 31
        extended command mechanism.

        If the device returns a delayed-response code (32/33/34/36), the
        command is retried up to ``dr_retries`` times with exponential
        backoff.

        Args:
            command: HART command number (0-65535).
            address: Polling address (0-15) for short frame.
            data: Command payload bytes.
            use_long_frame: Use 5-byte unique address.
            unique_addr: Explicit 5-byte unique address.

        Returns:
            Parsed :class:`HARTIPResponse`.

        Raises:
            HARTIPConnectionError: Not connected or no active session.
            HARTIPTimeoutError: No response within timeout.
            HARTIPStatusError: HART-IP header status != 0.
            HARTChecksumError: PDU checksum invalid.
            HARTCommunicationError: Bit 7 set in response code (comm error).
            ValueError: use_long_frame is True but unique_addr is None.
        """
        if not self._connected or not self._socket:
            raise HARTIPConnectionError("Not connected")
        if not self._session_active:
            raise HARTIPConnectionError("No active session (call connect() first)")

        # Fix #8: Raise ValueError if use_long_frame without unique_addr
        if use_long_frame and unique_addr is None:
            raise ValueError(
                "use_long_frame=True requires unique_addr (5-byte device address)"
            )

        if use_long_frame and unique_addr:
            delimiter = HARTFrameType.LONG_FRAME
            addr_bytes = unique_addr[:5]
        else:
            delimiter = HARTFrameType.SHORT_FRAME
            addr_bytes = bytes([address & 0x0F])

        # Fix #7: Extended command support (cmd > 253 uses Command 31 wrapper)
        wire_command = command
        wire_data = data
        if command > MAX_SINGLE_BYTE_CMD:
            wire_command = CMD_EXTENDED_CMD
            wire_data = command.to_bytes(2, "big") + data

        # Fix #2: Hold lock for entire sequence-generate + send + receive cycle
        with self._lock:
            frame = build_request(
                sequence=self._next_sequence_unlocked(),
                delimiter=delimiter,
                address=addr_bytes,
                command=wire_command,
                data=wire_data,
            )
            raw = self._send_recv_unlocked(frame)

        resp = self._parse(raw)

        # Fix #5: Delayed-response retry logic
        if resp.response_code in DR_RETRY_CODES:
            resp = self._handle_delayed_response(
                delimiter, addr_bytes, wire_command, wire_data
            )

        return resp

    def _handle_delayed_response(
        self,
        delimiter: int,
        addr_bytes: bytes,
        command: int,
        data: bytes,
    ) -> HARTIPResponse:
        """Retry a command that received a delayed-response code.

        Follows the FieldComm C# pattern: resend the same command with
        exponential backoff until either a non-DR response is received
        or the retry limit is exhausted.
        """
        delay = self.dr_retry_delay / 1000.0  # convert ms to seconds
        max_delay = max(delay, 30.0)  # cap at 30 seconds
        resp = None

        for retry in range(self.dr_retries):
            time.sleep(delay)

            with self._lock:
                frame = build_request(
                    sequence=self._next_sequence_unlocked(),
                    delimiter=delimiter,
                    address=addr_bytes,
                    command=command,
                    data=data,
                )
                raw = self._send_recv_unlocked(frame)

            resp = self._parse(raw)

            if resp.response_code not in DR_RETRY_CODES:
                return resp

            # Exponential backoff: double the delay after the first retry
            if retry > 0 and delay < max_delay:
                delay = min(delay * 2, max_delay)

        logger.warning(
            "Delayed-response retry limit (%d) exceeded", self.dr_retries
        )
        return resp

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
        """Read exactly *n* bytes from the TCP socket.

        Fix #3: Uses bytearray for O(n) accumulation instead of
        bytes concatenation which is O(n^2).
        """
        buf = bytearray()
        while len(buf) < n:
            chunk = self._socket.recv(n - len(buf))
            if not chunk:
                raise HARTIPConnectionError("Connection closed")
            buf.extend(chunk)
        return bytes(buf)

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
        frame_without_cksum = pdu_bytes[:-1]
        expected = xor_checksum(frame_without_cksum)
        if expected != pdu.checksum:
            raise HARTChecksumError(expected, pdu.checksum)

        response_code = 0
        device_status = 0
        payload = b""
        comm_error = False

        if pdu.byte_count >= 2:
            raw_response_byte = pdu.data[0]

            # Fix #4: Check bit 7 for communication error summary
            if raw_response_byte & COMM_ERROR_MASK:
                comm_error = True
                response_code = raw_response_byte
            else:
                response_code = raw_response_byte

            device_status = pdu.data[1]
            payload = bytes(pdu.data[2:])
        elif pdu.byte_count == 1:
            raw_response_byte = pdu.data[0]
            if raw_response_byte & COMM_ERROR_MASK:
                comm_error = True
            response_code = raw_response_byte

        return HARTIPResponse(
            header=header,
            pdu=pdu,
            response_code=response_code,
            device_status=device_status,
            payload=payload,
            comm_error=comm_error,
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

    def read_device_vars_status(self, address: int = 0) -> HARTIPResponse:
        """Command 9: Read Device Variables with Status."""
        return self.send_command(HARTCommand.READ_DEVICE_VARS_STATUS, address)

    def read_message(self, address: int = 0) -> HARTIPResponse:
        """Command 12: Read Message (24-byte packed ASCII)."""
        return self.send_command(HARTCommand.READ_MESSAGE, address)

    def read_tag_descriptor_date(self, address: int = 0) -> HARTIPResponse:
        """Command 13: Read Tag, Descriptor, Date."""
        return self.send_command(HARTCommand.READ_TAG_DESCRIPTOR_DATE, address)

    def read_pv_info(self, address: int = 0) -> HARTIPResponse:
        """Command 14: Read Primary Variable Transducer Information."""
        return self.send_command(HARTCommand.READ_PRIMARY_VAR_INFO, address)

    def read_output_info(self, address: int = 0) -> HARTIPResponse:
        """Command 15: Read Output Information."""
        return self.send_command(HARTCommand.READ_OUTPUT_INFO, address)

    def read_long_tag(self, address: int = 0) -> HARTIPResponse:
        """Command 20: Read Long Tag (HART 6+)."""
        return self.send_command(HARTCommand.READ_LONG_TAG, address)

    def read_additional_status(self, address: int = 0) -> HARTIPResponse:
        """Command 48: Read Additional Transmitter Status."""
        return self.send_command(HARTCommand.READ_ADDITIONAL_STATUS, address)

    def perform_self_test(self, address: int = 0) -> HARTIPResponse:
        """Command 41: Perform Device Self-Test."""
        return self.send_command(HARTCommand.PERFORM_SELF_TEST, address)
