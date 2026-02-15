"""
HART-IP client for TCP and UDP communication.

Provides a synchronous client that handles:
- Session management (initiate / close / keep-alive)
- HART PDU pass-through (msg_id=3)
- Direct PDU (msg_id=4) -- HART-IP v2 native framing
- Read Audit Log (msg_id=5) -- HART-IP v2 session history
- TCP and UDP socket management
- TLS 1.2+ transport for HART-IP v2 (TCP only)
- HART-IP frame encoding/decoding (using construct structs)
- Sequence number management
- Response parsing with checksum validation
- Extended command support (cmd > 253 via Command 31)
- Delayed-response retry logic
- Optional automatic keep-alive
"""

from __future__ import annotations

import contextlib
import logging
import socket
import ssl
import threading
import time
import warnings
from typing import TYPE_CHECKING, Any, Callable, Sequence

if TYPE_CHECKING:
    from .v2 import AuditLogResponse, DirectPDU, DirectPDUCommand

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
    HARTIP_V2_ALL_CIPHERS,
    MASTER_TYPE_PRIMARY,
    MAX_SINGLE_BYTE_CMD,
    HARTCommand,
    HARTFrameType,
    HARTIPStatus,
    HARTIPVersion,
    HARTResponseCode,
)
from .exceptions import (
    HARTChecksumError,
    HARTCommunicationError,
    HARTIPConnectionError,
    HARTIPStatusError,
    HARTIPTimeoutError,
    HARTIPTLSError,
    HARTProtocolError,
    HARTResponseError,
)
from .protocol import (
    HARTIPHeader,
    build_keep_alive,
    build_request,
    build_session_close,
    build_session_init,
    parse_response,
    xor_checksum,
)

logger = logging.getLogger(__name__)


_SENTINEL = object()


class HARTIPResponse:
    """Parsed HART-IP response.

    Attributes:
        header: Parsed HART-IP transport header (construct Container).
        pdu: Parsed HART PDU frame, or ``None`` for header-only messages.
        response_code: HART response code (first data byte). When
            :attr:`comm_error` is ``True``, this is the raw communication
            error flags byte (MSB set).
        device_status: HART device status byte (second data byte).
        payload: Remaining command data after response_code and device_status.
        comm_error: ``True`` if bit 7 of the response code byte was set,
            indicating a communication error summary rather than a command
            response code.
    """

    __slots__ = (
        "_parsed_cache",
        "comm_error",
        "device_status",
        "header",
        "payload",
        "pdu",
        "response_code",
    )

    def __init__(
        self,
        header: Any,
        pdu: Any,
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
        self._parsed_cache = _SENTINEL

    @property
    def command_number(self) -> int | None:
        """The HART command number from the PDU, or ``None`` if unavailable."""
        if self.pdu is not None and hasattr(self.pdu, "command"):
            return self.pdu.command
        return None

    @property
    def command_name(self) -> str:
        """Human-readable command name from the registry.

        Returns ``"unknown_cmd_{n}"`` when not registered, or ``"unknown"``
        when the command number is unavailable.
        """
        from .device import get_command_name

        cmd = self.command_number
        if cmd is None:
            return "unknown"
        return get_command_name(cmd)

    @property
    def parsed(self) -> Any:
        """Auto-parsed payload using the command registry.

        The result is computed lazily on first access and cached.  Returns
        ``None`` when no parser is registered for the command or when the
        command number is unavailable.

        Examples::

            resp = client.read_unique_id()
            info = resp.parsed           # DeviceInfo dataclass
            print(info.manufacturer_name)

            resp = client.read_dynamic_variables()
            data = resp.parsed           # dict with 'loop_current' and 'variables'
        """
        if self._parsed_cache is not _SENTINEL:
            return self._parsed_cache

        from .device import parse_command

        cmd = self.command_number
        if cmd is not None and self.payload:
            self._parsed_cache = parse_command(cmd, self.payload)
        else:
            self._parsed_cache = None
        return self._parsed_cache

    @property
    def success(self) -> bool:
        """True when the response code is 0 and no communication error occurred."""
        return self.response_code == HARTResponseCode.SUCCESS and not self.comm_error

    @property
    def error_message(self) -> str:
        """Human-readable error description."""
        if self.comm_error:
            return f"Communication error (flags=0x{self.response_code:02X})"
        try:
            return HARTResponseCode(self.response_code).name
        except ValueError:
            return f"Unknown error code: {self.response_code}"

    @property
    def error_code(self) -> HARTResponseCode | None:
        """The response code as an enum member, or ``None`` if not recognized.

        Returns ``None`` when :attr:`comm_error` is ``True`` (the byte is
        not a response code in that case).
        """
        if self.comm_error:
            return None
        try:
            return HARTResponseCode(self.response_code)
        except ValueError:
            return None

    def raise_for_error(self) -> None:
        """Raise an exception if the response indicates an error.

        Raises:
            HARTCommunicationError: If :attr:`comm_error` is ``True``.
            HARTResponseError: If :attr:`response_code` is non-zero.
        """
        if self.comm_error:
            raise HARTCommunicationError(self.response_code)
        if self.response_code != HARTResponseCode.SUCCESS:
            cmd = 0
            if self.pdu is not None and hasattr(self.pdu, "command"):
                cmd = self.pdu.command
            raise HARTResponseError(
                f"HART command {cmd} failed: {self.error_message}",
                code=self.response_code,
                command=cmd,
            )

    def __repr__(self) -> str:
        cmd = "?"
        if self.pdu is not None and hasattr(self.pdu, "command"):
            cmd = str(self.pdu.command)
        status = "ok" if self.success else self.error_message
        return (
            f"HARTIPResponse(cmd={cmd}, rc={self.response_code}, "
            f"status={status!r}, payload={len(self.payload)}B)"
        )


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
        version: HART-IP protocol version (1 or 2). Version 2 enables
            TLS for TCP and sends version=2 in the HART-IP header.
        tls: Explicitly enable TLS wrapping for TCP connections.
            If ``None`` (default), TLS is enabled automatically when
            ``version=2`` and ``protocol="tcp"``.
        psk_identity: PSK identity string for TLS-PSK authentication.
        psk_key: PSK key bytes (16 bytes for AES-128) for TLS-PSK.
        ciphers: TLS cipher suite string (e.g. ``HARTIP_V2_PSK_CIPHERS``).
            If ``None``, uses :data:`HARTIP_V2_ALL_CIPHERS`.
        ca_certs: Path to a CA certificate file for server verification.
            When set, ``verify_mode`` is changed to ``CERT_REQUIRED``.
        certfile: Path to a client certificate file for mutual TLS.
        keyfile: Path to the client certificate private key file.
        cert_validator: Optional callback ``(cert_dict) -> bool`` invoked
            after the TLS handshake with the peer certificate (as returned
            by :meth:`ssl.SSLSocket.getpeercert`).  Return ``True`` to
            accept, ``False`` (or raise) to reject.  Useful for certificate
            pinning or custom CA logic.
        ssl_context: Optional pre-configured :class:`ssl.SSLContext`.
            If provided, ``psk_identity``/``psk_key``/``ciphers``/``ca_certs``
            /``certfile``/``keyfile`` are ignored.

    Usage::

        from hartip import HARTIPClient, parse_cmd0

        # v1 plaintext (default)
        with HARTIPClient("192.168.1.100") as client:
            resp = client.read_unique_id()
            info = parse_cmd0(resp.payload)

        # v2 with TLS-PSK over TCP
        with HARTIPClient("192.168.1.100", protocol="tcp", version=2,
                          psk_identity="client1", psk_key=b"\\x00" * 16) as client:
            resp = client.read_unique_id()
    """

    def __init__(
        self,
        host: str,
        port: int | None = None,
        protocol: str = "udp",
        timeout: float = 5.0,
        master_type: int = MASTER_TYPE_PRIMARY,
        inactivity_timer: int = DEFAULT_INACTIVITY_TIMER,
        auto_keepalive: bool = False,
        dr_retries: int = DR_MAX_RETRIES,
        dr_retry_delay: int = DR_RETRY_DELAY_MS,
        version: int = HARTIPVersion.V1,
        tls: bool | None = None,
        psk_identity: str | None = None,
        psk_key: bytes | None = None,
        ciphers: str | None = None,
        ca_certs: str | None = None,
        certfile: str | None = None,
        keyfile: str | None = None,
        cert_validator: Callable[[dict[str, Any]], bool] | None = None,
        ssl_context: ssl.SSLContext | None = None,
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
        self.version = version
        self._psk_identity = psk_identity
        self._psk_key = psk_key
        self._ciphers = ciphers
        self._ca_certs = ca_certs
        self._certfile = certfile
        self._keyfile = keyfile
        self._cert_validator = cert_validator
        self._ssl_context = ssl_context

        # Warn when ssl_context is provided alongside PSK credentials
        if ssl_context is not None and (psk_identity is not None or psk_key is not None):
            warnings.warn(
                "ssl_context is provided; psk_identity and psk_key will be ignored",
                stacklevel=2,
            )

        # Determine TLS mode: explicit > auto-detect from version
        if tls is not None:
            self._use_tls = tls
        else:
            self._use_tls = version >= HARTIPVersion.V2 and self.protocol == "tcp"

        # Warn about v2+UDP lacking DTLS support
        if version >= HARTIPVersion.V2 and self.protocol == "udp":
            warnings.warn(
                "HART-IP v2 requires DTLS for UDP, but this library only supports "
                "TLS over TCP. The UDP connection will be unencrypted.",
                stacklevel=2,
            )

        self._socket: socket.socket | None = None
        self._connected = False
        self._session_active = False
        self._sequence = 0
        self._lock = threading.Lock()

        # Keep-alive thread state
        self._keepalive_thread: threading.Thread | None = None
        self._keepalive_stop = threading.Event()

    # -- public credential access (read-only, PSK key redacted in repr) ------

    @property
    def psk_identity(self) -> str | None:
        """PSK identity string, or ``None``."""
        return self._psk_identity

    @property
    def psk_key(self) -> bytes | None:
        """PSK key bytes, or ``None``."""
        return self._psk_key

    def __repr__(self) -> str:
        tls_info = ""
        if self._use_tls:
            tls_info = ", tls=True"
            if self._psk_identity is not None:
                tls_info += f", psk_identity={self._psk_identity!r}"
            if self._psk_key is not None:
                tls_info += ", psk_key=<redacted>"
        return (
            f"HARTIPClient({self.host!r}, port={self.port}, "
            f"protocol={self.protocol!r}, version={self.version}"
            f"{tls_info})"
        )

    # -- connection lifecycle ------------------------------------------------

    def connect(self) -> None:
        """Open the transport connection and initiate a HART-IP session.

        If already connected, the existing connection is closed first to
        avoid leaking the socket.

        For HART-IP v2 with ``tls=True`` (or ``version=2`` over TCP),
        the TCP socket is wrapped in TLS 1.2+ with the configured cipher
        suites and optional PSK authentication.

        Raises:
            HARTIPConnectionError: On socket or session failure.
            HARTIPTLSError: On TLS handshake or configuration failure.
        """
        # Close existing connection before creating a new one
        if self._connected or self._socket is not None:
            self.close()

        try:
            if self.protocol == "tcp":
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_sock.settimeout(self.timeout)
                raw_sock.connect((self.host, self.port))

                if self._use_tls:
                    self._socket = self._wrap_tls(raw_sock)
                else:
                    self._socket = raw_sock
            else:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._socket.settimeout(self.timeout)
            self._connected = True
        except HARTIPTLSError:
            self._connected = False
            raise
        except OSError as exc:
            self._connected = False
            raise HARTIPConnectionError(
                f"Failed to connect to {self.host}:{self.port}: {exc}"
            ) from exc

        # Initiate HART-IP session
        self._sequence = 0
        try:
            self._initiate_session()
        except Exception:
            self.close()
            raise

        # Start keep-alive thread if requested
        if self.auto_keepalive and self.inactivity_timer > 0:
            self._start_keepalive()

    def _wrap_tls(self, sock: socket.socket) -> ssl.SSLSocket:
        """Wrap a TCP socket in TLS 1.2+ for HART-IP v2.

        Uses the pre-configured ``ssl_context`` if provided, otherwise
        creates a TLS context with HART-IP v2 cipher suites and optional
        PSK authentication.

        Args:
            sock: Connected TCP socket.

        Returns:
            TLS-wrapped socket.

        Raises:
            HARTIPTLSError: On TLS handshake or configuration failure.
        """
        ctx = self._ssl_context
        if ctx is None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

            # Load CA certs for server verification if provided
            if self._ca_certs is not None:
                try:
                    ctx.load_verify_locations(self._ca_certs)
                except (ssl.SSLError, OSError) as exc:
                    sock.close()
                    raise HARTIPTLSError(
                        f"Failed to load CA certificates: {exc}", ssl_error=exc
                    ) from exc
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.check_hostname = True
            else:
                # HART-IP devices typically use self-signed or no certificates
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            # Load client certificate for mutual TLS if provided
            if self._certfile is not None:
                try:
                    ctx.load_cert_chain(self._certfile, self._keyfile)
                except ssl.SSLError as exc:
                    sock.close()
                    raise HARTIPTLSError(
                        f"Failed to load client certificate: {exc}", ssl_error=exc
                    ) from exc

            # Set cipher suites
            cipher_string = self._ciphers or HARTIP_V2_ALL_CIPHERS
            try:
                ctx.set_ciphers(cipher_string)
            except ssl.SSLError as exc:
                sock.close()
                raise HARTIPTLSError(
                    f"Failed to set cipher suites ({cipher_string!r}): {exc}",
                    ssl_error=exc,
                ) from exc

            # Configure PSK callback if credentials provided
            if self._psk_identity is not None and self._psk_key is not None:
                psk_id = self._psk_identity
                psk_bytes = self._psk_key

                if hasattr(ctx, "set_psk_client_callback"):

                    def _psk_callback(
                        _hint: str | None,
                    ) -> tuple[str | None, bytes]:
                        return (psk_id, psk_bytes)

                    ctx.set_psk_client_callback(_psk_callback)
                else:
                    logger.warning(
                        "PSK callbacks require Python 3.13+; TLS-PSK authentication not available"
                    )

        try:
            # Only set server_hostname when check_hostname is enabled
            hostname = self.host if ctx.check_hostname else None
            tls_sock = ctx.wrap_socket(sock, server_hostname=hostname)
        except ssl.SSLError as exc:
            sock.close()
            raise HARTIPTLSError(f"TLS handshake failed: {exc}", ssl_error=exc) from exc

        # Post-handshake custom certificate validation
        if self._cert_validator is not None:
            peer_cert = tls_sock.getpeercert()
            try:
                accepted = self._cert_validator(peer_cert)
            except Exception as exc:
                tls_sock.close()
                raise HARTIPTLSError(f"Certificate validation callback raised: {exc}") from exc
            if not accepted:
                tls_sock.close()
                raise HARTIPTLSError("Certificate rejected by cert_validator callback")

        return tls_sock

    def _initiate_session(self) -> None:
        """Send Session Initiate (msg_id=0) and validate the response.

        Per the C# reference, both status 0 (SUCCESS) and status 8
        (SET_TO_NEAREST_VALUE -- server adjusted the inactivity timer)
        are accepted as valid session initiation results.
        """
        frame = build_session_init(
            sequence=self._next_sequence(),
            master_type=self.master_type,
            inactivity_timer=self.inactivity_timer,
            version=self.version,
        )
        raw = self._send_recv(frame)
        header = HARTIPHeader.parse(raw[:HARTIP_HEADER_SIZE])

        _SESSION_INIT_OK = (
            HARTIPStatus.SUCCESS,
            HARTIPStatus.WARNING_SET_TO_NEAREST_VALUE,
        )
        if header.status not in _SESSION_INIT_OK:
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
            frame = build_session_close(sequence=self._next_sequence(), version=self.version)
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
                # For TLS sockets, try graceful shutdown
                if isinstance(self._socket, ssl.SSLSocket):
                    with contextlib.suppress(OSError, ssl.SSLError):
                        self._socket.unwrap()
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        self._connected = False

    @property
    def connected(self) -> bool:
        """True if the transport connection is open."""
        return self._connected

    @property
    def session_active(self) -> bool:
        """True if a HART-IP session has been established."""
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
                frame = build_keep_alive(sequence=self._next_sequence(), version=self.version)
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
                raw, _ = self._socket.recvfrom(65535)
                return raw
        except TimeoutError as exc:
            raise HARTIPTimeoutError("Operation timed out") from exc
        except OSError as exc:
            raise HARTIPConnectionError(f"Communication error: {exc}") from exc

    def _send_recv(self, frame: bytes) -> bytes:
        """Send a frame and receive the response (thread-safe).

        All send/receive operations are serialized under _lock
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
        unique_addr: bytes | None = None,
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
            unique_addr: Explicit 5-byte unique address. When provided,
                implies ``use_long_frame=True``.

        Returns:
            Parsed :class:`HARTIPResponse`.

        Raises:
            HARTIPConnectionError: Not connected or no active session.
            HARTIPTimeoutError: No response within timeout.
            HARTIPStatusError: HART-IP header status != 0.
            HARTChecksumError: PDU checksum invalid.
            ValueError: use_long_frame is True but unique_addr is None.
        """
        if not self._connected or not self._socket:
            raise HARTIPConnectionError("Not connected")
        if not self._session_active:
            raise HARTIPConnectionError("No active session (call connect() first)")

        # Raise ValueError if use_long_frame without unique_addr
        if use_long_frame and unique_addr is None:
            raise ValueError("use_long_frame=True requires unique_addr (5-byte device address)")

        # Auto-detect long frame when unique_addr is provided
        if unique_addr is not None:
            use_long_frame = True

        if use_long_frame and unique_addr:
            delimiter = HARTFrameType.LONG_FRAME
            addr_bytes = unique_addr[:5]
        else:
            delimiter = HARTFrameType.SHORT_FRAME
            # Short frame address byte: bit 7 = primary master flag,
            # bits 0-5 = polling address (per HART spec & C# reference).
            if self.master_type == MASTER_TYPE_PRIMARY:
                addr_bytes = bytes([(address & 0x3F) | 0x80])
            else:
                addr_bytes = bytes([address & 0x3F])

        # Extended command support (cmd > 253 uses Command 31 wrapper)
        wire_command = command
        wire_data = data
        if command > MAX_SINGLE_BYTE_CMD:
            wire_command = CMD_EXTENDED_CMD
            wire_data = command.to_bytes(2, "big") + data

        # Hold lock for entire sequence-generate + send + receive cycle
        with self._lock:
            frame = build_request(
                sequence=self._next_sequence_unlocked(),
                delimiter=delimiter,
                address=addr_bytes,
                command=wire_command,
                data=wire_data,
                version=self.version,
            )
            raw = self._send_recv_unlocked(frame)

        resp = self._parse(raw)

        # Delayed-response retry logic
        if resp.response_code in DR_RETRY_CODES:
            resp = self._handle_delayed_response(delimiter, addr_bytes, wire_command, wire_data)

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
                    version=self.version,
                )
                raw = self._send_recv_unlocked(frame)

            resp = self._parse(raw)

            if resp.response_code not in DR_RETRY_CODES:
                return resp

            # Exponential backoff: double the delay after the first retry
            if retry > 0 and delay < max_delay:
                delay = min(delay * 2, max_delay)

        logger.warning("Delayed-response retry limit (%d) exceeded", self.dr_retries)
        if resp is None:
            raise HARTIPTimeoutError(f"Delayed-response retry limit ({self.dr_retries}) exceeded")
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

        Uses bytearray for O(n) accumulation instead of
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

        # Validate checksum -- skip preamble bytes (0xFF), they are not
        # included in the XOR checksum per HART spec (Go reference: calcCrc
        # starts after preambles).
        pdu_bytes = data[HARTIP_HEADER_SIZE:]
        preamble_skip = getattr(pdu, "preamble_count", 0)
        frame_after_preambles = pdu_bytes[preamble_skip:]
        frame_without_cksum = frame_after_preambles[:-1]
        expected = xor_checksum(frame_without_cksum)
        if expected != pdu.checksum:
            raise HARTChecksumError(expected, pdu.checksum)

        response_code = 0
        device_status = 0
        payload = b""
        comm_error = False

        if pdu.byte_count >= 2:
            raw_response_byte = pdu.data[0]

            # Check bit 7 for communication error summary
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

    def read_unique_id(
        self, address: int = 0, *, unique_addr: bytes | None = None
    ) -> HARTIPResponse:
        """Command 0: Read Unique Identifier."""
        return self.send_command(HARTCommand.READ_UNIQUE_ID, address, unique_addr=unique_addr)

    def read_primary_variable(
        self, address: int = 0, *, unique_addr: bytes | None = None
    ) -> HARTIPResponse:
        """Command 1: Read Primary Variable."""
        return self.send_command(
            HARTCommand.READ_PRIMARY_VARIABLE, address, unique_addr=unique_addr
        )

    def read_current_and_percent(
        self, address: int = 0, *, unique_addr: bytes | None = None
    ) -> HARTIPResponse:
        """Command 2: Read Loop Current and Percent of Range."""
        return self.send_command(
            HARTCommand.READ_CURRENT_AND_PERCENT, address, unique_addr=unique_addr
        )

    def read_dynamic_variables(
        self, address: int = 0, *, unique_addr: bytes | None = None
    ) -> HARTIPResponse:
        """Command 3: Read Dynamic Variables."""
        return self.send_command(HARTCommand.READ_DYNAMIC_VARS, address, unique_addr=unique_addr)

    def read_device_vars_status(
        self,
        address: int = 0,
        *,
        device_var_codes: Sequence[int] = (0, 1, 2, 3),
        unique_addr: bytes | None = None,
    ) -> HARTIPResponse:
        """Command 9: Read Device Variables with Status.

        Args:
            address: Polling address (0-15) for short frame.
            device_var_codes: Device variable codes to read (1-8 codes).
                Defaults to ``(0, 1, 2, 3)`` for PV, SV, TV, QV.
                The HART spec requires at least 1 code in the request.
            unique_addr: Explicit 5-byte unique address for long frame.

        Returns:
            Parsed :class:`HARTIPResponse`.
        """
        data = bytes(device_var_codes[:8])
        return self.send_command(
            HARTCommand.READ_DEVICE_VARS_STATUS,
            address,
            data=data,
            unique_addr=unique_addr,
        )

    def write_poll_address(
        self,
        poll_address: int,
        loop_current_mode: int = 0,
        address: int = 0,
        *,
        unique_addr: bytes | None = None,
    ) -> HARTIPResponse:
        """Command 6: Write Polling Address.

        Args:
            poll_address: New polling address (0-63).
            loop_current_mode: 0=enabled, 1=disabled.
            address: Polling address for the request frame.
            unique_addr: Explicit 5-byte unique address for long frame.
        """
        data = bytes([poll_address & 0x3F, loop_current_mode & 0x01])
        return self.send_command(
            HARTCommand.WRITE_POLL_ADDRESS,
            address,
            data=data,
            unique_addr=unique_addr,
        )

    def read_loop_config(
        self, address: int = 0, *, unique_addr: bytes | None = None
    ) -> HARTIPResponse:
        """Command 7: Read Loop Configuration."""
        return self.send_command(HARTCommand.READ_LOOP_CONFIG, address, unique_addr=unique_addr)

    def read_dynamic_var_classifications(
        self, address: int = 0, *, unique_addr: bytes | None = None
    ) -> HARTIPResponse:
        """Command 8: Read Dynamic Variable Classifications."""
        return self.send_command(
            HARTCommand.READ_DYNAMIC_VAR_CLASSIFICATION,
            address,
            unique_addr=unique_addr,
        )

    def read_message(self, address: int = 0, *, unique_addr: bytes | None = None) -> HARTIPResponse:
        """Command 12: Read Message (24-byte packed ASCII)."""
        return self.send_command(HARTCommand.READ_MESSAGE, address, unique_addr=unique_addr)

    def read_tag_descriptor_date(
        self, address: int = 0, *, unique_addr: bytes | None = None
    ) -> HARTIPResponse:
        """Command 13: Read Tag, Descriptor, Date."""
        return self.send_command(
            HARTCommand.READ_TAG_DESCRIPTOR_DATE, address, unique_addr=unique_addr
        )

    def read_pv_info(self, address: int = 0, *, unique_addr: bytes | None = None) -> HARTIPResponse:
        """Command 14: Read Primary Variable Transducer Information."""
        return self.send_command(
            HARTCommand.READ_PRIMARY_VAR_INFO, address, unique_addr=unique_addr
        )

    def read_output_info(
        self, address: int = 0, *, unique_addr: bytes | None = None
    ) -> HARTIPResponse:
        """Command 15: Read Output Information."""
        return self.send_command(HARTCommand.READ_OUTPUT_INFO, address, unique_addr=unique_addr)

    def read_final_assembly(
        self, address: int = 0, *, unique_addr: bytes | None = None
    ) -> HARTIPResponse:
        """Command 16: Read Final Assembly Number."""
        return self.send_command(HARTCommand.READ_FINAL_ASSEMBLY, address, unique_addr=unique_addr)

    def write_message(
        self,
        message: str,
        address: int = 0,
        *,
        unique_addr: bytes | None = None,
    ) -> HARTIPResponse:
        """Command 17: Write Message.

        Args:
            message: Message string (up to 32 characters, packed to 24 bytes).
            address: Polling address for the request frame.
            unique_addr: Explicit 5-byte unique address for long frame.
        """
        from .ascii import pack_ascii

        packed = pack_ascii(message.ljust(32)[:32])[:24]
        return self.send_command(
            HARTCommand.WRITE_MESSAGE,
            address,
            data=packed,
            unique_addr=unique_addr,
        )

    def write_tag_descriptor_date(
        self,
        tag: str,
        descriptor: str,
        day: int,
        month: int,
        year: int,
        address: int = 0,
        *,
        unique_addr: bytes | None = None,
    ) -> HARTIPResponse:
        """Command 18: Write Tag, Descriptor, Date.

        Args:
            tag: Tag string (up to 8 characters, packed to 6 bytes).
            descriptor: Descriptor string (up to 16 characters, packed to 12 bytes).
            day: Day of month (1-31).
            month: Month (1-12).
            year: Year offset from 1900 (e.g. 124 for 2024).
            address: Polling address for the request frame.
            unique_addr: Explicit 5-byte unique address for long frame.
        """
        from .ascii import pack_ascii

        tag_packed = pack_ascii(tag.ljust(8)[:8])[:6]
        desc_packed = pack_ascii(descriptor.ljust(16)[:16])[:12]
        data = tag_packed + desc_packed + bytes([day, month, year])
        return self.send_command(
            HARTCommand.WRITE_TAG_DESCRIPTOR_DATE,
            address,
            data=data,
            unique_addr=unique_addr,
        )

    def write_final_assembly(
        self,
        assembly_number: int,
        address: int = 0,
        *,
        unique_addr: bytes | None = None,
    ) -> HARTIPResponse:
        """Command 19: Write Final Assembly Number.

        Args:
            assembly_number: Final assembly number (0-16777215, Unsigned-24).
            address: Polling address for the request frame.
            unique_addr: Explicit 5-byte unique address for long frame.
        """
        data = assembly_number.to_bytes(3, "big")
        return self.send_command(
            HARTCommand.WRITE_FINAL_ASSEMBLY,
            address,
            data=data,
            unique_addr=unique_addr,
        )

    def read_long_tag(
        self, address: int = 0, *, unique_addr: bytes | None = None
    ) -> HARTIPResponse:
        """Command 20: Read Long Tag (HART 6+)."""
        return self.send_command(HARTCommand.READ_LONG_TAG, address, unique_addr=unique_addr)

    def read_additional_status(
        self, address: int = 0, *, unique_addr: bytes | None = None
    ) -> HARTIPResponse:
        """Command 48: Read Additional Transmitter Status."""
        return self.send_command(
            HARTCommand.READ_ADDITIONAL_STATUS, address, unique_addr=unique_addr
        )

    def perform_self_test(
        self, address: int = 0, *, unique_addr: bytes | None = None
    ) -> HARTIPResponse:
        """Command 41: Perform Device Self-Test."""
        return self.send_command(HARTCommand.PERFORM_SELF_TEST, address, unique_addr=unique_addr)

    # -- v2 convenience wrappers (msg_id=4, msg_id=5) -----------------------

    def send_direct_pdu(
        self,
        commands: Sequence[DirectPDUCommand],
        *,
        device_status: int = 0,
        extended_status: int = 0,
    ) -> DirectPDU:
        """Send a Direct PDU request (msg_id=4) and parse the response.

        Direct PDU provides native HART-IP framing without the serial
        token-passing wrapper. Each command uses a 16-bit command number,
        allowing extended commands without the Command 31 mechanism.

        Args:
            commands: List of :class:`DirectPDUCommand` instances.
            device_status: Device status byte (usually 0 for requests).
            extended_status: Extended status byte (usually 0 for requests).

        Returns:
            Parsed :class:`DirectPDU` with response commands.

        Raises:
            HARTIPConnectionError: Not connected or no active session.
            HARTIPTimeoutError: No response within timeout.
            HARTIPStatusError: HART-IP header status != 0.
        """
        from .v2 import (
            build_direct_pdu_request,
            parse_direct_pdu_response,
        )

        if not self._connected or not self._socket:
            raise HARTIPConnectionError("Not connected")
        if not self._session_active:
            raise HARTIPConnectionError("No active session (call connect() first)")

        with self._lock:
            frame = build_direct_pdu_request(
                sequence=self._next_sequence_unlocked(),
                commands=commands,
                device_status=device_status,
                extended_status=extended_status,
                version=self.version,
            )
            raw = self._send_recv_unlocked(frame)

        header = HARTIPHeader.parse(raw[:HARTIP_HEADER_SIZE])

        if header.status != HARTIPStatus.SUCCESS:
            try:
                name = HARTIPStatus(header.status).name
            except ValueError:
                name = f"status {header.status}"
            raise HARTIPStatusError(f"HART-IP error: {name}", header.status)

        payload = raw[HARTIP_HEADER_SIZE:]
        return parse_direct_pdu_response(payload)

    def read_audit_log(
        self,
        start_record: int = 0,
        number_of_records: int = 10,
    ) -> AuditLogResponse:
        """Send a Read Audit Log request (msg_id=5) and parse the response.

        Retrieves session history from the HART-IP server, including
        connection timestamps, security status, and PDU counters.

        Args:
            start_record: First record index to retrieve.
            number_of_records: Number of records to retrieve.

        Returns:
            Parsed :class:`AuditLogResponse`.

        Raises:
            HARTIPConnectionError: Not connected or no active session.
            HARTIPTimeoutError: No response within timeout.
            HARTIPStatusError: HART-IP header status != 0.
        """
        from .v2 import build_audit_log_request, parse_audit_log_response

        if not self._connected or not self._socket:
            raise HARTIPConnectionError("Not connected")
        if not self._session_active:
            raise HARTIPConnectionError("No active session (call connect() first)")

        with self._lock:
            frame = build_audit_log_request(
                sequence=self._next_sequence_unlocked(),
                start_record=start_record,
                number_of_records=number_of_records,
                version=self.version,
            )
            raw = self._send_recv_unlocked(frame)

        header = HARTIPHeader.parse(raw[:HARTIP_HEADER_SIZE])

        if header.status != HARTIPStatus.SUCCESS:
            try:
                name = HARTIPStatus(header.status).name
            except ValueError:
                name = f"status {header.status}"
            raise HARTIPStatusError(f"HART-IP error: {name}", header.status)

        payload = raw[HARTIP_HEADER_SIZE:]
        return parse_audit_log_response(payload)
