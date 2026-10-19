"""
HART-IP client for TCP and UDP communication.

:class:`HARTIPClient` owns the socket and the session: connect and
STARTTLS upgrade, Session Initiate / Close, keep-alive, sequence numbers
and the request/reply exchange.  The pieces it builds on live in their
own modules:

- :mod:`hartip.response`: :class:`HARTIPResponse` and reply decoding
- :mod:`hartip._tls`: TLS context setup and the handshake
- :mod:`hartip._transport`: frame I/O and reply matching
- :mod:`hartip._commands`: the ``read_*`` / ``write_*`` wrappers
- :mod:`hartip.probe`: :func:`probe_server_version`
"""

from __future__ import annotations

import contextlib
import logging
import socket
import ssl
import threading
import time
import warnings
from collections.abc import Callable, Sequence
from typing import Final

from ._commands import UNSET, CommandsMixin
from ._tls import CertValidator, TLSSettings
from ._transport import (
    FrameKind,
    UDPPeer,
    classify_frame,
    recv_tcp_frame,
    recv_udp_frame,
    resolve_udp_peer,
)
from .constants import (
    CMD_EXTENDED_CMD,
    DEFAULT_INACTIVITY_TIMER,
    DR_MAX_RETRIES,
    DR_RETRY_CODES,
    DR_RETRY_DELAY_MS,
    HARTIP_HEADER_SIZE,
    HARTIP_TCP_PORT,
    HARTIP_UDP_PORT,
    MASTER_TYPE_PRIMARY,
    MAX_SINGLE_BYTE_CMD,
    HARTFrameType,
    HARTIPStatus,
    HARTIPVersion,
)
from .exceptions import HARTError, HARTIPConnectionError, HARTIPTimeoutError
from .probe import probe_server_version
from .protocol import (
    MessageHeader,
    build_keep_alive,
    build_request,
    build_session_close,
    build_session_init,
    parse_header,
)
from .response import (
    HARTIPResponse,
    check_hartip_status,
    check_pdu_reply,
    decode_response,
    status_name,
    unwrap_extended,
)
from .v2 import (
    AuditLogResponse,
    DirectPDU,
    DirectPDUCommand,
    build_audit_log_request,
    build_direct_pdu_request,
    parse_audit_log_response,
    parse_direct_pdu_response,
)

__all__ = ["HARTIPClient", "HARTIPResponse", "probe_server_version"]

logger = logging.getLogger(__name__)

#: Former name of :data:`hartip._commands.UNSET`, kept for importers.
_UNSET: Final = UNSET

PublishCallback = Callable[[HARTIPResponse], None]

# Per the FieldComm C# client, SET_TO_NEAREST_VALUE (the server adjusted
# the inactivity timer) is a successful Session Initiate.
_SESSION_INIT_OK = (HARTIPStatus.SUCCESS, HARTIPStatus.WARNING_SET_TO_NEAREST_VALUE)

# hipserver (hsauditlog.cpp) answers a range past its records with
# SET_TO_NEAREST_VALUE and the clamped records; start_record and
# number_of_records in the body say what was actually returned.
_AUDIT_LOG_OK = (HARTIPStatus.SUCCESS, HARTIPStatus.WARNING_SET_TO_NEAREST_VALUE)


def _frame_address(
    address: int, unique_addr: bytes | None, use_long_frame: bool, master_type: int
) -> tuple[int, bytes]:
    """Return ``(delimiter, address bytes)`` for a request PDU.

    Raises:
        ValueError: *use_long_frame* without *unique_addr*.
    """
    if use_long_frame and unique_addr is None:
        raise ValueError("use_long_frame=True requires unique_addr (5-byte device address)")
    if unique_addr:
        return HARTFrameType.LONG_FRAME, unique_addr[:5]
    # Short frame address byte: bit 7 = primary master flag, bits 0-5 =
    # polling address (HART spec, FieldComm C# client).
    master_flag = 0x80 if master_type == MASTER_TYPE_PRIMARY else 0x00
    return HARTFrameType.SHORT_FRAME, bytes([(address & 0x3F) | master_flag])


def _wire_command(command: int, data: bytes) -> tuple[int, bytes]:
    """Wrap a command above 253 in Command 31 (2-byte expanded number first)."""
    if command > MAX_SINGLE_BYTE_CMD:
        return CMD_EXTENDED_CMD, command.to_bytes(2, "big") + data
    return command, data


def _close_socket(sock: socket.socket) -> None:
    """Close a socket, shutting TLS down gracefully first; never raises."""
    if isinstance(sock, ssl.SSLSocket):
        with contextlib.suppress(OSError):
            sock.unwrap()
    with contextlib.suppress(OSError):
        sock.close()


class HARTIPClient(CommandsMixin):
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
        starttls: Use a STARTTLS-like upgrade model for TLS (default
            ``True``).  Per HCF_SPEC-085 (HART-IP v2), the Session
            Initiate is exchanged in plaintext and TLS is negotiated
            immediately afterwards.  Set to ``False`` to wrap the
            socket in TLS **before** sending the Session Initiate
            (non-standard, for servers that expect TLS from the start).
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
        on_publish: Optional callback ``(HARTIPResponse) -> None`` for
            unsolicited Publish frames (burst-mode data) that arrive while
            the client waits for a reply.  Frames that fail validation are
            not delivered.  It runs after the client lock is released, on
            the thread that made the request (the keep-alive thread for
            frames read during a keep-alive), so it may use the client;
            exceptions it raises are logged.  Publish frames are only read while a
            request is outstanding; there is no background reader.

    Usage::

        from hartip import HARTIPClient, parse_cmd0

        # v1 plaintext (default)
        with HARTIPClient("192.168.1.100") as client:
            resp = client.read_unique_id()
            info = parse_cmd0(resp.payload)

        # v2 with TLS-PSK over TCP (STARTTLS -- spec-compliant default)
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
        starttls: bool = True,
        psk_identity: str | None = None,
        psk_key: bytes | None = None,
        ciphers: str | None = None,
        ca_certs: str | None = None,
        certfile: str | None = None,
        keyfile: str | None = None,
        cert_validator: CertValidator | None = None,
        ssl_context: ssl.SSLContext | None = None,
        on_publish: PublishCallback | None = None,
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
        self._starttls = starttls
        self._tls = TLSSettings(
            psk_identity=psk_identity,
            psk_key=psk_key,
            ciphers=ciphers,
            ca_certs=ca_certs,
            certfile=certfile,
            keyfile=keyfile,
            cert_validator=cert_validator,
            ssl_context=ssl_context,
        )

        if ssl_context is not None and (psk_identity is not None or psk_key is not None):
            warnings.warn(
                "ssl_context is provided; psk_identity and psk_key will be ignored",
                stacklevel=2,
            )

        # Explicit ``tls`` wins; otherwise v2 over TCP means TLS.
        self._use_tls = (
            tls if tls is not None else version >= HARTIPVersion.V2 and self.protocol == "tcp"
        )

        if version >= HARTIPVersion.V2 and self.protocol == "udp":
            warnings.warn(
                "HART-IP v2 requires DTLS for UDP, but this library only supports "
                "TLS over TCP. The UDP connection will be unencrypted.",
                stacklevel=2,
            )

        # Default address for convenience methods.  Users may set these
        # after connecting so that address/unique_addr need not be passed
        # on every call.  ``read_unique_id()`` auto-populates
        # ``default_unique_addr`` on success.
        self.default_address: int = 0
        self.default_unique_addr: bytes | None = None

        self._socket: socket.socket | None = None
        self._udp_peer: UDPPeer | None = None
        self._connected = False
        self._session_active = False
        self.server_version: int | None = None
        self._sequence = 0
        self._lock = threading.Lock()
        self._on_publish = on_publish
        self._pending_publishes: list[bytes] = []

        self._keepalive_thread: threading.Thread | None = None
        self._keepalive_stop = threading.Event()

    # -- public credential access (read-only, PSK key redacted in repr) ------

    @property
    def psk_identity(self) -> str | None:
        """PSK identity string, or ``None``."""
        return self._tls.psk_identity

    @property
    def psk_key(self) -> bytes | None:
        """PSK key bytes, or ``None``."""
        return self._tls.psk_key

    def __repr__(self) -> str:
        tls_info = ""
        if self._use_tls:
            tls_info = ", tls=True"
            if self.psk_identity is not None:
                tls_info += f", psk_identity={self.psk_identity!r}"
            if self.psk_key is not None:
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

        For HART-IP v2 with TLS enabled (the default for ``version=2``
        over TCP), the connection follows the HCF_SPEC-085 STARTTLS
        model by default:

        1. TCP connect (plaintext)
        2. Session Initiate exchanged in plaintext
        3. Socket upgraded to TLS
        4. All subsequent traffic is encrypted

        When ``starttls=False``, TLS is established before the Session
        Initiate (non-standard, for servers that expect TLS from the
        start).

        Raises:
            HARTIPConnectionError: On socket or session failure.
            HARTIPTLSError: On TLS handshake or configuration failure.
        """
        if self._connected or self._socket is not None:
            self.close()

        self._socket = self._open_socket()
        self._connected = True
        self._sequence = 0
        try:
            self._initiate_session()
            if self._use_tls and self._starttls and self.protocol == "tcp":
                # Session Initiate went in plaintext; upgrade before anything else.
                self._socket = self._tls.wrap(self._socket, self.host)
        except Exception:
            self.close()
            raise

        if self.auto_keepalive and self.inactivity_timer > 0:
            self._start_keepalive()

    def _open_socket(self) -> socket.socket:
        """Create the transport socket (TLS-wrapped for direct TLS).

        Raises:
            HARTIPConnectionError: Socket creation, name resolution or
                TCP connect failed.
            HARTIPTLSError: Direct TLS handshake failed.
        """
        try:
            if self.protocol == "tcp":
                return self._open_tcp()
            self._udp_peer = resolve_udp_peer(self.host, self.port)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            return sock
        except OSError as exc:
            raise HARTIPConnectionError(
                f"Failed to connect to {self.host}:{self.port}: {exc}"
            ) from exc

    def _open_tcp(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
        except OSError:
            sock.close()
            raise
        if self._use_tls and not self._starttls:
            # Direct TLS before Session Initiate (non-standard).
            return self._tls.wrap(sock, self.host)
        return sock

    def _initiate_session(self) -> None:
        """Send Session Initiate (msg_id=0) and validate the response.

        Raises:
            HARTIPConnectionError: The server refused the session.
        """
        raw = self._exchange(
            lambda seq: build_session_init(
                sequence=seq,
                master_type=self.master_type,
                inactivity_timer=self.inactivity_timer,
                version=self.version,
            )
        )
        header = parse_header(raw)
        if header.status not in _SESSION_INIT_OK:
            raise HARTIPConnectionError(f"Session initiate failed: {status_name(header.status)}")
        self.server_version = header.version
        self._session_active = True

    def _close_session(self) -> None:
        """Send Session Close (msg_id=1) if session is active."""
        if not self._session_active or self._socket is None:
            return
        # Best-effort; the socket may already be closed (e.g. STARTTLS failure).
        with contextlib.suppress(OSError, HARTError):
            self._exchange(lambda seq: build_session_close(sequence=seq, version=self.version))
        self._session_active = False

    def close(self) -> None:
        """Close the HART-IP session and transport connection."""
        self._stop_keepalive()
        self._close_session()
        sock, self._socket = self._socket, None
        if sock is not None:
            _close_socket(sock)
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
            if not self._connected or not self._session_active or self._socket is None:
                break
            try:
                self._exchange(lambda seq: build_keep_alive(sequence=seq, version=self.version))
            except (OSError, HARTError):
                logger.debug("Keep-alive failed, stopping keep-alive thread")
                break

    # -- sequence generator --------------------------------------------------

    def _next_sequence(self) -> int:
        """Generate the next sequence number (thread-safe)."""
        with self._lock:
            return self._next_sequence_unlocked()

    def _next_sequence_unlocked(self) -> int:
        """Generate the next sequence number (caller must hold _lock)."""
        self._sequence = (self._sequence + 1) & 0xFFFF
        return self._sequence

    # -- send / receive ------------------------------------------------------

    def _exchange(self, build: Callable[[int], bytes]) -> bytes:
        """Build a frame for the next sequence number, send it, return the reply.

        ``build`` receives the sequence number.  Drawing the number and
        sending happen under one ``_lock`` hold.  Publish frames read
        meanwhile are delivered after the lock is released so an
        ``on_publish`` callback can call back into the client without
        deadlocking.
        """
        try:
            with self._lock:
                return self._send_recv_unlocked(build(self._next_sequence_unlocked()))
        finally:
            self._deliver_publishes()

    def _require_socket(self) -> socket.socket:
        if self._socket is None:
            raise HARTIPConnectionError("Not connected")
        return self._socket

    def _require_session(self) -> None:
        """Raise :class:`HARTIPConnectionError` unless a session is open."""
        if not self._connected or self._socket is None:
            raise HARTIPConnectionError("Not connected")
        if not self._session_active:
            raise HARTIPConnectionError("No active session (call connect() first)")

    def _peer(self) -> UDPPeer:
        """UDP server address, resolved on first use."""
        if self._udp_peer is None:
            self._udp_peer = resolve_udp_peer(self.host, self.port)
        return self._udp_peer

    def _send_recv_unlocked(self, frame: bytes) -> bytes:
        """Send a frame and return the reply that answers it (caller must hold _lock).

        A reply answers the request when it is a Response, Error or NAK
        message carrying the request's sequence number and message id.
        Anything else that arrives first is skipped: unsolicited Publish
        frames, late replies to earlier requests, and on UDP datagrams from
        another address or too short to hold a HART-IP header.  Waiting is
        bounded by ``timeout`` in total, not per received frame.

        The returned bytes are cut to the header's ``byte_count``.
        """
        sock = self._require_socket()
        try:
            if self.protocol == "tcp":
                sock.sendall(frame)
            else:
                sock.sendto(frame, self._peer())
            return self._await_reply(
                sock, sequence=int.from_bytes(frame[4:6], "big"), msg_id=frame[2]
            )
        except TimeoutError as exc:
            raise HARTIPTimeoutError("Operation timed out") from exc
        except OSError as exc:
            raise HARTIPConnectionError(f"Communication error: {exc}") from exc
        finally:
            with contextlib.suppress(OSError):
                sock.settimeout(self.timeout)

    def _await_reply(self, sock: socket.socket, sequence: int, msg_id: int) -> bytes:
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HARTIPTimeoutError("Operation timed out")
            sock.settimeout(remaining)
            raw = (
                recv_tcp_frame(sock)
                if self.protocol == "tcp"
                else recv_udp_frame(sock, self._peer())
            )
            if raw is None:
                continue
            header = parse_header(raw)
            kind = classify_frame(header, sequence, msg_id)
            if kind is FrameKind.REPLY:
                return raw
            self._skip_frame(raw, header, kind, sequence, msg_id)

    def _skip_frame(
        self, raw: bytes, header: MessageHeader, kind: FrameKind, sequence: int, msg_id: int
    ) -> None:
        """Queue a Publish frame for ``on_publish`` or log and drop a stale one."""
        if kind is FrameKind.PUBLISH and self._on_publish is not None:
            self._pending_publishes.append(raw)
        elif kind is FrameKind.PUBLISH:
            logger.debug("Skipping publish frame (seq %d)", header.sequence)
        else:
            logger.debug(
                "Discarding stale frame (type %d, id %d, seq %d) while waiting for id %d seq %d",
                header.msg_type,
                header.msg_id,
                header.sequence,
                msg_id,
                sequence,
            )

    def _deliver_publishes(self) -> None:
        callback = self._on_publish
        if not self._pending_publishes or callback is None:
            return
        with self._lock:
            pending, self._pending_publishes = self._pending_publishes, []
        for raw in pending:
            try:
                resp = self._decode_publish(raw)
            except HARTError as exc:
                logger.debug("Dropping invalid publish frame: %s", exc)
                continue
            try:
                callback(resp)
            except Exception:
                logger.exception("on_publish callback raised")

    @staticmethod
    def _decode_publish(raw: bytes) -> HARTIPResponse:
        resp = decode_response(raw)
        if resp.pdu is not None and resp.pdu.command == CMD_EXTENDED_CMD:
            unwrap_extended(resp, None)
        return resp

    # -- HART PDU pass-through (msg_id=3) ------------------------------------

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
            address: Polling address (0-63) for short frame.
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
        self._require_session()
        delimiter, addr_bytes = _frame_address(
            address, unique_addr, use_long_frame, self.master_type
        )
        wire_command, wire_data = _wire_command(command, data)

        resp = self._transact(delimiter, addr_bytes, wire_command, wire_data)
        if resp.response_code in DR_RETRY_CODES:
            resp = self._handle_delayed_response(delimiter, addr_bytes, wire_command, wire_data)

        if wire_command != command:
            unwrap_extended(resp, command)
        return resp

    def _transact(
        self, delimiter: int, addr_bytes: bytes, command: int, data: bytes
    ) -> HARTIPResponse:
        """One pass-through request; the reply must echo *command*."""
        raw = self._exchange(
            lambda seq: build_request(
                sequence=seq,
                delimiter=delimiter,
                address=addr_bytes,
                command=command,
                data=data,
                version=self.version,
            )
        )
        resp = decode_response(raw)
        check_pdu_reply(resp, command)
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
        resp: HARTIPResponse | None = None

        for retry in range(self.dr_retries):
            time.sleep(delay)
            resp = self._transact(delimiter, addr_bytes, command, data)
            if resp.response_code not in DR_RETRY_CODES:
                return resp
            # Exponential backoff: double the delay after the first retry
            if retry > 0:
                delay = min(delay * 2, max_delay)

        logger.warning("Delayed-response retry limit (%d) exceeded", self.dr_retries)
        if resp is None:
            raise HARTIPTimeoutError(f"Delayed-response retry limit ({self.dr_retries}) exceeded")
        return resp

    # -- HART-IP v2 (msg_id=4, msg_id=5) -------------------------------------

    def _exchange_v2(self, build: Callable[[int], bytes], accept: Sequence[int]) -> bytes:
        """Exchange a v2 message; return its body after checking the header status."""
        self._require_session()
        raw = self._exchange(build)
        header = parse_header(raw)
        check_hartip_status(header, accept)
        if header.status == HARTIPStatus.WARNING_SET_TO_NEAREST_VALUE:
            logger.debug("Request range adjusted by server")
        return raw[HARTIP_HEADER_SIZE:]

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
        body = self._exchange_v2(
            lambda seq: build_direct_pdu_request(
                sequence=seq,
                commands=commands,
                device_status=device_status,
                extended_status=extended_status,
                version=self.version,
            ),
            accept=(HARTIPStatus.SUCCESS,),
        )
        return parse_direct_pdu_response(body)

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
            HARTIPStatusError: HART-IP header status other than 0 or 8
                (SET_TO_NEAREST_VALUE, the server clamped the range).
        """
        body = self._exchange_v2(
            lambda seq: build_audit_log_request(
                sequence=seq,
                start_record=start_record,
                number_of_records=number_of_records,
                version=self.version,
            ),
            accept=_AUDIT_LOG_OK,
        )
        return parse_audit_log_response(body)
