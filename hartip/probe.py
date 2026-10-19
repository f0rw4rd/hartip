"""
HART-IP server version probe.

:func:`probe_server_version` tells a v1 server from a v2 (TLS-capable)
one with a single plaintext Session Initiate.
"""

from __future__ import annotations

import contextlib
import socket

from ._transport import recv_exact
from .constants import (
    HARTIP_HEADER_SIZE,
    HARTIP_TCP_PORT,
    HARTIPMessageID,
    HARTIPStatus,
    HARTIPVersion,
)
from .exceptions import HARTFrameError, HARTIPConnectionError, HARTIPTimeoutError
from .protocol import build_session_close, build_session_init, parse_header

_PROBE_SEQUENCE = 1


def probe_server_version(
    host: str,
    port: int = HARTIP_TCP_PORT,
    *,
    timeout: float = 3.0,
) -> int:
    """Probe a HART-IP server to discover its protocol version.

    Sends a version-2 Session Initiate over TCP and inspects the
    response status to determine TLS capability:

    - ``status=0`` (SUCCESS) → server supports v2 (TLS)
    - ``status=9`` (ERROR_SECURITY_NOT_INITIALIZED) → server is v1 only

    The session is immediately closed without TLS negotiation.

    Args:
        host: Target device hostname or IP address.
        port: Target TCP port (default 5094).
        timeout: Socket timeout in seconds.

    Returns:
        The server's HART-IP version (1 or 2).

    Raises:
        HARTIPConnectionError: On socket failure.
        HARTIPTimeoutError: No response within timeout.
        HARTFrameError: The reply does not answer the probe.
    """
    sock = _connect(host, port, timeout)
    try:
        return _probe(sock)
    except TimeoutError as exc:
        raise HARTIPTimeoutError("Version probe timed out") from exc
    except OSError as exc:
        raise HARTIPConnectionError(f"Version probe failed: {exc}") from exc
    finally:
        # Best-effort session close, then tear down.
        with contextlib.suppress(OSError):
            sock.sendall(build_session_close(sequence=_PROBE_SEQUENCE + 1, version=2))
        sock.close()


def _connect(host: str, port: int, timeout: float) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, port))
    except OSError as exc:
        sock.close()
        raise HARTIPConnectionError(f"Failed to connect to {host}:{port}: {exc}") from exc
    return sock


def _probe(sock: socket.socket) -> int:
    # Both v1 and v2 servers answer a version-2 Session Initiate.
    sock.sendall(
        build_session_init(
            sequence=_PROBE_SEQUENCE, master_type=1, inactivity_timer=5000, version=2
        )
    )
    header = parse_header(recv_exact(sock, HARTIP_HEADER_SIZE))
    if header.msg_id != HARTIPMessageID.SESSION_INITIATE or header.sequence != _PROBE_SEQUENCE:
        raise HARTFrameError(
            f"Unexpected reply to version probe (id {header.msg_id}, seq {header.sequence})"
        )
    # Drain the body; the verdict is in the header, so EOF here is harmless.
    with contextlib.suppress(HARTIPConnectionError):
        recv_exact(sock, header.payload_len)
    if header.status == HARTIPStatus.ERROR_SECURITY_NOT_INITIALIZED:
        return HARTIPVersion.V1
    return header.version
