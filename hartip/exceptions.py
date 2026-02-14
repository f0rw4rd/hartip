"""
HART protocol exception hierarchy.

Provides specific exception types for different error conditions.
"""

from __future__ import annotations


class HARTError(Exception):
    """Base exception for all HART errors."""

    pass


class HARTIPError(HARTError):
    """HART-IP transport layer errors."""

    pass


class HARTIPTimeoutError(HARTIPError):
    """HART-IP operation timed out."""

    pass


class HARTIPConnectionError(HARTIPError):
    """Failed to establish HART-IP connection."""

    pass


class HARTIPTLSError(HARTIPConnectionError):
    """TLS/DTLS handshake or configuration failure.

    Raised when the TLS layer fails during connection setup.
    Subclass of :class:`HARTIPConnectionError` so existing ``except``
    blocks that catch connection errors still work.

    Attributes:
        ssl_error: The underlying :class:`ssl.SSLError` if available.
    """

    def __init__(self, message: str, ssl_error: object | None = None):
        super().__init__(message)
        self.ssl_error = ssl_error


class HARTIPStatusError(HARTIPError):
    """HART-IP header returned non-zero status."""

    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


class HARTProtocolError(HARTError):
    """HART PDU / application layer errors."""

    pass


class HARTChecksumError(HARTProtocolError):
    """HART PDU checksum mismatch."""

    def __init__(self, expected: int, actual: int):
        super().__init__(f"Checksum mismatch: expected 0x{expected:02X}, got 0x{actual:02X}")
        self.expected = expected
        self.actual = actual


class HARTResponseError(HARTProtocolError):
    """HART command returned an error response code."""

    def __init__(self, message: str, code: int = 0, command: int = 0):
        super().__init__(message)
        self.code = code
        self.command = command


class HARTCommunicationError(HARTProtocolError):
    """HART communication error detected (bit 7 set in response code byte).

    The error_flags byte encodes:
        Bit 6: Vertical parity error
        Bit 5: Overrun error
        Bit 4: Framing error
        Bit 3: Longitudinal parity error
        Bit 1: Buffer overflow
    """

    def __init__(self, flags: int):
        parts = []
        if flags & 0x40:
            parts.append("vertical_parity")
        if flags & 0x20:
            parts.append("overrun")
        if flags & 0x10:
            parts.append("framing")
        if flags & 0x08:
            parts.append("longitudinal_parity")
        if flags & 0x02:
            parts.append("buffer_overflow")
        desc = ", ".join(parts) if parts else "unknown"
        super().__init__(f"Communication error: {desc} (flags=0x{flags:02X})")
        self.flags = flags
