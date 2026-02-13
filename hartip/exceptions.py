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
