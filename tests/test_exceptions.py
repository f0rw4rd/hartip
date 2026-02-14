"""Tests for HART exception hierarchy."""

import pytest

from hartip.exceptions import (
    HARTChecksumError,
    HARTCommunicationError,
    HARTError,
    HARTIPConnectionError,
    HARTIPError,
    HARTIPStatusError,
    HARTIPTimeoutError,
    HARTIPTLSError,
    HARTProtocolError,
    HARTResponseError,
)


class TestExceptionHierarchy:
    def test_hartip_error_is_hart_error(self) -> None:
        assert issubclass(HARTIPError, HARTError)

    def test_timeout_is_hartip_error(self) -> None:
        assert issubclass(HARTIPTimeoutError, HARTIPError)

    def test_connection_is_hartip_error(self) -> None:
        assert issubclass(HARTIPConnectionError, HARTIPError)

    def test_status_is_hartip_error(self) -> None:
        assert issubclass(HARTIPStatusError, HARTIPError)

    def test_protocol_is_hart_error(self) -> None:
        assert issubclass(HARTProtocolError, HARTError)

    def test_checksum_is_protocol_error(self) -> None:
        assert issubclass(HARTChecksumError, HARTProtocolError)

    def test_response_is_protocol_error(self) -> None:
        assert issubclass(HARTResponseError, HARTProtocolError)

    def test_communication_is_protocol_error(self) -> None:
        assert issubclass(HARTCommunicationError, HARTProtocolError)

    def test_tls_error_is_connection_error(self) -> None:
        assert issubclass(HARTIPTLSError, HARTIPConnectionError)

    def test_tls_error_is_hartip_error(self) -> None:
        assert issubclass(HARTIPTLSError, HARTIPError)


class TestHARTChecksumError:
    def test_message(self) -> None:
        exc = HARTChecksumError(expected=0xAB, actual=0xCD)
        assert "0xAB" in str(exc)
        assert "0xCD" in str(exc)
        assert exc.expected == 0xAB
        assert exc.actual == 0xCD


class TestHARTIPStatusError:
    def test_status(self) -> None:
        exc = HARTIPStatusError("test", status=5)
        assert exc.status == 5
        assert "test" in str(exc)


class TestHARTResponseError:
    def test_code_and_command(self) -> None:
        exc = HARTResponseError("error", code=1, command=0)
        assert exc.code == 1
        assert exc.command == 0


class TestHARTCommunicationError:
    def test_vertical_parity(self) -> None:
        exc = HARTCommunicationError(0x40)
        assert exc.flags == 0x40
        assert "vertical_parity" in str(exc)

    def test_overrun(self) -> None:
        exc = HARTCommunicationError(0x20)
        assert "overrun" in str(exc)

    def test_framing(self) -> None:
        exc = HARTCommunicationError(0x10)
        assert "framing" in str(exc)

    def test_longitudinal_parity(self) -> None:
        exc = HARTCommunicationError(0x08)
        assert "longitudinal_parity" in str(exc)

    def test_buffer_overflow(self) -> None:
        exc = HARTCommunicationError(0x02)
        assert "buffer_overflow" in str(exc)

    def test_multiple_flags(self) -> None:
        exc = HARTCommunicationError(0x5A)  # vertical + framing + longitudinal + buffer
        msg = str(exc)
        assert "vertical_parity" in msg
        assert "framing" in msg
        assert "longitudinal_parity" in msg
        assert "buffer_overflow" in msg

    def test_unknown_flags(self) -> None:
        exc = HARTCommunicationError(0x00)
        assert "unknown" in str(exc)


class TestHARTIPTLSError:
    def test_message(self) -> None:
        exc = HARTIPTLSError("TLS handshake failed: bad cert")
        assert "TLS handshake failed" in str(exc)

    def test_ssl_error_attribute(self) -> None:
        import ssl

        ssl_exc = ssl.SSLError("test ssl error")
        exc = HARTIPTLSError("TLS failed", ssl_error=ssl_exc)
        assert exc.ssl_error is ssl_exc

    def test_ssl_error_none_by_default(self) -> None:
        exc = HARTIPTLSError("TLS failed")
        assert exc.ssl_error is None

    def test_caught_by_connection_error(self) -> None:
        """HARTIPTLSError should be catchable as HARTIPConnectionError."""
        exc = HARTIPTLSError("test")
        try:
            raise exc
        except HARTIPConnectionError as caught:
            assert caught is exc
        else:
            pytest.fail("HARTIPTLSError not caught by HARTIPConnectionError")
