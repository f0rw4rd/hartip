"""
TLS for HART-IP v2 over TCP.

:class:`TLSSettings` holds the client's TLS options and turns them into a
configured :class:`ssl.SSLContext` and a wrapped socket.  Defaults: TLS 1.2
minimum, capped at TLS 1.2 when PSK credentials are given, and no
certificate verification unless ``ca_certs`` is set (HART-IP devices
commonly have self-signed or no certificates).
"""

from __future__ import annotations

import logging
import socket
import ssl
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .constants import HARTIP_V2_ALL_CIPHERS
from .exceptions import HARTIPTLSError

logger = logging.getLogger(__name__)

CertValidator = Callable[[dict[str, Any]], bool]
"""Post-handshake check: receives ``SSLSocket.getpeercert()``, returns acceptance."""


@dataclass(frozen=True)
class TLSSettings:
    """TLS options of a :class:`~hartip.client.HARTIPClient`.

    ``ssl_context``, when given, is used as is and the other context
    options are ignored.  ``cert_validator`` applies either way.
    """

    psk_identity: str | None = None
    psk_key: bytes | None = None
    ciphers: str | None = None
    ca_certs: str | None = None
    certfile: str | None = None
    keyfile: str | None = None
    cert_validator: CertValidator | None = None
    ssl_context: ssl.SSLContext | None = None

    def __repr__(self) -> str:
        key = "<redacted>" if self.psk_key is not None else None
        return f"TLSSettings(psk_identity={self.psk_identity!r}, psk_key={key}, ...)"

    def create_context(self) -> ssl.SSLContext:
        """Return the configured client context.

        Raises:
            HARTIPTLSError: A CA file, client certificate or cipher string
                could not be loaded.
        """
        if self.ssl_context is not None:
            return self.ssl_context
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._configure_verification(ctx)
        self._load_client_certificate(ctx)
        self._set_ciphers(ctx)
        if self.psk_identity is not None and self.psk_key is not None:
            self._configure_psk(ctx, self.psk_identity, self.psk_key)
        return ctx

    def wrap(self, sock: socket.socket, host: str) -> ssl.SSLSocket:
        """Run the TLS handshake on a connected TCP socket.

        The socket is closed on any failure.

        Raises:
            HARTIPTLSError: Context setup, handshake or certificate
                validation failed.
        """
        try:
            ctx = self.create_context()
            # server_hostname is only meaningful when the hostname is checked.
            hostname = host if ctx.check_hostname else None
            tls_sock = ctx.wrap_socket(sock, server_hostname=hostname)
        except HARTIPTLSError:
            sock.close()
            raise
        except ssl.SSLError as exc:
            sock.close()
            raise HARTIPTLSError(f"TLS handshake failed: {exc}", ssl_error=exc) from exc
        try:
            self._validate_peer(tls_sock)
        except HARTIPTLSError:
            tls_sock.close()
            raise
        return tls_sock

    def _configure_verification(self, ctx: ssl.SSLContext) -> None:
        if self.ca_certs is None:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return
        try:
            ctx.load_verify_locations(self.ca_certs)
        except (ssl.SSLError, OSError) as exc:
            raise HARTIPTLSError(f"Failed to load CA certificates: {exc}", ssl_error=exc) from exc
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True

    def _load_client_certificate(self, ctx: ssl.SSLContext) -> None:
        if self.certfile is None:
            return
        try:
            ctx.load_cert_chain(self.certfile, self.keyfile)
        except (ssl.SSLError, OSError) as exc:
            raise HARTIPTLSError(
                f"Failed to load client certificate: {exc}", ssl_error=exc
            ) from exc

    def _set_ciphers(self, ctx: ssl.SSLContext) -> None:
        cipher_string = self.ciphers or HARTIP_V2_ALL_CIPHERS
        try:
            ctx.set_ciphers(cipher_string)
        except ssl.SSLError as exc:
            raise HARTIPTLSError(
                f"Failed to set cipher suites ({cipher_string!r}): {exc}", ssl_error=exc
            ) from exc

    @staticmethod
    def _configure_psk(ctx: ssl.SSLContext, identity: str, key: bytes) -> None:
        # OpenSSL serves PSK suites through the TLS 1.2 API; servers such as
        # hipserver register only the legacy PSK callback, which TLS 1.3
        # never invokes.
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        if sys.version_info >= (3, 13):
            ctx.set_psk_client_callback(lambda _hint: (identity, key))
        else:
            logger.warning(
                "PSK callbacks require Python 3.13+; TLS-PSK authentication not available"
            )

    def _validate_peer(self, tls_sock: ssl.SSLSocket) -> None:
        if self.cert_validator is None:
            return
        cert: dict[str, Any] = dict(tls_sock.getpeercert() or {})
        try:
            accepted = self.cert_validator(cert)
        except Exception as exc:
            raise HARTIPTLSError(f"Certificate validation callback raised: {exc}") from exc
        if not accepted:
            raise HARTIPTLSError("Certificate rejected by cert_validator callback")
