"""Unit tests for hartip._tls.TLSSettings (context setup and handshake)."""

from __future__ import annotations

import logging
import ssl
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from hartip._tls import TLSSettings
from hartip.constants import HARTIP_V2_PSK_CIPHERS
from hartip.exceptions import HARTIPTLSError

# Self-signed P-256 certificate and key made for these tests only
# (openssl req -x509 -newkey ec -subj /CN=hartip-test -days 36500).
TEST_CERT = """\
-----BEGIN CERTIFICATE-----
MIIBgzCCASmgAwIBAgIUAVvP98PYAU98YAt8283T+q0F6/wwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLaGFydGlwLXRlc3QwIBcNMjYxMDE5MjEyOTQ5WhgPMjEyNjA5
MjUyMTI5NDlaMBYxFDASBgNVBAMMC2hhcnRpcC10ZXN0MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEqnS2XBC3Ly38Wvq+YKq2DLzyv9nH7bmOt1OV/F4NJcb7zZDD
wHxdeWP3lWZCmpoMaofnU4aJQSA0sOoQwk3MXqNTMFEwHQYDVR0OBBYEFOz0rOmR
SHqkIpNFhaCaC6NzqICNMB8GA1UdIwQYMBaAFOz0rOmRSHqkIpNFhaCaC6NzqICN
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgM/EWqPbU35prAarq
qhqMXZ/hmSx9Sr7bz1iUix2n5ZsCIQDuCdBLCa3DOVqkyBGr3L2WJXVeU58ZxgH9
/ASHKtANEQ==
-----END CERTIFICATE-----
"""
TEST_KEY = """\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFdDh1gqezx1ZFf/M
mmf/3cUemsFFfuMwticCCuudAIWhRANCAASqdLZcELcvLfxa+r5gqrYMvPK/2cft
uY63U5X8Xg0lxvvNkMPAfF15Y/eVZkKamgxqh+dTholBIDSw6hDCTcxe
-----END PRIVATE KEY-----
"""


@pytest.fixture
def cert_files(tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text(TEST_CERT)
    key.write_text(TEST_KEY)
    return str(cert), str(key)


class TestRepr:
    def test_key_redacted(self) -> None:
        text = repr(TLSSettings(psk_identity="client1", psk_key=b"\x01\x02secret"))
        assert "client1" in text
        assert "<redacted>" in text
        assert "secret" not in text
        assert "\\x01" not in text

    def test_no_key(self) -> None:
        assert "psk_key=None" in repr(TLSSettings())


class TestCreateContext:
    def test_defaults(self) -> None:
        ctx = TLSSettings().create_context()
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
        assert ctx.verify_mode == ssl.CERT_NONE
        assert ctx.check_hostname is False

    def test_ssl_context_used_as_is(self) -> None:
        given = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        settings = TLSSettings(ssl_context=given, ca_certs="/nonexistent", ciphers="BOGUS")
        assert settings.create_context() is given

    def test_ca_certs_require_verification(self, cert_files) -> None:
        ctx = TLSSettings(ca_certs=cert_files[0]).create_context()
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

    def test_missing_ca_file(self, tmp_path) -> None:
        with pytest.raises(HARTIPTLSError, match="Failed to load CA certificates"):
            TLSSettings(ca_certs=str(tmp_path / "missing.pem")).create_context()

    def test_invalid_ca_file(self, tmp_path) -> None:
        bad = tmp_path / "bad.pem"
        bad.write_text("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n")
        with pytest.raises(HARTIPTLSError, match="Failed to load CA certificates"):
            TLSSettings(ca_certs=str(bad)).create_context()

    def test_client_certificate(self, cert_files) -> None:
        TLSSettings(certfile=cert_files[0], keyfile=cert_files[1]).create_context()

    def test_missing_client_certificate(self, tmp_path) -> None:
        with pytest.raises(HARTIPTLSError, match="Failed to load client certificate"):
            TLSSettings(certfile=str(tmp_path / "missing.pem")).create_context()

    def test_client_certificate_without_key(self, cert_files) -> None:
        with pytest.raises(HARTIPTLSError, match="Failed to load client certificate"):
            TLSSettings(certfile=cert_files[0]).create_context()

    def test_bad_cipher_string(self) -> None:
        with pytest.raises(HARTIPTLSError, match="Failed to set cipher suites"):
            TLSSettings(ciphers="NO-SUCH-CIPHER").create_context()

    def test_psk_caps_at_tls12(self) -> None:
        ctx = TLSSettings(
            psk_identity="client1", psk_key=b"\x00" * 16, ciphers=HARTIP_V2_PSK_CIPHERS
        ).create_context()
        assert ctx.maximum_version == ssl.TLSVersion.TLSv1_2

    def test_identity_without_key_is_not_psk(self) -> None:
        ctx = TLSSettings(psk_identity="client1").create_context()
        assert ctx.maximum_version != ssl.TLSVersion.TLSv1_2


class TestConfigurePsk:
    def test_callback_returns_credentials(self) -> None:
        ctx = MagicMock()
        with patch("hartip._tls.sys", SimpleNamespace(version_info=(3, 13, 0))):
            TLSSettings._configure_psk(ctx, "client1", b"k" * 16)
        assert ctx.maximum_version == ssl.TLSVersion.TLSv1_2
        callback = ctx.set_psk_client_callback.call_args[0][0]
        assert callback(None) == ("client1", b"k" * 16)
        assert callback("server hint") == ("client1", b"k" * 16)

    def test_old_python_warns(self, caplog) -> None:
        ctx = MagicMock()
        with (
            patch("hartip._tls.sys", SimpleNamespace(version_info=(3, 12, 0))),
            caplog.at_level(logging.WARNING, logger="hartip._tls"),
        ):
            TLSSettings._configure_psk(ctx, "client1", b"secretkey1234567")
        ctx.set_psk_client_callback.assert_not_called()
        assert "Python 3.13+" in caplog.text
        assert "secretkey" not in caplog.text

    @pytest.mark.skipif(sys.version_info < (3, 13), reason="PSK callbacks need 3.13+")
    def test_real_context_accepts_callback(self) -> None:
        TLSSettings(psk_identity="client1", psk_key=b"\x00" * 16).create_context()


def _settings_with_context(ctx: MagicMock, **kwargs) -> TLSSettings:
    return TLSSettings(ssl_context=ctx, **kwargs)


class TestWrap:
    def test_handshake_failure_closes_socket(self) -> None:
        ctx = MagicMock(check_hostname=False)
        ctx.wrap_socket.side_effect = ssl.SSLError("handshake failed")
        sock = MagicMock()
        with pytest.raises(HARTIPTLSError, match="TLS handshake failed") as info:
            _settings_with_context(ctx).wrap(sock, "dev")
        sock.close.assert_called_once()
        assert isinstance(info.value.ssl_error, ssl.SSLError)

    def test_context_failure_closes_socket(self, tmp_path) -> None:
        sock = MagicMock()
        with pytest.raises(HARTIPTLSError, match="Failed to load CA certificates"):
            TLSSettings(ca_certs=str(tmp_path / "missing.pem")).wrap(sock, "dev")
        sock.close.assert_called_once()

    def test_server_hostname_only_when_checked(self) -> None:
        sock = MagicMock()
        unchecked = MagicMock(check_hostname=False)
        _settings_with_context(unchecked).wrap(sock, "dev.example")
        assert unchecked.wrap_socket.call_args.kwargs["server_hostname"] is None

        checked = MagicMock(check_hostname=True)
        _settings_with_context(checked).wrap(sock, "dev.example")
        assert checked.wrap_socket.call_args.kwargs["server_hostname"] == "dev.example"

    def test_validator_gets_peer_cert(self) -> None:
        seen = []
        ctx = MagicMock(check_hostname=False)
        tls_sock = ctx.wrap_socket.return_value
        tls_sock.getpeercert.return_value = {"subject": ((("commonName", "dev"),),)}
        settings = _settings_with_context(ctx, cert_validator=lambda c: seen.append(c) or True)
        assert settings.wrap(MagicMock(), "dev") is tls_sock
        assert seen == [{"subject": ((("commonName", "dev"),),)}]
        tls_sock.close.assert_not_called()

    def test_validator_gets_empty_dict_without_cert(self) -> None:
        seen = []
        ctx = MagicMock(check_hostname=False)
        ctx.wrap_socket.return_value.getpeercert.return_value = None
        settings = _settings_with_context(ctx, cert_validator=lambda c: seen.append(c) or True)
        settings.wrap(MagicMock(), "dev")
        assert seen == [{}]

    def test_validator_rejects(self) -> None:
        ctx = MagicMock(check_hostname=False)
        tls_sock = ctx.wrap_socket.return_value
        tls_sock.getpeercert.return_value = {}
        settings = _settings_with_context(ctx, cert_validator=lambda _c: False)
        with pytest.raises(HARTIPTLSError, match="rejected by cert_validator"):
            settings.wrap(MagicMock(), "dev")
        tls_sock.close.assert_called_once()

    def test_validator_raises(self) -> None:
        def crash(_cert):
            raise ValueError("pin mismatch")

        ctx = MagicMock(check_hostname=False)
        tls_sock = ctx.wrap_socket.return_value
        tls_sock.getpeercert.return_value = {}
        with pytest.raises(HARTIPTLSError, match="pin mismatch"):
            _settings_with_context(ctx, cert_validator=crash).wrap(MagicMock(), "dev")
        tls_sock.close.assert_called_once()
