"""
Integration tests for HART-IP over TCP against FieldComm hipserver.

Requires a HART-IP hipserver to be running (Docker container or external).

Note: hipserver may only support a single active session at a time.
These tests use function-scoped clients to avoid conflicts with UDP tests.
"""

from __future__ import annotations

import pytest

from hartip import (
    HARTCommand,
    HARTIPClient,
    HARTResponseCode,
    parse_cmd0,
    parse_cmd1,
    parse_cmd3,
)
from hartip.exceptions import HARTIPConnectionError, HARTIPTimeoutError

from .conftest import skip_no_hipserver, skip_no_tcp

pytestmark = [
    pytest.mark.integration,
    skip_no_hipserver,
    skip_no_tcp,
]


@pytest.fixture()
def tcp_client(hart_host, hart_tcp_port):
    """Function-scoped TCP client connected to hipserver."""
    client = HARTIPClient(hart_host, port=hart_tcp_port, protocol="tcp", timeout=5.0)
    client.connect()
    yield client
    client.close()


class TestTCPConnection:
    """Basic TCP connectivity tests."""

    def test_client_connected(self, tcp_client):
        assert tcp_client.connected

    def test_session_active(self, tcp_client):
        assert tcp_client.session_active

    def test_command_0_succeeds(self, tcp_client):
        resp = tcp_client.read_unique_id()
        assert resp.response_code == HARTResponseCode.SUCCESS


class TestTCPReadUniqueId:
    """Command 0 over TCP."""

    def test_parse_device_info(self, tcp_client):
        resp = tcp_client.read_unique_id()
        info = parse_cmd0(resp.payload)
        assert info.manufacturer_id >= 0
        assert info.hart_revision >= 5


class TestTCPReadVariables:
    """Process variable reads over TCP."""

    def test_primary_variable(self, tcp_client):
        try:
            resp = tcp_client.read_primary_variable()
        except HARTIPTimeoutError:
            pytest.skip("hipflowapp does not respond to Command 1 over TCP")
        if resp.response_code == HARTResponseCode.SUCCESS:
            var = parse_cmd1(resp.payload)
            assert var is not None
        else:
            pytest.fail(f"Command 1 failed with response code {resp.response_code}")

    def test_dynamic_variables(self, tcp_client):
        try:
            resp = tcp_client.read_dynamic_variables()
        except HARTIPTimeoutError:
            pytest.skip("hipflowapp does not respond to Command 3 over TCP")
        if resp.response_code == HARTResponseCode.SUCCESS:
            result = parse_cmd3(resp.payload)
            assert len(result["variables"]) >= 1
        else:
            pytest.fail(f"Command 3 failed with response code {resp.response_code}")


class TestTCPMultipleCommands:
    """Send multiple commands over a single TCP connection."""

    def test_sequential_commands(self, tcp_client):
        r0a = tcp_client.read_unique_id()
        r0b = tcp_client.read_unique_id()

        assert r0a.response_code == HARTResponseCode.SUCCESS
        assert r0b.response_code == HARTResponseCode.SUCCESS

        info_a = parse_cmd0(r0a.payload)
        info_b = parse_cmd0(r0b.payload)
        assert info_a.device_id == info_b.device_id


class TestTCPReconnect:
    """Test disconnecting and reconnecting over TCP."""

    def test_reconnect(self, hart_host, hart_tcp_port):
        client = HARTIPClient(hart_host, port=hart_tcp_port, protocol="tcp", timeout=5.0)

        # First connection
        client.connect()
        resp = client.read_unique_id()
        assert resp.response_code == HARTResponseCode.SUCCESS
        client.close()

        # Second connection
        client.connect()
        resp = client.read_unique_id()
        assert resp.response_code == HARTResponseCode.SUCCESS
        client.close()
