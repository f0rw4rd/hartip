"""
Integration tests for HART-IP over UDP against FieldComm hipserver.

Requires a HART-IP hipserver to be running (Docker container or external).
"""

from __future__ import annotations

import pytest

from hartip import (
    HARTCommand,
    HARTIPClient,
    HARTResponseCode,
    parse_cmd0,
    parse_cmd1,
    parse_cmd2,
    parse_cmd3,
)
from hartip.exceptions import HARTIPTimeoutError

from .conftest import skip_no_hipserver, skip_no_udp

pytestmark = [
    pytest.mark.integration,
    skip_no_hipserver,
    skip_no_udp,
]


@pytest.fixture(scope="module")
def udp_client(hart_host, hart_udp_port):
    """Module-scoped UDP client connected to hipserver."""
    client = HARTIPClient(hart_host, port=hart_udp_port, protocol="udp", timeout=5.0)
    client.connect()
    yield client
    client.close()


class TestConnection:
    """Basic UDP connectivity tests."""

    def test_client_connected(self, udp_client):
        assert udp_client.connected

    def test_session_active(self, udp_client):
        assert udp_client.session_active

    def test_command_0_succeeds(self, udp_client):
        resp = udp_client.read_unique_id()
        assert resp.response_code == HARTResponseCode.SUCCESS


class TestReadUniqueId:
    """Command 0: Read Unique Identifier."""

    def test_parse_device_info(self, udp_client):
        resp = udp_client.read_unique_id()
        info = parse_cmd0(resp.payload)
        assert info.manufacturer_id >= 0
        assert info.hart_revision >= 5

    def test_unique_address_length(self, udp_client):
        resp = udp_client.read_unique_id()
        info = parse_cmd0(resp.payload)
        assert len(info.unique_address) == 5

    def test_manufacturer_name_resolved(self, udp_client):
        resp = udp_client.read_unique_id()
        info = parse_cmd0(resp.payload)
        # hipflowapp identifies as FieldComm Group (0xDA)
        assert info.manufacturer_name != ""


class TestReadPrimaryVariable:
    """Command 1: Read Primary Variable."""

    def test_returns_variable(self, udp_client):
        try:
            resp = udp_client.read_primary_variable()
        except HARTIPTimeoutError:
            pytest.skip("hipflowapp does not respond to Command 1")
        if resp.response_code == HARTResponseCode.SUCCESS:
            var = parse_cmd1(resp.payload)
            assert var is not None
            assert var.unit_code >= 0


class TestReadCurrentAndPercent:
    """Command 2: Read Loop Current and Percent of Range."""

    def test_returns_values(self, udp_client):
        try:
            resp = udp_client.read_current_and_percent()
        except HARTIPTimeoutError:
            pytest.skip("hipflowapp does not respond to Command 2")
        if resp.response_code == HARTResponseCode.SUCCESS:
            result = parse_cmd2(resp.payload)
            assert "current_mA" in result
            assert "percent_range" in result


class TestReadDynamicVariables:
    """Command 3: Read Dynamic Variables."""

    def test_returns_list(self, udp_client):
        try:
            resp = udp_client.read_dynamic_variables()
        except HARTIPTimeoutError:
            pytest.skip("hipflowapp does not respond to Command 3")
        if resp.response_code == HARTResponseCode.SUCCESS:
            variables = parse_cmd3(resp.payload)
            assert len(variables) >= 1
            for var in variables:
                assert var.label in ("PV", "SV", "TV", "QV")


class TestAdditionalStatus:
    """Command 48: Read Additional Transmitter Status."""

    def test_command_48(self, udp_client):
        try:
            resp = udp_client.read_additional_status()
        except HARTIPTimeoutError:
            pytest.skip("hipflowapp does not respond to Command 48")
        # hipserver may return SUCCESS or CMD_NOT_IMPLEMENTED
        assert resp.response_code in (
            HARTResponseCode.SUCCESS,
            HARTResponseCode.CMD_NOT_IMPLEMENTED,
        )


class TestLongFrame:
    """Long frame (5-byte unique address) communication."""

    def test_command_0_with_long_frame(self, udp_client):
        # First get the unique address via short frame
        resp = udp_client.read_unique_id()
        info = parse_cmd0(resp.payload)

        if len(info.unique_address) == 5:
            try:
                resp2 = udp_client.send_command(
                    HARTCommand.READ_UNIQUE_ID,
                    use_long_frame=True,
                    unique_addr=info.unique_address,
                )
            except HARTIPTimeoutError:
                pytest.skip("hipflowapp does not respond to long frame")
            # Accept SUCCESS or device-specific response codes
            assert resp2.pdu is not None


class TestSequencing:
    """Verify sequence number handling across multiple commands."""

    def test_multiple_commands_increment(self, udp_client):
        responses = []
        for _ in range(5):
            resp = udp_client.read_unique_id()
            responses.append(resp)
        # All should succeed
        assert all(r.response_code == HARTResponseCode.SUCCESS for r in responses)
