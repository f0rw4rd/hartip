"""
Integration tests for HART-IP client against the Python mock server.

The Python mock server (from msf-ics) implements the full HART command set
including error responses, write protection, and multi-device support.

Requires the mock server on HARTIP_TEST_MOCK_UDP_PORT (default 15094) and
HARTIP_TEST_MOCK_TCP_PORT (default 15095).  Start it with::

    HART_UDP_PORT=15094 HART_TCP_PORT=15095 python hart_server.py

Override via environment variables::

    HARTIP_TEST_MOCK_UDP_PORT=15094 HARTIP_TEST_MOCK_TCP_PORT=15095
"""

from __future__ import annotations

import os
import socket

import pytest

from hartip import (
    DeviceInfo,
    HARTCommand,
    HARTIPClient,
    Variable,
    parse_cmd0,
    parse_cmd1,
    parse_cmd7,
    parse_cmd8,
    parse_cmd14,
    parse_cmd16,
)
from hartip.device import parse_cmd3, parse_cmd13, parse_cmd48
from hartip.exceptions import (
    HARTIPConnectionError,
    HARTIPTimeoutError,
    HARTResponseError,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MOCK_HOST = os.environ.get("HARTIP_TEST_HOST", "127.0.0.1")
MOCK_UDP_PORT = int(os.environ.get("HARTIP_TEST_MOCK_UDP_PORT", "25094"))
MOCK_TCP_PORT = int(os.environ.get("HARTIP_TEST_MOCK_TCP_PORT", "25095"))


def _mock_udp_reachable() -> bool:
    """Quick check: send a raw packet and see if we get a response."""
    import struct

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        # Send a minimal session-init frame
        hdr = struct.pack(">BBBBHH", 1, 0, 0, 0, 0, 13)
        payload = struct.pack(">BI", 1, 30000)
        sock.sendto(hdr + payload, (MOCK_HOST, MOCK_UDP_PORT))
        data, _ = sock.recvfrom(1024)
        sock.close()
        return len(data) >= 8
    except (TimeoutError, OSError):
        return False


def _mock_tcp_reachable() -> bool:
    try:
        with socket.create_connection((MOCK_HOST, MOCK_TCP_PORT), timeout=2):
            return True
    except (TimeoutError, ConnectionRefusedError, OSError):
        return False


skip_no_mock_udp = pytest.mark.skipif(
    not _mock_udp_reachable(),
    reason=f"HART-IP mock not reachable on UDP {MOCK_HOST}:{MOCK_UDP_PORT}",
)

skip_no_mock_tcp = pytest.mark.skipif(
    not _mock_tcp_reachable(),
    reason=f"HART-IP mock not reachable on TCP {MOCK_HOST}:{MOCK_TCP_PORT}",
)


# ---------------------------------------------------------------------------
# UDP Tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def udp_client():
    """Per-test UDP client connected to mock server."""
    client = HARTIPClient(MOCK_HOST, port=MOCK_UDP_PORT, protocol="udp", timeout=3.0)
    client.connect()
    yield client
    client.close()


@skip_no_mock_udp
@pytest.mark.integration
class TestUDPReads:
    """Verify that reads return correct data over UDP."""

    def test_read_unique_id(self, udp_client):
        resp = udp_client.read_unique_id()
        assert resp.success
        info = parse_cmd0(resp.payload)
        assert info.manufacturer_id > 0
        assert len(info.unique_address) == 5

    def test_read_primary_variable(self, udp_client):
        resp = udp_client.read_primary_variable()
        assert resp.success
        pv = parse_cmd1(resp.payload)
        assert pv.unit_code >= 0
        assert isinstance(pv.value, float)

    def test_read_dynamic_variables(self, udp_client):
        resp = udp_client.read_dynamic_variables()
        assert resp.success
        vs = parse_cmd3(resp.payload)
        assert "loop_current" in vs
        assert len(vs["variables"]) == 4

    def test_read_tag_descriptor_date(self, udp_client):
        resp = udp_client.read_tag_descriptor_date()
        assert resp.success
        tag = parse_cmd13(resp.payload)
        assert tag["tag"] == "PT-101"
        assert "PRESSURE" in tag["descriptor"].upper()

    def test_read_output_info(self, udp_client):
        resp = udp_client.send_command(HARTCommand.READ_OUTPUT_INFO)
        assert resp.success
        # Mock sends 15 bytes (minimal); full parser expects 18
        assert len(resp.payload) >= 15

    def test_read_additional_status(self, udp_client):
        resp = udp_client.read_additional_status()
        assert resp.success
        status = parse_cmd48(resp.payload)
        assert isinstance(status, dict)

    def test_repr_on_success(self, udp_client):
        resp = udp_client.read_unique_id()
        r = repr(resp)
        assert "cmd=0" in r
        assert "rc=0" in r
        assert "ok" in r


@skip_no_mock_udp
@pytest.mark.integration
class TestUDPErrors:
    """Verify that error conditions are detected and reported correctly."""

    def test_unsupported_command(self, udp_client):
        """Server returns CMD_NOT_IMPLEMENTED for unknown command."""
        resp = udp_client.send_command(200)
        assert not resp.success
        assert resp.response_code != 0
        assert resp.error_message != "SUCCESS"

    def test_unsupported_command_raise_for_error(self, udp_client):
        """raise_for_error() raises HARTResponseError for bad command."""
        resp = udp_client.send_command(200)
        with pytest.raises(HARTResponseError) as exc_info:
            resp.raise_for_error()
        assert exc_info.value.command == 200
        assert exc_info.value.code != 0

    def test_write_too_few_bytes(self, udp_client):
        """Cmd 6 (Write Poll Address) with no data returns TOO_FEW_DATA_BYTES."""
        resp = udp_client.send_command(HARTCommand.WRITE_POLL_ADDRESS)
        assert not resp.success
        # rc=5 in HART spec = TOO_FEW_DATA_BYTES
        assert resp.response_code != 0

    def test_wrong_address(self, udp_client):
        """Command to non-existent address returns error."""
        resp = udp_client.send_command(0, address=15)
        # The mock may return UNDEFINED_COMMAND or similar for unknown device
        assert resp.response_code != 0
        # The key assertion: non-existent address returns an error


@skip_no_mock_udp
@pytest.mark.integration
class TestUDPWrites:
    """Verify write commands succeed and return correct data."""

    def test_write_poll_address(self, udp_client):
        """Cmd 6 with valid data byte succeeds."""
        resp = udp_client.send_command(HARTCommand.WRITE_POLL_ADDRESS, data=bytes([0]))
        assert resp.success

    def test_self_test(self, udp_client):
        """Cmd 41 (Perform Self-Test) succeeds."""
        resp = udp_client.send_command(HARTCommand.PERFORM_SELF_TEST)
        assert resp.success

    def test_master_reset(self, udp_client):
        """Cmd 42 (Perform Master Reset) succeeds."""
        resp = udp_client.send_command(HARTCommand.PERFORM_MASTER_RESET)
        assert resp.success

    def test_reset_config_flag(self, udp_client):
        """Cmd 38 (Reset Configuration Changed Flag) succeeds."""
        resp = udp_client.send_command(HARTCommand.RESET_CONFIG_FLAG)
        assert resp.success


# ---------------------------------------------------------------------------
# TCP Tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def tcp_client():
    """Per-test TCP client connected to mock server."""
    client = HARTIPClient(MOCK_HOST, port=MOCK_TCP_PORT, protocol="tcp", timeout=3.0)
    client.connect()
    yield client
    client.close()


@skip_no_mock_tcp
@pytest.mark.integration
class TestTCPReads:
    """Verify reads work correctly over TCP."""

    def test_read_unique_id(self, tcp_client):
        resp = tcp_client.read_unique_id()
        assert resp.success
        info = parse_cmd0(resp.payload)
        assert info.manufacturer_id > 0

    def test_read_primary_variable(self, tcp_client):
        resp = tcp_client.read_primary_variable()
        assert resp.success
        pv = parse_cmd1(resp.payload)
        assert isinstance(pv.value, float)

    def test_read_dynamic_variables(self, tcp_client):
        resp = tcp_client.read_dynamic_variables()
        assert resp.success
        vs = parse_cmd3(resp.payload)
        assert len(vs["variables"]) == 4


@skip_no_mock_tcp
@pytest.mark.integration
class TestTCPErrors:
    """Verify errors work correctly over TCP."""

    def test_unsupported_command(self, tcp_client):
        resp = tcp_client.send_command(200)
        assert not resp.success

    def test_raise_for_error(self, tcp_client):
        resp = tcp_client.send_command(200)
        with pytest.raises(HARTResponseError):
            resp.raise_for_error()


# ---------------------------------------------------------------------------
# Connection error tests (no mock needed)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestConnectionErrors:
    """Test connection failure behaviour."""

    def test_tcp_connection_refused(self):
        """TCP connect to a closed port raises HARTIPConnectionError."""
        client = HARTIPClient("127.0.0.1", port=19999, protocol="tcp", timeout=1)
        with pytest.raises(HARTIPConnectionError):
            client.connect()
        client.close()

    def test_udp_timeout(self):
        """UDP send to unreachable port times out with HARTIPTimeoutError."""
        client = HARTIPClient("127.0.0.1", port=19999, protocol="udp", timeout=1)
        # UDP connect() succeeds (no handshake), but session init times out
        with pytest.raises(HARTIPTimeoutError):
            client.connect()
        client.close()

    def test_not_connected_raises(self):
        """send_command before connect() raises HARTIPConnectionError."""
        client = HARTIPClient("127.0.0.1")
        with pytest.raises(HARTIPConnectionError, match="Not connected"):
            client.send_command(0)

    def test_context_manager_on_error(self):
        """Context manager exits cleanly even if connect() fails."""
        with pytest.raises(HARTIPTimeoutError):
            with HARTIPClient("127.0.0.1", port=19999, protocol="udp", timeout=1):
                pass  # connect will fail


# ---------------------------------------------------------------------------
# Long frame tests
# ---------------------------------------------------------------------------


@skip_no_mock_udp
@pytest.mark.integration
class TestLongFrame:
    """Verify long-frame (5-byte unique address) communication."""

    def test_unique_addr_auto_long_frame(self, udp_client):
        """Passing unique_addr should automatically use long frame."""
        resp0 = udp_client.read_unique_id()
        info = parse_cmd0(resp0.payload)
        unique = info.unique_address

        resp = udp_client.send_command(0, unique_addr=unique)
        assert resp.pdu is not None


# ---------------------------------------------------------------------------
# Sequencing and session lifecycle
# ---------------------------------------------------------------------------


@skip_no_mock_udp
@pytest.mark.integration
class TestSequencing:
    """Verify sequence numbers increment correctly."""

    def test_multiple_commands(self, udp_client):
        """Send 10 commands; all should succeed with valid headers."""
        for _ in range(10):
            resp = udp_client.read_unique_id()
            assert resp.success

    def test_reconnect(self):
        """Closing and reconnecting should work."""
        client = HARTIPClient(MOCK_HOST, port=MOCK_UDP_PORT, protocol="udp", timeout=3)
        client.connect()
        r1 = client.read_unique_id()
        assert r1.success
        client.close()

        client.connect()
        r2 = client.read_unique_id()
        assert r2.success
        client.close()


# ---------------------------------------------------------------------------
# Auto-parse API tests (resp.parsed / resp.command_name / resp.command_number)
# ---------------------------------------------------------------------------


@skip_no_mock_udp
@pytest.mark.integration
class TestAutoParse:
    """Verify the auto-parse API on HARTIPResponse."""

    def test_parsed_cmd0_returns_device_info(self, udp_client):
        """resp.parsed for Command 0 returns a DeviceInfo dataclass."""
        resp = udp_client.read_unique_id()
        assert resp.success
        parsed = resp.parsed
        assert isinstance(parsed, DeviceInfo)
        assert parsed.manufacturer_id > 0

    def test_parsed_cmd1_returns_variable(self, udp_client):
        """resp.parsed for Command 1 returns a Variable dataclass."""
        resp = udp_client.read_primary_variable()
        assert resp.success
        parsed = resp.parsed
        assert isinstance(parsed, Variable)
        assert parsed.label == "PV"

    def test_parsed_cmd3_returns_dict(self, udp_client):
        """resp.parsed for Command 3 returns a dict with loop_current and variables."""
        resp = udp_client.read_dynamic_variables()
        assert resp.success
        parsed = resp.parsed
        assert isinstance(parsed, dict)
        assert "loop_current" in parsed
        assert len(parsed["variables"]) == 4

    def test_command_name_returns_friendly(self, udp_client):
        """resp.command_name returns the human-readable registry name."""
        resp = udp_client.read_unique_id()
        assert resp.command_name == "read_unique_id"

    def test_command_number_returns_int(self, udp_client):
        """resp.command_number returns the HART command number."""
        resp = udp_client.read_unique_id()
        assert resp.command_number == 0

    def test_parsed_caching(self, udp_client):
        """Second access to resp.parsed returns the same cached object."""
        resp = udp_client.read_unique_id()
        first = resp.parsed
        second = resp.parsed
        assert first is second

    def test_friendly_name_matches_parsed(self, udp_client):
        """Friendly-name parser produces the same result as resp.parsed."""
        resp = udp_client.read_unique_id()
        from_parsed = resp.parsed
        from_manual = parse_cmd0(resp.payload)
        assert isinstance(from_parsed, DeviceInfo)
        assert isinstance(from_manual, DeviceInfo)
        assert from_parsed.manufacturer_id == from_manual.manufacturer_id
        assert from_parsed.device_id == from_manual.device_id

    def test_parsed_cmd48_returns_dict(self, udp_client):
        """resp.parsed for Command 48 returns a dict."""
        resp = udp_client.read_additional_status()
        assert resp.success
        parsed = resp.parsed
        assert isinstance(parsed, dict)
        assert "device_specific_status" in parsed


# ---------------------------------------------------------------------------
# Additional parser tests (commands 7, 8, 14, 16, 38)
# ---------------------------------------------------------------------------


@skip_no_mock_udp
@pytest.mark.integration
class TestAdditionalParsers:
    """Test parsers for commands the mock supports: 7, 8, 14, 16, 38."""

    def test_cmd7_loop_configuration(self, udp_client):
        """Command 7: Read Loop Configuration returns polling address and mode."""
        resp = udp_client.read_loop_config()
        assert resp.success
        parsed = resp.parsed
        assert isinstance(parsed, dict)
        assert "polling_address" in parsed
        assert "loop_current_mode" in parsed
        # Verify manual parser matches
        manual = parse_cmd7(resp.payload)
        assert manual == parsed

    def test_cmd8_dynamic_variable_classifications(self, udp_client):
        """Command 8: Read Dynamic Variable Classifications returns 4 codes."""
        resp = udp_client.read_dynamic_var_classifications()
        assert resp.success
        parsed = resp.parsed
        assert isinstance(parsed, dict)
        assert "pv_classification" in parsed
        assert "sv_classification" in parsed
        assert "tv_classification" in parsed
        assert "qv_classification" in parsed
        # Verify manual parser matches
        manual = parse_cmd8(resp.payload)
        assert manual == parsed

    def test_cmd14_pv_transducer_info(self, udp_client):
        """Command 14: Read PV Transducer Information returns limits and span."""
        resp = udp_client.read_pv_info()
        assert resp.success
        parsed = resp.parsed
        assert isinstance(parsed, dict)
        assert "transducer_serial_number" in parsed
        assert "unit_code" in parsed
        assert "upper_transducer_limit" in parsed
        assert "lower_transducer_limit" in parsed
        assert "minimum_span" in parsed
        # Verify manual parser matches
        manual = parse_cmd14(resp.payload)
        assert manual == parsed

    def test_cmd16_final_assembly_number(self, udp_client):
        """Command 16: Read Final Assembly Number returns an integer."""
        resp = udp_client.read_final_assembly()
        assert resp.success
        parsed = resp.parsed
        assert isinstance(parsed, dict)
        assert "final_assembly_number" in parsed
        assert isinstance(parsed["final_assembly_number"], int)
        assert parsed["final_assembly_number"] > 0
        # Verify manual parser matches
        manual = parse_cmd16(resp.payload)
        assert manual == parsed

    def test_cmd38_reset_config_flag(self, udp_client):
        """Command 38: Reset Configuration Changed Flag succeeds."""
        resp = udp_client.send_command(HARTCommand.RESET_CONFIG_FLAG)
        assert resp.success
        assert resp.command_name == "reset_configuration_changed_flag"
        assert resp.command_number == 38
