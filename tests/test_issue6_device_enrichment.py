"""Tests for issue #6: device enrichment features.

Covers:
1. DeviceInfo.write_protected / config_changed properties
2. Variable.value / unit_code (verified existing)
3. get_device_type_name() lookup
4. Physical signaling name lookup + DeviceInfo.physical_signaling_name
5. Lock/unlock: parse_cmd71, parse_cmd76, client convenience methods
"""

import struct
from unittest.mock import MagicMock, patch

from hartip.client import HARTIPClient
from hartip.constants import HARTIP_HEADER_SIZE, HARTFrameType, HARTIPMessageType
from hartip.device import (
    PHYSICAL_SIGNALING_CODES,
    DeviceInfo,
    Variable,
    get_device_type_name,
    get_physical_signaling_name,
    parse_cmd0,
    parse_cmd71,
    parse_cmd76,
)
from hartip.protocol import HARTIPHeader, build_pdu

# ---------------------------------------------------------------------------
# Helpers (same pattern as test_client.py)
# ---------------------------------------------------------------------------


def _build_session_init_response(status: int = 0) -> bytes:
    payload = struct.pack(">BI", 1, 30000)
    total = HARTIP_HEADER_SIZE + len(payload)
    hdr = HARTIPHeader.build(
        dict(
            version=1,
            msg_type=HARTIPMessageType.RESPONSE,
            msg_id=0,
            status=status,
            sequence=1,
            byte_count=total,
        )
    )
    return hdr + payload


def _build_mock_response(
    command: int = 0,
    response_code: int = 0,
    device_status: int = 0,
    payload: bytes = b"",
    status: int = 0,
) -> bytes:
    data = bytes([response_code, device_status]) + payload
    pdu = build_pdu(HARTFrameType.SHORT_FRAME, b"\x00", command, data)
    total = HARTIP_HEADER_SIZE + len(pdu)
    hdr = HARTIPHeader.build(
        dict(
            version=1,
            msg_type=HARTIPMessageType.RESPONSE,
            msg_id=3,
            status=status,
            sequence=1,
            byte_count=total,
        )
    )
    return hdr + pdu


_ADDR = ("127.0.0.1", 5094)


# ---------------------------------------------------------------------------
# Feature 1: DeviceInfo flag properties
# ---------------------------------------------------------------------------


class TestDeviceInfoFlagProperties:
    def test_write_protected_set(self) -> None:
        info = DeviceInfo(flags=0x80)
        assert info.write_protected is True

    def test_write_protected_clear(self) -> None:
        info = DeviceInfo(flags=0x00)
        assert info.write_protected is False

    def test_config_changed_set(self) -> None:
        info = DeviceInfo(flags=0x40)
        assert info.config_changed is True

    def test_config_changed_clear(self) -> None:
        info = DeviceInfo(flags=0x00)
        assert info.config_changed is False

    def test_both_flags_set(self) -> None:
        info = DeviceInfo(flags=0xC0)
        assert info.write_protected is True
        assert info.config_changed is True

    def test_neither_flag_set(self) -> None:
        info = DeviceInfo(flags=0x3F)
        assert info.write_protected is False
        assert info.config_changed is False

    def test_from_parse_cmd0(self) -> None:
        """Verify properties work on DeviceInfo parsed from Command 0."""
        payload = bytes(
            [
                0x00,  # expansion code
                0x26,  # manufacturer_id
                0x01,  # device_type
                0x05,  # num_preambles
                0x05,  # hart_revision
                0x03,  # device_revision
                0x02,  # software_revision
                0x10,  # hw_rev | phys_sig
                0xC0,  # flags: write_protected + config_changed
                0x01,
                0x02,
                0x03,  # device_id
            ]
        )
        info = parse_cmd0(payload)
        assert info.flags == 0xC0
        assert info.write_protected is True
        assert info.config_changed is True


# ---------------------------------------------------------------------------
# Feature 2: Variable already has value and unit_code
# ---------------------------------------------------------------------------


class TestVariableFieldsExist:
    def test_value_field(self) -> None:
        v = Variable(value=3.14, unit_code=7)
        assert abs(v.value - 3.14) < 0.001

    def test_unit_code_field(self) -> None:
        v = Variable(value=0.0, unit_code=32)
        assert v.unit_code == 32
        assert v.unit_name == "degC"


# ---------------------------------------------------------------------------
# Feature 3: get_device_type_name()
# ---------------------------------------------------------------------------


class TestGetDeviceTypeName:
    def test_pressure_transmitter(self) -> None:
        for code in (40, 45, 49):
            assert get_device_type_name(code) == "Pressure Transmitter"

    def test_temperature_transmitter(self) -> None:
        for code in (50, 55, 59):
            assert get_device_type_name(code) == "Temperature Transmitter"

    def test_flow_meter(self) -> None:
        for code in (60, 65, 69):
            assert get_device_type_name(code) == "Flow Meter"

    def test_level_transmitter(self) -> None:
        for code in (70, 75, 79):
            assert get_device_type_name(code) == "Level Transmitter"

    def test_gateway_interface(self) -> None:
        for code in (80, 87, 94):
            assert get_device_type_name(code) == "Gateway / Interface"

    def test_unknown_below_range(self) -> None:
        assert get_device_type_name(0) == "Unknown"
        assert get_device_type_name(39) == "Unknown"

    def test_unknown_above_range(self) -> None:
        assert get_device_type_name(95) == "Unknown"
        assert get_device_type_name(255) == "Unknown"

    def test_unknown_gap(self) -> None:
        """Codes between ranges are unknown (there are no gaps in the spec ranges)."""
        # No gaps in the defined ranges: 40-49, 50-59, 60-69, 70-79, 80-94
        # But 95 should be unknown
        assert get_device_type_name(95) == "Unknown"


# ---------------------------------------------------------------------------
# Feature 4: Physical signaling name
# ---------------------------------------------------------------------------


class TestPhysicalSignaling:
    def test_bell_202_fsk(self) -> None:
        assert get_physical_signaling_name(0) == "Bell 202 FSK"

    def test_fsk(self) -> None:
        assert get_physical_signaling_name(2) == "FSK"

    def test_wirelesshart(self) -> None:
        assert get_physical_signaling_name(4) == "WirelessHART"

    def test_unknown(self) -> None:
        assert get_physical_signaling_name(1) == "Unknown"
        assert get_physical_signaling_name(3) == "Unknown"
        assert get_physical_signaling_name(5) == "Unknown"
        assert get_physical_signaling_name(7) == "Unknown"

    def test_physical_signaling_codes_dict(self) -> None:
        assert PHYSICAL_SIGNALING_CODES[0] == "Bell 202 FSK"
        assert PHYSICAL_SIGNALING_CODES[2] == "FSK"
        assert PHYSICAL_SIGNALING_CODES[4] == "WirelessHART"

    def test_device_info_property(self) -> None:
        info = DeviceInfo(physical_signaling=0)
        assert info.physical_signaling_name == "Bell 202 FSK"

    def test_device_info_property_wirelesshart(self) -> None:
        info = DeviceInfo(physical_signaling=4)
        assert info.physical_signaling_name == "WirelessHART"

    def test_device_info_property_unknown(self) -> None:
        info = DeviceInfo(physical_signaling=6)
        assert info.physical_signaling_name == "Unknown"

    def test_from_parse_cmd0(self) -> None:
        """Verify physical_signaling_name works on parsed DeviceInfo."""
        payload = bytes(
            [
                0x00,  # expansion code
                0x26,  # manufacturer_id
                0x01,  # device_type
                0x05,  # num_preambles
                0x05,  # hart_revision
                0x03,  # device_revision
                0x02,  # software_revision
                0x04,  # hw_rev=0 | phys_sig=4 (WirelessHART)
                0x00,  # flags
                0x01,
                0x02,
                0x03,  # device_id
            ]
        )
        info = parse_cmd0(payload)
        assert info.physical_signaling == 4
        assert info.physical_signaling_name == "WirelessHART"


# ---------------------------------------------------------------------------
# Feature 5a: parse_cmd71 / parse_cmd76
# ---------------------------------------------------------------------------


class TestParseCmd71:
    def test_unlock(self) -> None:
        result = parse_cmd71(bytes([0]))
        assert result["lock_code"] == 0

    def test_lock_temporary(self) -> None:
        result = parse_cmd71(bytes([1]))
        assert result["lock_code"] == 1

    def test_lock_permanent(self) -> None:
        result = parse_cmd71(bytes([2]))
        assert result["lock_code"] == 2

    def test_lock_all(self) -> None:
        result = parse_cmd71(bytes([3]))
        assert result["lock_code"] == 3

    def test_empty(self) -> None:
        assert parse_cmd71(b"") == {}


class TestParseCmd76:
    def test_unlocked(self) -> None:
        result = parse_cmd76(bytes([0x00]))
        assert result["lock_status"] == 0
        assert result["device_locked"] is False
        assert result["lock_permanent"] is False
        assert result["lock_primary"] is False
        assert result["configuration_locked"] is False
        assert result["lock_gateway"] is False

    def test_device_locked(self) -> None:
        result = parse_cmd76(bytes([0x01]))
        assert result["device_locked"] is True
        assert result["lock_permanent"] is False

    def test_permanent_lock(self) -> None:
        result = parse_cmd76(bytes([0x03]))
        assert result["device_locked"] is True
        assert result["lock_permanent"] is True

    def test_all_flags(self) -> None:
        result = parse_cmd76(bytes([0x1F]))
        assert result["device_locked"] is True
        assert result["lock_permanent"] is True
        assert result["lock_primary"] is True
        assert result["configuration_locked"] is True
        assert result["lock_gateway"] is True

    def test_lock_gateway_only(self) -> None:
        result = parse_cmd76(bytes([0x10]))
        assert result["lock_gateway"] is True
        assert result["device_locked"] is False

    def test_empty(self) -> None:
        assert parse_cmd76(b"") == {}


# ---------------------------------------------------------------------------
# Feature 5b: Client lock/unlock/read_lock_state convenience methods
# ---------------------------------------------------------------------------


class TestLockDeviceClient:
    def _make_connected_client(self, mock_sock):
        session_resp = _build_session_init_response()
        mock_sock.recvfrom.side_effect = [
            (session_resp, _ADDR),
        ]
        client = HARTIPClient("127.0.0.1", protocol="udp")
        client.connect()
        return client

    def test_lock_device(self) -> None:
        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            client = self._make_connected_client(mock_sock)
            cmd_resp = _build_mock_response(command=71, payload=bytes([1]))
            mock_sock.recvfrom.side_effect = [(cmd_resp, _ADDR)]
            resp = client.lock_device(lock_code=1)
            assert resp.response_code == 0
            # Verify command 71 was sent with data byte 1
            sent_frame = mock_sock.sendto.call_args_list[-1][0][0]
            pdu_bytes = sent_frame[HARTIP_HEADER_SIZE:]
            assert pdu_bytes[2] == 71  # command
            assert pdu_bytes[3] == 1  # byte_count
            assert pdu_bytes[4] == 1  # lock_code

    def test_unlock_device(self) -> None:
        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            client = self._make_connected_client(mock_sock)
            cmd_resp = _build_mock_response(command=71, payload=bytes([0]))
            mock_sock.recvfrom.side_effect = [(cmd_resp, _ADDR)]
            resp = client.unlock_device()
            assert resp.response_code == 0
            # Verify command 71 with data byte 0 (unlock)
            sent_frame = mock_sock.sendto.call_args_list[-1][0][0]
            pdu_bytes = sent_frame[HARTIP_HEADER_SIZE:]
            assert pdu_bytes[2] == 71  # command
            assert pdu_bytes[4] == 0  # lock_code = unlock

    def test_read_lock_state(self) -> None:
        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            client = self._make_connected_client(mock_sock)
            cmd_resp = _build_mock_response(command=76, payload=bytes([0x01]))
            mock_sock.recvfrom.side_effect = [(cmd_resp, _ADDR)]
            resp = client.read_lock_state()
            assert resp.response_code == 0
            # Verify command 76 was sent
            sent_frame = mock_sock.sendto.call_args_list[-1][0][0]
            pdu_bytes = sent_frame[HARTIP_HEADER_SIZE:]
            assert pdu_bytes[2] == 76  # command

    def test_lock_device_permanent(self) -> None:
        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            client = self._make_connected_client(mock_sock)
            cmd_resp = _build_mock_response(command=71, payload=bytes([2]))
            mock_sock.recvfrom.side_effect = [(cmd_resp, _ADDR)]
            resp = client.lock_device(lock_code=2)
            assert resp.response_code == 0
            sent_frame = mock_sock.sendto.call_args_list[-1][0][0]
            pdu_bytes = sent_frame[HARTIP_HEADER_SIZE:]
            assert pdu_bytes[4] == 2  # lock_code = permanent


# ---------------------------------------------------------------------------
# Feature 5c: Command registry integration
# ---------------------------------------------------------------------------


class TestCommandRegistry:
    def test_cmd71_registered(self) -> None:
        from hartip.device import COMMAND_REGISTRY

        assert 71 in COMMAND_REGISTRY
        parser, name = COMMAND_REGISTRY[71]
        assert parser is parse_cmd71
        assert name == "lock_device"

    def test_cmd76_registered(self) -> None:
        from hartip.device import COMMAND_REGISTRY

        assert 76 in COMMAND_REGISTRY
        parser, name = COMMAND_REGISTRY[76]
        assert parser is parse_cmd76
        assert name == "read_lock_device_state"

    def test_parse_command_cmd71(self) -> None:
        from hartip.device import parse_command

        result = parse_command(71, bytes([1]))
        assert result["lock_code"] == 1

    def test_parse_command_cmd76(self) -> None:
        from hartip.device import parse_command

        result = parse_command(76, bytes([0x01]))
        assert result["device_locked"] is True


# ---------------------------------------------------------------------------
# Imports from __init__.py
# ---------------------------------------------------------------------------


class TestPublicImports:
    def test_get_device_type_name_importable(self) -> None:
        from hartip import get_device_type_name as fn

        assert fn(40) == "Pressure Transmitter"

    def test_get_physical_signaling_name_importable(self) -> None:
        from hartip import get_physical_signaling_name as fn

        assert fn(0) == "Bell 202 FSK"

    def test_physical_signaling_codes_importable(self) -> None:
        from hartip import PHYSICAL_SIGNALING_CODES as codes

        assert 0 in codes

    def test_parse_cmd71_importable(self) -> None:
        from hartip import parse_cmd71 as fn

        assert fn(bytes([1]))["lock_code"] == 1

    def test_parse_cmd76_importable(self) -> None:
        from hartip import parse_cmd76 as fn

        assert fn(bytes([0x01]))["device_locked"] is True

    def test_parse_lock_device_importable(self) -> None:
        from hartip import parse_lock_device as fn

        assert fn(bytes([2]))["lock_code"] == 2

    def test_parse_lock_device_state_importable(self) -> None:
        from hartip import parse_lock_device_state as fn

        assert fn(bytes([0x03]))["lock_permanent"] is True
