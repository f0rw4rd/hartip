"""Tests for HART device data models and response parsing."""

import struct

from hartip.ascii import pack_ascii
from hartip.constants import HARTCommErrorFlags
from hartip.device import (
    DeviceInfo,
    DeviceVariable,
    Variable,
    decode_comm_error_flags,
    is_comm_error,
    parse_cmd0,
    parse_cmd1,
    parse_cmd2,
    parse_cmd3,
    parse_cmd9,
    parse_cmd12,
    parse_cmd13,
    parse_cmd14,
    parse_cmd15,
    parse_cmd20,
    parse_cmd48,
)

# ---------------------------------------------------------------------------
# Variable / DeviceInfo dataclasses
# ---------------------------------------------------------------------------


class TestVariable:
    def test_auto_unit_name(self) -> None:
        v = Variable(value=1.0, unit_code=7)
        assert v.unit_name == "bar"

    def test_explicit_unit_name(self) -> None:
        v = Variable(value=1.0, unit_code=7, unit_name="custom")
        assert v.unit_name == "custom"

    def test_label(self) -> None:
        v = Variable(value=1.0, unit_code=7, label="PV")
        assert v.label == "PV"


class TestDeviceVariable:
    def test_fields(self) -> None:
        dv = DeviceVariable(
            slot=0,
            device_var_code=1,
            classification=64,
            unit_code=7,
            unit_name="bar",
            value=1.5,
            status=0,
        )
        assert dv.slot == 0
        assert dv.device_var_code == 1
        assert dv.classification == 64
        assert dv.unit_code == 7
        assert dv.unit_name == "bar"
        assert abs(dv.value - 1.5) < 0.001
        assert dv.status == 0


class TestDeviceInfo:
    def test_auto_vendor_name(self) -> None:
        info = DeviceInfo(manufacturer_id=0x26)
        assert "Rosemount" in info.manufacturer_name

    def test_explicit_vendor_name(self) -> None:
        info = DeviceInfo(manufacturer_id=0x26, manufacturer_name="Custom")
        assert info.manufacturer_name == "Custom"

    def test_defaults(self) -> None:
        info = DeviceInfo()
        assert info.manufacturer_id == 0
        assert info.device_type == 0
        assert info.expanded_device_type == 0
        assert info.hart_revision == 0
        assert info.unique_address == b""
        assert info.tag == ""
        assert info.long_tag == ""


# ---------------------------------------------------------------------------
# Communication error utilities
# ---------------------------------------------------------------------------


class TestCommError:
    def test_is_comm_error_msb_set(self) -> None:
        assert is_comm_error(0x80) is True
        assert is_comm_error(0xC0) is True
        assert is_comm_error(0xFF) is True

    def test_is_comm_error_msb_clear(self) -> None:
        assert is_comm_error(0x00) is False
        assert is_comm_error(0x01) is False
        assert is_comm_error(0x7F) is False

    def test_decode_vertical_parity(self) -> None:
        flags = decode_comm_error_flags(0xC0)  # bit 6
        assert HARTCommErrorFlags.VERTICAL_PARITY in flags

    def test_decode_overrun(self) -> None:
        flags = decode_comm_error_flags(0xA0)  # bit 5
        assert HARTCommErrorFlags.OVERRUN_ERROR in flags

    def test_decode_framing(self) -> None:
        flags = decode_comm_error_flags(0x90)  # bit 4
        assert HARTCommErrorFlags.FRAMING_ERROR in flags

    def test_decode_longitudinal_parity(self) -> None:
        flags = decode_comm_error_flags(0x88)  # bit 3
        assert HARTCommErrorFlags.LONGITUDINAL_PARITY in flags

    def test_decode_buffer_overflow(self) -> None:
        flags = decode_comm_error_flags(0x82)  # bit 1
        assert HARTCommErrorFlags.BUFFER_OVERFLOW in flags

    def test_decode_multiple_flags(self) -> None:
        flags = decode_comm_error_flags(0xDA)  # bits 6,4,3,1
        assert HARTCommErrorFlags.VERTICAL_PARITY in flags
        assert HARTCommErrorFlags.FRAMING_ERROR in flags
        assert HARTCommErrorFlags.LONGITUDINAL_PARITY in flags
        assert HARTCommErrorFlags.BUFFER_OVERFLOW in flags

    def test_decode_none(self) -> None:
        flags = decode_comm_error_flags(0x80)  # no error flags, just MSB
        assert flags == HARTCommErrorFlags.NONE


# ---------------------------------------------------------------------------
# Command 0 – Read Unique Identifier
# ---------------------------------------------------------------------------


class TestParseCmd0:
    def test_legacy_12_byte(self) -> None:
        payload = bytes(
            [
                0x00,  # expansion code
                0x26,  # manufacturer_id = Rosemount
                0x01,  # device_type
                0x05,  # num_preambles
                0x05,  # hart_revision
                0x03,  # device_revision
                0x02,  # software_revision
                0x10,  # hardware_revision(5b) | physical_signaling(3b)
                0x00,  # flags
                0x01,
                0x02,
                0x03,  # device_id (24-bit)
            ]
        )
        info = parse_cmd0(payload)
        assert info.manufacturer_id == 0x26
        assert "Rosemount" in info.manufacturer_name
        assert info.device_type == 0x01
        assert info.expanded_device_type == (0x26 << 8) | 0x01
        assert info.device_id == 0x010203
        assert info.hart_revision == 5
        assert info.software_revision == 2
        assert info.hardware_revision == 2  # (0x10 >> 3) & 0x1F
        assert info.physical_signaling == 0  # 0x10 & 0x07
        assert info.num_preambles == 5

    def test_unique_address(self) -> None:
        payload = bytes(
            [
                0x00,
                0x26,
                0x01,
                0x05,
                0x05,
                0x03,
                0x02,
                0x10,
                0x00,
                0x01,
                0x02,
                0x03,
            ]
        )
        info = parse_cmd0(payload)
        assert len(info.unique_address) == 5
        assert info.unique_address[0] == 0x80 | (0x26 & 0x3F)
        assert info.unique_address[1] == 0x01
        assert info.unique_address[2] == 0x01
        assert info.unique_address[3] == 0x02
        assert info.unique_address[4] == 0x03

    def test_extended_fields(self) -> None:
        payload = bytes(
            [
                0x00,
                0x03,
                0x02,
                0x05,
                0x07,
                0x10,
                0x05,
                0x28,
                0x00,
                0x00,
                0xAB,
                0xCD,
                0x05,  # num_response_preambles
                0x03,  # max_device_vars
                0x00,
                0x01,  # config_change_counter
                0x00,  # extended_field_device_status
            ]
        )
        info = parse_cmd0(payload)
        assert info.num_response_preambles == 5
        assert info.config_change_counter == 1
        assert info.extended_field_device_status == 0

    def test_hart7_extended(self) -> None:
        payload = bytes(
            [
                254,  # expansion code (HART 7)
                0x03,
                0x02,
                0x05,
                0x07,
                0x10,
                0x05,
                0x28,
                0x00,
                0x00,
                0xAB,
                0xCD,
                0x05,
                0x03,
                0x00,
                0x01,
                0x00,
                0x00,
                0x03,  # manufacturer_id_16bit
                0x00,
                0x10,  # private_label
                0x05,  # device_profile
            ]
        )
        info = parse_cmd0(payload)
        assert info.manufacturer_id == 3
        assert info.device_id == 0x00ABCD
        assert info.hart_revision == 7
        assert info.manufacturer_id_16bit == 3
        assert info.private_label == 0x10
        assert info.device_profile == 5

    def test_too_short(self) -> None:
        info = parse_cmd0(b"\x00\x01")
        assert info.manufacturer_id == 0

    def test_empty(self) -> None:
        info = parse_cmd0(b"")
        assert info.manufacturer_id == 0


# ---------------------------------------------------------------------------
# Command 1 – Read Primary Variable
# ---------------------------------------------------------------------------


class TestParseCmd1:
    def test_valid(self) -> None:
        payload = bytes([7]) + struct.pack(">f", 1.5)
        var = parse_cmd1(payload)
        assert var is not None
        assert var.unit_code == 7
        assert var.unit_name == "bar"
        assert abs(var.value - 1.5) < 0.001
        assert var.label == "PV"

    def test_too_short(self) -> None:
        assert parse_cmd1(b"\x07\x00") is None

    def test_empty(self) -> None:
        assert parse_cmd1(b"") is None


# ---------------------------------------------------------------------------
# Command 2 – Read Loop Current and Percent
# ---------------------------------------------------------------------------


class TestParseCmd2:
    def test_valid(self) -> None:
        payload = struct.pack(">f", 4.0) + struct.pack(">f", 50.0)
        result = parse_cmd2(payload)
        assert abs(result["current_mA"] - 4.0) < 0.001
        assert abs(result["percent_range"] - 50.0) < 0.001

    def test_too_short(self) -> None:
        assert parse_cmd2(b"\x00" * 7) == {}

    def test_empty(self) -> None:
        assert parse_cmd2(b"") == {}


# ---------------------------------------------------------------------------
# Command 3 – Read Dynamic Variables
# ---------------------------------------------------------------------------


class TestParseCmd3:
    def test_four_variables(self) -> None:
        payload = struct.pack(">f", 4.0)
        for unit, val in [(7, 1.0), (32, 25.0), (57, 50.0), (39, 4.0)]:
            payload += bytes([unit]) + struct.pack(">f", val)
        result = parse_cmd3(payload)
        assert abs(result["loop_current"] - 4.0) < 0.001
        variables = result["variables"]
        assert len(variables) == 4
        assert variables[0].label == "PV"
        assert variables[0].unit_name == "bar"
        assert variables[1].label == "SV"
        assert variables[2].label == "TV"
        assert variables[3].label == "QV"

    def test_one_variable(self) -> None:
        payload = struct.pack(">f", 12.0) + bytes([7]) + struct.pack(">f", 2.0)
        result = parse_cmd3(payload)
        assert abs(result["loop_current"] - 12.0) < 0.001
        assert len(result["variables"]) == 1
        assert result["variables"][0].label == "PV"

    def test_current_only(self) -> None:
        payload = struct.pack(">f", 4.0)
        result = parse_cmd3(payload)
        assert abs(result["loop_current"] - 4.0) < 0.001
        assert result["variables"] == []

    def test_too_short(self) -> None:
        assert parse_cmd3(b"\x00\x01\x02") == {}


# ---------------------------------------------------------------------------
# Command 9 – Read Device Variables with Status
# ---------------------------------------------------------------------------


class TestParseCmd9:
    def test_single_slot(self) -> None:
        payload = bytes([0x00])  # extended_device_status
        payload += bytes([0x00, 0x40, 0x07])  # var_code, classification, unit
        payload += struct.pack(">f", 1.5)
        payload += bytes([0x00])  # status
        result = parse_cmd9(payload)
        assert result["extended_device_status"] == 0
        assert len(result["variables"]) == 1
        dv = result["variables"][0]
        assert dv.slot == 0
        assert dv.device_var_code == 0
        assert dv.classification == 0x40
        assert dv.unit_code == 7
        assert dv.unit_name == "bar"
        assert abs(dv.value - 1.5) < 0.001
        assert dv.status == 0
        assert result["timestamp"] is None

    def test_two_slots_with_timestamp(self) -> None:
        payload = bytes([0x10])  # extended_device_status
        # Slot 0
        payload += bytes([0x00, 0x40, 0x07]) + struct.pack(">f", 1.0) + bytes([0x00])
        # Slot 1
        payload += bytes([0x01, 0x40, 0x20]) + struct.pack(">f", 25.0) + bytes([0x00])
        # Timestamp
        payload += bytes([0x00, 0x00, 0x01, 0x00])

        result = parse_cmd9(payload)
        assert result["extended_device_status"] == 0x10
        assert len(result["variables"]) == 2
        assert result["variables"][1].unit_code == 0x20
        assert result["timestamp"] == bytes([0x00, 0x00, 0x01, 0x00])

    def test_max_slots(self) -> None:
        payload = bytes([0x00])
        for i in range(8):
            payload += bytes([i, 0x40, 0x07]) + struct.pack(">f", float(i)) + bytes([0x00])
        result = parse_cmd9(payload)
        assert len(result["variables"]) == 8

    def test_too_short(self) -> None:
        assert parse_cmd9(b"\x00" * 8) == {}

    def test_empty(self) -> None:
        assert parse_cmd9(b"") == {}


# ---------------------------------------------------------------------------
# Command 12 – Read Message
# ---------------------------------------------------------------------------


class TestParseCmd12:
    def test_packed_ascii(self) -> None:
        packed = pack_ascii("HELLO WORLD TEST MSG")
        # Pad to 24 bytes
        packed = packed + bytes(24 - len(packed))
        result = parse_cmd12(packed[:24])
        assert len(result) > 0
        assert "HELLO" in result

    def test_too_short(self) -> None:
        assert parse_cmd12(b"\x00" * 23) == ""

    def test_empty(self) -> None:
        assert parse_cmd12(b"") == ""


# ---------------------------------------------------------------------------
# Command 13 – Read Tag, Descriptor, Date
# ---------------------------------------------------------------------------


class TestParseCmd13:
    def test_valid(self) -> None:
        # Tag is 6 packed bytes (8 chars), descriptor is 12 packed bytes (16 chars)
        tag = pack_ascii("TAG12345")[:6]  # 8 chars -> 6 packed bytes
        tag = tag.ljust(6, b"\x00")
        descriptor = pack_ascii("DESCRIPTION TEST")[:12]  # 16 chars -> 12 packed bytes
        descriptor = descriptor.ljust(12, b"\x00")
        day, month, year = 15, 6, 124  # 2024-06-15
        payload = tag + descriptor + bytes([day, month, year])
        assert len(payload) == 21
        result = parse_cmd13(payload)
        assert "tag" in result
        assert "descriptor" in result
        assert result["date"] == "2024-06-15"

    def test_too_short(self) -> None:
        assert parse_cmd13(b"\x00" * 20) == {}


# ---------------------------------------------------------------------------
# Command 14 – Read PV Transducer Information
# ---------------------------------------------------------------------------


class TestParseCmd14:
    def test_valid(self) -> None:
        payload = bytes([0x00, 0x01, 0x02])  # serial = 0x000102
        payload += bytes([0x07])  # unit_code = bar
        payload += struct.pack(">f", 100.0)
        payload += struct.pack(">f", 0.0)
        payload += struct.pack(">f", 1.0)
        result = parse_cmd14(payload)
        assert result["transducer_serial_number"] == 0x000102
        assert result["unit_code"] == 7
        assert result["unit_name"] == "bar"
        assert abs(result["upper_transducer_limit"] - 100.0) < 0.001
        assert abs(result["lower_transducer_limit"] - 0.0) < 0.001
        assert abs(result["minimum_span"] - 1.0) < 0.001

    def test_too_short(self) -> None:
        assert parse_cmd14(b"\x00" * 15) == {}


# ---------------------------------------------------------------------------
# Command 15 – Read Output Information
# ---------------------------------------------------------------------------


class TestParseCmd15:
    def test_valid(self) -> None:
        payload = bytes([0x00, 0x00, 0x07])  # alarm, transfer, range_units=bar
        payload += struct.pack(">f", 100.0)  # upper
        payload += struct.pack(">f", 0.0)  # lower
        payload += struct.pack(">f", 2.0)  # damping
        payload += bytes([0xFB, 0xFA, 0x00])  # write_protect, reserved, channel_flags
        result = parse_cmd15(payload)
        assert result["alarm_selection_code"] == 0
        assert result["transfer_function_code"] == 0
        assert result["range_units_code"] == 7
        assert result["range_unit_name"] == "bar"
        assert abs(result["upper_range_value"] - 100.0) < 0.001
        assert abs(result["lower_range_value"] - 0.0) < 0.001
        assert abs(result["damping_value"] - 2.0) < 0.001
        assert result["write_protect_code"] == 0xFB
        assert result["analog_channel_flags"] == 0x00

    def test_too_short(self) -> None:
        assert parse_cmd15(b"\x00" * 17) == {}


# ---------------------------------------------------------------------------
# Command 20 – Read Long Tag
# ---------------------------------------------------------------------------


class TestParseCmd20:
    def test_valid(self) -> None:
        tag = b"MY-LONG-TAG\x00" + b"\x00" * 20  # 32 bytes
        result = parse_cmd20(tag)
        assert result == "MY-LONG-TAG"

    def test_too_short(self) -> None:
        assert parse_cmd20(b"SHORT") == ""


# ---------------------------------------------------------------------------
# Command 48 – Read Additional Device Status
# ---------------------------------------------------------------------------


class TestParseCmd48:
    def test_minimal_6_bytes(self) -> None:
        payload = bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
        result = parse_cmd48(payload)
        assert result["device_specific_status"] == payload
        assert "extended_device_status" not in result

    def test_9_bytes(self) -> None:
        payload = bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
        payload += bytes([0x10, 0x00, 0x20])
        result = parse_cmd48(payload)
        assert result["extended_device_status"] == 0x10
        assert result["operating_mode"] == 0x00
        assert result["standardized_status_0"] == 0x20

    def test_13_bytes(self) -> None:
        payload = bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
        payload += bytes([0x10, 0x00, 0x20])
        payload += bytes([0x01, 0x02, 0x03, 0x04])
        result = parse_cmd48(payload)
        assert result["standardized_status_1"] == 0x01
        assert result["analog_channel_saturated"] == 0x02
        assert result["standardized_status_2"] == 0x03
        assert result["standardized_status_3"] == 0x04

    def test_14_bytes(self) -> None:
        payload = bytes(14)
        payload = bytes([0x00] * 6 + [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05])
        result = parse_cmd48(payload)
        assert result["analog_channel_fixed"] == 0x05

    def test_25_bytes(self) -> None:
        payload = bytes(25)
        result = parse_cmd48(payload)
        assert "additional_device_specific_status" in result
        assert len(result["additional_device_specific_status"]) == 11

    def test_too_short(self) -> None:
        assert parse_cmd48(b"\x00" * 5) == {}

    def test_empty(self) -> None:
        assert parse_cmd48(b"") == {}
