"""Tests for HART protocol lookup tables and bitfield decoders.

Covers all functionality in hartip/lookups.py:
1. decode_device_status() - device status byte
2. decode_cmd0_flags() - Command 0 flags byte
3. decode_extended_device_status() - extended field device status
4. decode_device_variable_status() - Command 9 DV status
5. decode_standardized_status_0/1/2/3() - Command 48 status bytes
6. Classification code lookup
7. Transfer function code lookup
8. Operating mode code lookup
9. Alarm selection code lookup
10. Write protect code lookup
11. Device family code lookup
12. Timestamp conversion helpers
13. Integration with DeviceInfo and DeviceVariable dataclasses
14. Integration with command parsers (cmd8, cmd9, cmd15, cmd48, cmd54, etc.)
"""

import struct
from datetime import timedelta

from hartip.device import (
    DeviceInfo,
    DeviceVariable,
    parse_cmd8,
    parse_cmd9,
    parse_cmd15,
    parse_cmd48,
    parse_cmd54,
    parse_cmd79,
    parse_cmd90,
    parse_cmd103,
    parse_cmd104,
    parse_cmd105,
    parse_cmd534,
)
from hartip.lookups import (
    ALARM_SELECTION_CODES,
    CLASSIFICATION_CODES,
    DEVICE_FAMILY_CODES,
    HART_TICKS_PER_SECOND,
    OPERATING_MODE_CODES,
    TRANSFER_FUNCTION_CODES,
    WRITE_PROTECT_CODES,
    decode_cmd0_flags,
    decode_device_status,
    decode_device_variable_status,
    decode_extended_device_status,
    decode_standardized_status_0,
    decode_standardized_status_1,
    decode_standardized_status_2,
    decode_standardized_status_3,
    get_alarm_selection_name,
    get_classification_name,
    get_device_family_name,
    get_operating_mode_name,
    get_transfer_function_name,
    get_write_protect_name,
    hart_ticks_to_seconds,
    hart_ticks_to_timedelta,
)

# ---------------------------------------------------------------------------
# 1. decode_device_status
# ---------------------------------------------------------------------------


class TestDecodeDeviceStatus:
    def test_all_clear(self) -> None:
        result = decode_device_status(0x00)
        assert all(v is False for v in result.values())

    def test_all_set(self) -> None:
        result = decode_device_status(0xFF)
        assert all(v is True for v in result.values())

    def test_device_malfunction_bit7(self) -> None:
        result = decode_device_status(0x80)
        assert result["device_malfunction"] is True
        assert result["config_changed"] is False

    def test_config_changed_bit6(self) -> None:
        result = decode_device_status(0x40)
        assert result["config_changed"] is True
        assert result["device_malfunction"] is False

    def test_cold_start_bit5(self) -> None:
        result = decode_device_status(0x20)
        assert result["cold_start"] is True

    def test_more_status_available_bit4(self) -> None:
        result = decode_device_status(0x10)
        assert result["more_status_available"] is True

    def test_loop_current_fixed_bit3(self) -> None:
        result = decode_device_status(0x08)
        assert result["loop_current_fixed"] is True

    def test_loop_current_saturated_bit2(self) -> None:
        result = decode_device_status(0x04)
        assert result["loop_current_saturated"] is True

    def test_non_primary_var_out_of_limits_bit1(self) -> None:
        result = decode_device_status(0x02)
        assert result["non_primary_var_out_of_limits"] is True

    def test_primary_var_out_of_limits_bit0(self) -> None:
        result = decode_device_status(0x01)
        assert result["primary_var_out_of_limits"] is True

    def test_multiple_bits(self) -> None:
        # cold_start(0x20) + loop_current_fixed(0x08) + primary_var_out(0x01)
        result = decode_device_status(0x29)
        assert result["cold_start"] is True
        assert result["loop_current_fixed"] is True
        assert result["primary_var_out_of_limits"] is True
        assert result["device_malfunction"] is False
        assert result["config_changed"] is False

    def test_returns_eight_keys(self) -> None:
        result = decode_device_status(0x00)
        assert len(result) == 8


# ---------------------------------------------------------------------------
# 2. decode_cmd0_flags
# ---------------------------------------------------------------------------


class TestDecodeCmdZeroFlags:
    def test_all_clear(self) -> None:
        result = decode_cmd0_flags(0x00)
        assert all(v is False for v in result.values())

    def test_all_set(self) -> None:
        result = decode_cmd0_flags(0xFF)
        assert all(v is True for v in result.values())

    def test_c8psk_in_multi_drop_only_bit7(self) -> None:
        result = decode_cmd0_flags(0x80)
        assert result["c8psk_in_multi_drop_only"] is True

    def test_c8psk_capable_bit6(self) -> None:
        result = decode_cmd0_flags(0x40)
        assert result["c8psk_capable"] is True

    def test_safehart_capable_bit4(self) -> None:
        result = decode_cmd0_flags(0x10)
        assert result["safehart_capable"] is True

    def test_ieee802_15_4_capable_bit3(self) -> None:
        result = decode_cmd0_flags(0x08)
        assert result["ieee802_15_4_capable"] is True

    def test_protocol_bridge_bit2(self) -> None:
        result = decode_cmd0_flags(0x04)
        assert result["protocol_bridge"] is True

    def test_eeprom_control_bit1(self) -> None:
        result = decode_cmd0_flags(0x02)
        assert result["eeprom_control"] is True

    def test_multi_sensor_field_device_bit0(self) -> None:
        result = decode_cmd0_flags(0x01)
        assert result["multi_sensor_field_device"] is True

    def test_returns_eight_keys(self) -> None:
        result = decode_cmd0_flags(0x00)
        assert len(result) == 8


# ---------------------------------------------------------------------------
# 3. decode_extended_device_status
# ---------------------------------------------------------------------------


class TestDecodeExtendedDeviceStatus:
    def test_all_clear(self) -> None:
        result = decode_extended_device_status(0x00)
        assert all(v is False for v in result.values())

    def test_maintenance_required_bit0(self) -> None:
        result = decode_extended_device_status(0x01)
        assert result["maintenance_required"] is True

    def test_device_variable_alert_bit1(self) -> None:
        result = decode_extended_device_status(0x02)
        assert result["device_variable_alert"] is True

    def test_critical_power_failure_bit2(self) -> None:
        result = decode_extended_device_status(0x04)
        assert result["critical_power_failure"] is True

    def test_failure_bit3(self) -> None:
        result = decode_extended_device_status(0x08)
        assert result["failure"] is True

    def test_out_of_specification_bit4(self) -> None:
        result = decode_extended_device_status(0x10)
        assert result["out_of_specification"] is True

    def test_function_check_bit5(self) -> None:
        result = decode_extended_device_status(0x20)
        assert result["function_check"] is True

    def test_multiple_bits(self) -> None:
        # maintenance_required(0x01) + failure(0x08) + function_check(0x20)
        result = decode_extended_device_status(0x29)
        assert result["maintenance_required"] is True
        assert result["failure"] is True
        assert result["function_check"] is True
        assert result["critical_power_failure"] is False

    def test_returns_six_keys(self) -> None:
        result = decode_extended_device_status(0x00)
        assert len(result) == 6


# ---------------------------------------------------------------------------
# 4. decode_device_variable_status
# ---------------------------------------------------------------------------


class TestDecodeDeviceVariableStatus:
    def test_all_zero(self) -> None:
        result = decode_device_variable_status(0x00)
        assert result["process_data_status"] == 0
        assert result["process_data_status_name"] == "Bad"
        assert result["limit_status"] == 0
        assert result["limit_status_name"] == "Not Limited"
        assert result["more_device_variable_status_available"] is False
        assert result["device_family_specific_status"] == 0

    def test_good_status(self) -> None:
        # Bits 7-6 = 0b11 = 3 (Good)
        result = decode_device_variable_status(0xC0)
        assert result["process_data_status"] == 3
        assert result["process_data_status_name"] == "Good"

    def test_poor_accuracy(self) -> None:
        # Bits 7-6 = 0b01 = 1 (Poor Accuracy)
        result = decode_device_variable_status(0x40)
        assert result["process_data_status"] == 1
        assert result["process_data_status_name"] == "Poor Accuracy"

    def test_manual_fixed(self) -> None:
        # Bits 7-6 = 0b10 = 2 (Manual/Fixed)
        result = decode_device_variable_status(0x80)
        assert result["process_data_status"] == 2
        assert result["process_data_status_name"] == "Manual/Fixed"

    def test_low_limited(self) -> None:
        # Bits 5-4 = 0b01 = 1 (Low Limited)
        result = decode_device_variable_status(0x10)
        assert result["limit_status"] == 1
        assert result["limit_status_name"] == "Low Limited"

    def test_high_limited(self) -> None:
        # Bits 5-4 = 0b10 = 2 (High Limited)
        result = decode_device_variable_status(0x20)
        assert result["limit_status"] == 2
        assert result["limit_status_name"] == "High Limited"

    def test_constant(self) -> None:
        # Bits 5-4 = 0b11 = 3 (Constant)
        result = decode_device_variable_status(0x30)
        assert result["limit_status"] == 3
        assert result["limit_status_name"] == "Constant"

    def test_more_status_available(self) -> None:
        result = decode_device_variable_status(0x08)
        assert result["more_device_variable_status_available"] is True

    def test_family_specific_bits(self) -> None:
        result = decode_device_variable_status(0x05)
        assert result["device_family_specific_status"] == 5

    def test_combined(self) -> None:
        # Good(0xC0) + HighLimited(0x20) + MoreStatus(0x08) + FamilySpecific=3
        result = decode_device_variable_status(0xEB)
        assert result["process_data_status_name"] == "Good"
        assert result["limit_status_name"] == "High Limited"
        assert result["more_device_variable_status_available"] is True
        assert result["device_family_specific_status"] == 3


# ---------------------------------------------------------------------------
# 5. Standardized Status Bytes (Command 48)
# ---------------------------------------------------------------------------


class TestDecodeStandardizedStatus0:
    def test_all_clear(self) -> None:
        result = decode_standardized_status_0(0x00)
        assert all(v is False for v in result.values())

    def test_device_configuration_lock_bit7(self) -> None:
        result = decode_standardized_status_0(0x80)
        assert result["device_configuration_lock"] is True

    def test_electronic_defect_bit6(self) -> None:
        result = decode_standardized_status_0(0x40)
        assert result["electronic_defect"] is True

    def test_environmental_conditions_bit5(self) -> None:
        result = decode_standardized_status_0(0x20)
        assert result["environmental_conditions_out_of_range"] is True

    def test_power_supply_conditions_bit4(self) -> None:
        result = decode_standardized_status_0(0x10)
        assert result["power_supply_conditions_out_of_range"] is True

    def test_watchdog_reset_bit3(self) -> None:
        result = decode_standardized_status_0(0x08)
        assert result["watchdog_reset_executed"] is True

    def test_volatile_memory_defect_bit2(self) -> None:
        result = decode_standardized_status_0(0x04)
        assert result["volatile_memory_defect"] is True

    def test_non_volatile_memory_defect_bit1(self) -> None:
        result = decode_standardized_status_0(0x02)
        assert result["non_volatile_memory_defect"] is True

    def test_dv_simulation_active_bit0(self) -> None:
        result = decode_standardized_status_0(0x01)
        assert result["device_variable_simulation_active"] is True

    def test_all_set(self) -> None:
        result = decode_standardized_status_0(0xFF)
        assert all(v is True for v in result.values())


class TestDecodeStandardizedStatus1:
    def test_all_clear(self) -> None:
        result = decode_standardized_status_1(0x00)
        assert result["undefined_bits"] == 0
        assert result["reserved"] is False
        assert result["battery_or_power_supply_needs_maintenance"] is False
        assert result["event_notification_overflow"] is False
        assert result["discrete_variable_simulation_active"] is False
        assert result["status_simulation_active"] is False

    def test_battery_needs_maintenance_bit3(self) -> None:
        result = decode_standardized_status_1(0x08)
        assert result["battery_or_power_supply_needs_maintenance"] is True

    def test_event_notification_overflow_bit2(self) -> None:
        result = decode_standardized_status_1(0x04)
        assert result["event_notification_overflow"] is True

    def test_discrete_variable_simulation_bit1(self) -> None:
        result = decode_standardized_status_1(0x02)
        assert result["discrete_variable_simulation_active"] is True

    def test_status_simulation_active_bit0(self) -> None:
        result = decode_standardized_status_1(0x01)
        assert result["status_simulation_active"] is True

    def test_undefined_bits(self) -> None:
        result = decode_standardized_status_1(0xE0)
        assert result["undefined_bits"] == 7


class TestDecodeStandardizedStatus2:
    def test_all_clear(self) -> None:
        result = decode_standardized_status_2(0x00)
        assert result["stale_data_notice"] is False
        assert result["sub_device_with_duplicate_id"] is False
        assert result["sub_device_mismatch"] is False
        assert result["duplicate_master_detected"] is False
        assert result["sub_device_list_changed"] is False

    def test_stale_data_notice_bit4(self) -> None:
        result = decode_standardized_status_2(0x10)
        assert result["stale_data_notice"] is True

    def test_sub_device_duplicate_id_bit3(self) -> None:
        result = decode_standardized_status_2(0x08)
        assert result["sub_device_with_duplicate_id"] is True

    def test_sub_device_mismatch_bit2(self) -> None:
        result = decode_standardized_status_2(0x04)
        assert result["sub_device_mismatch"] is True

    def test_duplicate_master_bit1(self) -> None:
        result = decode_standardized_status_2(0x02)
        assert result["duplicate_master_detected"] is True

    def test_sub_device_list_changed_bit0(self) -> None:
        result = decode_standardized_status_2(0x01)
        assert result["sub_device_list_changed"] is True


class TestDecodeStandardizedStatus3:
    def test_all_clear(self) -> None:
        result = decode_standardized_status_3(0x00)
        assert result["radio_failure"] is False
        assert result["block_transfer_pending"] is False
        assert result["bandwidth_allocation_pending"] is False
        assert result["reserved"] is False
        assert result["capacity_denied"] is False

    def test_radio_failure_bit4(self) -> None:
        result = decode_standardized_status_3(0x10)
        assert result["radio_failure"] is True

    def test_block_transfer_pending_bit3(self) -> None:
        result = decode_standardized_status_3(0x08)
        assert result["block_transfer_pending"] is True

    def test_bandwidth_allocation_pending_bit2(self) -> None:
        result = decode_standardized_status_3(0x04)
        assert result["bandwidth_allocation_pending"] is True

    def test_capacity_denied_bit0(self) -> None:
        result = decode_standardized_status_3(0x01)
        assert result["capacity_denied"] is True


# ---------------------------------------------------------------------------
# 6. Classification Code Lookup
# ---------------------------------------------------------------------------


class TestClassificationCodes:
    def test_not_classified(self) -> None:
        assert get_classification_name(0) == "Not Classified"

    def test_temperature(self) -> None:
        assert get_classification_name(64) == "Temperature"

    def test_pressure(self) -> None:
        assert get_classification_name(65) == "Pressure"

    def test_volumetric_flow(self) -> None:
        assert get_classification_name(66) == "Volumetric Flow"

    def test_mass_flow(self) -> None:
        assert get_classification_name(72) == "Mass Flow"

    def test_analytical(self) -> None:
        assert get_classification_name(81) == "Analytical"

    def test_concentration(self) -> None:
        assert get_classification_name(90) == "Concentration"

    def test_acceleration(self) -> None:
        assert get_classification_name(96) == "Acceleration"

    def test_linear_stiffness(self) -> None:
        assert get_classification_name(113) == "Linear Stiffness"

    def test_reserved_range_1_63(self) -> None:
        assert get_classification_name(1) == "Reserved (1)"
        assert get_classification_name(63) == "Reserved (63)"

    def test_reserved_range_91_95(self) -> None:
        assert get_classification_name(91) == "Reserved (91)"
        assert get_classification_name(95) == "Reserved (95)"

    def test_unknown(self) -> None:
        assert get_classification_name(200) == "Unknown (200)"

    def test_dict_has_expected_entries(self) -> None:
        assert len(CLASSIFICATION_CODES) > 30


# ---------------------------------------------------------------------------
# 7. Transfer Function Code Lookup
# ---------------------------------------------------------------------------


class TestTransferFunctionCodes:
    def test_linear(self) -> None:
        assert get_transfer_function_name(0) == "Linear"

    def test_square_root(self) -> None:
        assert get_transfer_function_name(1) == "Square Root"

    def test_special_curve(self) -> None:
        assert get_transfer_function_name(4) == "Special Curve"

    def test_square(self) -> None:
        assert get_transfer_function_name(5) == "Square"

    def test_equal_percentage(self) -> None:
        assert "Equal Percentage" in get_transfer_function_name(10)

    def test_flat_bottom_tank(self) -> None:
        assert get_transfer_function_name(100) == "Flat Bottom Tank"

    def test_discrete_switch(self) -> None:
        assert get_transfer_function_name(230) == "Discrete Switch"

    def test_not_used(self) -> None:
        assert get_transfer_function_name(250) == "Not Used"

    def test_none(self) -> None:
        assert get_transfer_function_name(251) == "None"

    def test_unknown(self) -> None:
        assert get_transfer_function_name(99) == "Unknown (99)"

    def test_dict_has_expected_entries(self) -> None:
        assert len(TRANSFER_FUNCTION_CODES) > 20


# ---------------------------------------------------------------------------
# 8. Operating Mode Code Lookup
# ---------------------------------------------------------------------------


class TestOperatingModeCodes:
    def test_reserved(self) -> None:
        assert get_operating_mode_name(0) == "Reserved"

    def test_device_specific(self) -> None:
        assert get_operating_mode_name(1) == "Device Specific (1)"
        assert get_operating_mode_name(255) == "Device Specific (255)"

    def test_dict_contents(self) -> None:
        assert 0 in OPERATING_MODE_CODES


# ---------------------------------------------------------------------------
# 9. Alarm Selection Code Lookup
# ---------------------------------------------------------------------------


class TestAlarmSelectionCodes:
    def test_high(self) -> None:
        assert get_alarm_selection_name(0) == "High"

    def test_low(self) -> None:
        assert get_alarm_selection_name(1) == "Low"

    def test_hold_last_output(self) -> None:
        assert get_alarm_selection_name(239) == "Hold Last Output Value"

    def test_manufacturer_specific(self) -> None:
        assert "Manufacturer Specific" in get_alarm_selection_name(240)
        assert "Manufacturer Specific" in get_alarm_selection_name(249)

    def test_not_used(self) -> None:
        assert get_alarm_selection_name(250) == "Not Used"

    def test_none(self) -> None:
        assert get_alarm_selection_name(251) == "None"

    def test_unknown_code(self) -> None:
        assert get_alarm_selection_name(100) == "Unknown (100)"

    def test_dict_has_expected_entries(self) -> None:
        assert len(ALARM_SELECTION_CODES) >= 7


# ---------------------------------------------------------------------------
# 10. Write Protect Code Lookup
# ---------------------------------------------------------------------------


class TestWriteProtectCodes:
    def test_no(self) -> None:
        assert get_write_protect_name(0) == "No"

    def test_yes(self) -> None:
        assert get_write_protect_name(1) == "Yes"

    def test_not_used(self) -> None:
        assert get_write_protect_name(250) == "Not Used"

    def test_none(self) -> None:
        assert get_write_protect_name(251) == "None"

    def test_unknown(self) -> None:
        assert get_write_protect_name(252) == "Unknown"

    def test_special(self) -> None:
        assert get_write_protect_name(253) == "Special"

    def test_unknown_code(self) -> None:
        assert get_write_protect_name(100) == "Unknown (100)"

    def test_dict_contents(self) -> None:
        assert len(WRITE_PROTECT_CODES) == 6


# ---------------------------------------------------------------------------
# 11. Device Family Code Lookup
# ---------------------------------------------------------------------------


class TestDeviceFamilyCodes:
    def test_temperature(self) -> None:
        assert get_device_family_name(4) == "Temperature"

    def test_pressure(self) -> None:
        assert get_device_family_name(5) == "Pressure"

    def test_not_used(self) -> None:
        assert get_device_family_name(250) == "Not Used"

    def test_unknown(self) -> None:
        assert get_device_family_name(200) == "Unknown (200)"

    def test_dict_has_expected_entries(self) -> None:
        assert len(DEVICE_FAMILY_CODES) >= 15


# ---------------------------------------------------------------------------
# 12. Timestamp Conversion Helpers
# ---------------------------------------------------------------------------


class TestTimestampConversion:
    def test_zero_ticks(self) -> None:
        assert hart_ticks_to_seconds(0) == 0.0

    def test_one_second(self) -> None:
        # 1 second = 32000 ticks
        assert abs(hart_ticks_to_seconds(32000) - 1.0) < 1e-10

    def test_one_millisecond(self) -> None:
        # 1 ms = 32 ticks
        assert abs(hart_ticks_to_seconds(32) - 0.001) < 1e-10

    def test_one_minute(self) -> None:
        # 1 minute = 60 * 32000 = 1920000 ticks
        assert abs(hart_ticks_to_seconds(1920000) - 60.0) < 1e-10

    def test_timedelta_zero(self) -> None:
        td = hart_ticks_to_timedelta(0)
        assert td == timedelta(0)

    def test_timedelta_one_second(self) -> None:
        td = hart_ticks_to_timedelta(32000)
        assert td == timedelta(seconds=1)

    def test_timedelta_one_hour(self) -> None:
        td = hart_ticks_to_timedelta(3600 * 32000)
        assert td == timedelta(hours=1)

    def test_ticks_per_second_constant(self) -> None:
        assert HART_TICKS_PER_SECOND == 32000


# ---------------------------------------------------------------------------
# 13. DeviceInfo integration
# ---------------------------------------------------------------------------


class TestDeviceInfoIntegration:
    def test_flags_decoded(self) -> None:
        info = DeviceInfo(flags=0x0B)  # bits 0,1,3
        decoded = info.flags_decoded
        assert decoded["multi_sensor_field_device"] is True
        assert decoded["eeprom_control"] is True
        assert decoded["ieee802_15_4_capable"] is True
        assert decoded["c8psk_capable"] is False

    def test_extended_device_status_decoded(self) -> None:
        info = DeviceInfo(extended_field_device_status=0x05)  # bits 0,2
        decoded = info.extended_device_status_decoded
        assert decoded["maintenance_required"] is True
        assert decoded["critical_power_failure"] is True
        assert decoded["failure"] is False


# ---------------------------------------------------------------------------
# 14. DeviceVariable integration
# ---------------------------------------------------------------------------


class TestDeviceVariableIntegration:
    def test_classification_name_temperature(self) -> None:
        dv = DeviceVariable(
            slot=0,
            device_var_code=1,
            classification=64,
            unit_code=32,
            unit_name="degC",
            value=25.0,
            status=0xC0,
        )
        assert dv.classification_name == "Temperature"

    def test_classification_name_pressure(self) -> None:
        dv = DeviceVariable(
            slot=0,
            device_var_code=0,
            classification=65,
            unit_code=7,
            unit_name="bar",
            value=1.0,
            status=0,
        )
        assert dv.classification_name == "Pressure"

    def test_classification_name_not_classified(self) -> None:
        dv = DeviceVariable(
            slot=0,
            device_var_code=0,
            classification=0,
            unit_code=0,
            unit_name="",
            value=0.0,
            status=0,
        )
        assert dv.classification_name == "Not Classified"

    def test_status_decoded(self) -> None:
        # Good(0xC0) + Not Limited(0x00) + MoreStatus(0x08)
        dv = DeviceVariable(
            slot=0,
            device_var_code=0,
            classification=64,
            unit_code=32,
            unit_name="degC",
            value=25.0,
            status=0xC8,
        )
        decoded = dv.status_decoded
        assert decoded["process_data_status_name"] == "Good"
        assert decoded["limit_status_name"] == "Not Limited"
        assert decoded["more_device_variable_status_available"] is True


# ---------------------------------------------------------------------------
# 15. Command parser integration tests
# ---------------------------------------------------------------------------


class TestCmd8Integration:
    def test_classification_names_added(self) -> None:
        payload = bytes([64, 65, 66, 67])  # Temp, Pressure, VolFlow, Velocity
        result = parse_cmd8(payload)
        assert result["pv_classification_name"] == "Temperature"
        assert result["sv_classification_name"] == "Pressure"
        assert result["tv_classification_name"] == "Volumetric Flow"
        assert result["qv_classification_name"] == "Velocity"

    def test_not_classified(self) -> None:
        payload = bytes([0, 0, 0, 0])
        result = parse_cmd8(payload)
        assert result["pv_classification_name"] == "Not Classified"

    def test_backward_compatible(self) -> None:
        """Ensure original fields are still present."""
        payload = bytes([64, 65, 66, 67])
        result = parse_cmd8(payload)
        assert result["pv_classification"] == 64
        assert result["sv_classification"] == 65
        assert result["tv_classification"] == 66
        assert result["qv_classification"] == 67


class TestCmd9Integration:
    def _make_single_slot_payload(self, ext_status: int = 0, var_status: int = 0xC0) -> bytes:
        payload = bytes([ext_status])  # extended_device_status
        payload += bytes([0x00, 0x40, 0x07])  # var_code, classification=64, unit=bar
        payload += struct.pack(">f", 1.5)
        payload += bytes([var_status])
        return payload

    def test_extended_device_status_decoded(self) -> None:
        payload = self._make_single_slot_payload(ext_status=0x05)
        result = parse_cmd9(payload)
        decoded = result["extended_device_status_decoded"]
        assert decoded["maintenance_required"] is True
        assert decoded["critical_power_failure"] is True
        assert decoded["failure"] is False

    def test_timestamp_seconds(self) -> None:
        payload = self._make_single_slot_payload()
        # Add 4-byte timestamp: 32000 ticks = 1 second
        payload += struct.pack(">I", 32000)
        result = parse_cmd9(payload)
        assert result["timestamp"] is not None
        assert abs(result["timestamp_seconds"] - 1.0) < 1e-10

    def test_timestamp_seconds_none_when_no_timestamp(self) -> None:
        payload = self._make_single_slot_payload()
        result = parse_cmd9(payload)
        assert result["timestamp"] is None
        assert result["timestamp_seconds"] is None

    def test_backward_compatible(self) -> None:
        """Ensure original fields are unchanged."""
        payload = self._make_single_slot_payload()
        result = parse_cmd9(payload)
        assert result["extended_device_status"] == 0
        assert len(result["variables"]) == 1
        dv = result["variables"][0]
        assert dv.classification == 0x40
        assert dv.unit_name == "bar"


class TestCmd15Integration:
    def _make_payload(
        self,
        alarm: int = 0,
        transfer: int = 0,
        write_protect: int = 0,
    ) -> bytes:
        payload = bytes([alarm, transfer, 0x07])  # alarm, transfer, range_units=bar
        payload += struct.pack(">f", 100.0)  # upper
        payload += struct.pack(">f", 0.0)  # lower
        payload += struct.pack(">f", 2.0)  # damping
        payload += bytes([write_protect, 0xFA, 0x00])
        return payload

    def test_alarm_selection_name(self) -> None:
        result = parse_cmd15(self._make_payload(alarm=0))
        assert result["alarm_selection_name"] == "High"

    def test_alarm_selection_name_low(self) -> None:
        result = parse_cmd15(self._make_payload(alarm=1))
        assert result["alarm_selection_name"] == "Low"

    def test_transfer_function_name(self) -> None:
        result = parse_cmd15(self._make_payload(transfer=0))
        assert result["transfer_function_name"] == "Linear"

    def test_transfer_function_name_sqrt(self) -> None:
        result = parse_cmd15(self._make_payload(transfer=1))
        assert result["transfer_function_name"] == "Square Root"

    def test_write_protect_name(self) -> None:
        result = parse_cmd15(self._make_payload(write_protect=0))
        assert result["write_protect_name"] == "No"

    def test_write_protect_name_yes(self) -> None:
        result = parse_cmd15(self._make_payload(write_protect=1))
        assert result["write_protect_name"] == "Yes"

    def test_backward_compatible(self) -> None:
        result = parse_cmd15(self._make_payload())
        assert result["alarm_selection_code"] == 0
        assert result["transfer_function_code"] == 0
        assert result["write_protect_code"] == 0
        assert result["range_unit_name"] == "bar"


class TestCmd48Integration:
    def _make_9byte_payload(
        self,
        ext_status: int = 0,
        op_mode: int = 0,
        std0: int = 0,
    ) -> bytes:
        return bytes([0x00] * 6 + [ext_status, op_mode, std0])

    def _make_13byte_payload(
        self,
        std0: int = 0,
        std1: int = 0,
        std2: int = 0,
        std3: int = 0,
    ) -> bytes:
        return bytes([0x00] * 6 + [0x00, 0x00, std0, std1, 0x00, std2, std3])

    def test_extended_device_status_decoded(self) -> None:
        result = parse_cmd48(self._make_9byte_payload(ext_status=0x05))
        decoded = result["extended_device_status_decoded"]
        assert decoded["maintenance_required"] is True
        assert decoded["critical_power_failure"] is True

    def test_operating_mode_name(self) -> None:
        result = parse_cmd48(self._make_9byte_payload(op_mode=0))
        assert result["operating_mode_name"] == "Reserved"

    def test_operating_mode_name_device_specific(self) -> None:
        result = parse_cmd48(self._make_9byte_payload(op_mode=5))
        assert result["operating_mode_name"] == "Device Specific (5)"

    def test_standardized_status_0_decoded(self) -> None:
        result = parse_cmd48(self._make_9byte_payload(std0=0x80))
        decoded = result["standardized_status_0_decoded"]
        assert decoded["device_configuration_lock"] is True
        assert decoded["electronic_defect"] is False

    def test_standardized_status_1_decoded(self) -> None:
        result = parse_cmd48(self._make_13byte_payload(std1=0x08))
        decoded = result["standardized_status_1_decoded"]
        assert decoded["battery_or_power_supply_needs_maintenance"] is True

    def test_standardized_status_2_decoded(self) -> None:
        result = parse_cmd48(self._make_13byte_payload(std2=0x10))
        decoded = result["standardized_status_2_decoded"]
        assert decoded["stale_data_notice"] is True

    def test_standardized_status_3_decoded(self) -> None:
        result = parse_cmd48(self._make_13byte_payload(std3=0x10))
        decoded = result["standardized_status_3_decoded"]
        assert decoded["radio_failure"] is True

    def test_backward_compatible_6bytes(self) -> None:
        """Minimal 6-byte payload should still work without decoded fields."""
        payload = bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
        result = parse_cmd48(payload)
        assert "extended_device_status_decoded" not in result
        assert result["device_specific_status"] == payload


class TestCmd54Integration:
    def _make_payload(self) -> bytes:
        payload = bytes([0x00])  # device_variable_code
        payload += bytes([0x00, 0x01, 0x02])  # sensor_serial
        payload += bytes([0x07])  # units_code = bar
        payload += struct.pack(">f", 100.0)  # upper
        payload += struct.pack(">f", 0.0)  # lower
        payload += struct.pack(">f", 2.0)  # damping
        payload += struct.pack(">f", 1.0)  # min_span
        payload += bytes([0x40])  # classification = 64 = Temperature
        payload += bytes([0x04])  # device_family = 4 = Temperature
        payload += struct.pack(">I", 32000)  # acquisition_period = 1 second
        payload += bytes([0x00])  # properties
        return payload

    def test_classification_name(self) -> None:
        result = parse_cmd54(self._make_payload())
        assert result["classification_name"] == "Temperature"

    def test_device_family_name(self) -> None:
        result = parse_cmd54(self._make_payload())
        assert result["device_family_name"] == "Temperature"

    def test_acquisition_period_seconds(self) -> None:
        result = parse_cmd54(self._make_payload())
        assert abs(result["acquisition_period_seconds"] - 1.0) < 1e-10

    def test_backward_compatible(self) -> None:
        result = parse_cmd54(self._make_payload())
        assert result["classification"] == 0x40
        assert result["device_family"] == 0x04
        assert result["acquisition_period"] == 32000
        assert result["unit_name"] == "bar"


class TestCmd79Integration:
    def test_device_family_name(self) -> None:
        payload = bytes([0x00, 0x00, 0x07])
        payload += struct.pack(">f", 1.0)
        payload += bytes([0x05])  # device_family = 5 = Pressure
        result = parse_cmd79(payload)
        assert result["device_family_name"] == "Pressure"


class TestCmd90Integration:
    def test_timestamp_seconds(self) -> None:
        payload = bytes([15, 6, 124])  # day, month, year
        payload += struct.pack(">I", 64000)  # 2 seconds
        payload += bytes([15, 6, 124])  # last received date
        payload += struct.pack(">I", 32000)  # 1 second
        payload += bytes([0x00])  # rtc_flags
        result = parse_cmd90(payload)
        assert abs(result["device_timestamp_seconds"] - 2.0) < 1e-10
        assert abs(result["last_received_timestamp_seconds"] - 1.0) < 1e-10

    def test_backward_compatible(self) -> None:
        payload = bytes([15, 6, 124])
        payload += struct.pack(">I", 64000)
        payload += bytes([15, 6, 124])
        payload += struct.pack(">I", 32000)
        payload += bytes([0x00])
        result = parse_cmd90(payload)
        assert result["device_timestamp"] == 64000
        assert result["last_received_timestamp"] == 32000


class TestCmd103Integration:
    def test_burst_period_seconds(self) -> None:
        payload = bytes([0x00])  # burst_message_number
        payload += struct.pack(">I", 320000)  # 10 seconds
        payload += struct.pack(">I", 640000)  # 20 seconds
        result = parse_cmd103(payload)
        assert abs(result["burst_comm_period_seconds"] - 10.0) < 1e-10
        assert abs(result["max_burst_comm_period_seconds"] - 20.0) < 1e-10


class TestCmd104Integration:
    def test_trigger_classification_name(self) -> None:
        payload = bytes([0x00, 0x00, 64, 0x07])  # burst_msg, mode, class=Temp, units
        payload += struct.pack(">f", 1.0)
        result = parse_cmd104(payload)
        assert result["trigger_classification_name"] == "Temperature"


class TestCmd105Integration:
    def test_trigger_classification_name(self) -> None:
        # Full 29-byte non-legacy payload
        payload = bytes([0x00, 31])  # burst_mode_control, command_number_legacy
        payload += bytes([0] * 8)  # device_variable_index_list
        payload += bytes([0x00, 0x01])  # burst_msg, max_burst
        payload += struct.pack(">H", 3)  # command_number
        payload += struct.pack(">I", 32000)  # burst_comm_period = 1s
        payload += struct.pack(">I", 64000)  # max_burst_comm_period = 2s
        payload += bytes([0x00])  # trigger_mode
        payload += bytes([64])  # trigger_classification = Temperature
        payload += bytes([0x07])  # trigger_units_code = bar
        payload += struct.pack(">f", 50.0)  # trigger_value
        result = parse_cmd105(payload)
        assert result["trigger_classification_name"] == "Temperature"
        assert abs(result["burst_comm_period_seconds"] - 1.0) < 1e-10
        assert abs(result["max_burst_comm_period_seconds"] - 2.0) < 1e-10


class TestCmd534Integration:
    def test_device_family_name(self) -> None:
        payload = bytes([0x00, 0x00, 0x07])
        payload += struct.pack(">f", 1.0)
        payload += bytes([0x04])  # device_family = Temperature
        result = parse_cmd534(payload)
        assert result["device_family_name"] == "Temperature"


# ---------------------------------------------------------------------------
# 16. Public API imports
# ---------------------------------------------------------------------------


class TestPublicImports:
    def test_all_decoders_importable(self) -> None:
        from hartip import (
            decode_cmd0_flags,
            decode_device_status,
            decode_device_variable_status,
            decode_extended_device_status,
            decode_standardized_status_0,
            decode_standardized_status_1,
            decode_standardized_status_2,
            decode_standardized_status_3,
        )

        assert callable(decode_device_status)
        assert callable(decode_cmd0_flags)
        assert callable(decode_extended_device_status)
        assert callable(decode_device_variable_status)
        assert callable(decode_standardized_status_0)
        assert callable(decode_standardized_status_1)
        assert callable(decode_standardized_status_2)
        assert callable(decode_standardized_status_3)

    def test_all_lookup_functions_importable(self) -> None:
        from hartip import (
            get_alarm_selection_name,
            get_classification_name,
            get_device_family_name,
            get_operating_mode_name,
            get_transfer_function_name,
            get_write_protect_name,
        )

        assert callable(get_classification_name)
        assert callable(get_transfer_function_name)
        assert callable(get_operating_mode_name)
        assert callable(get_alarm_selection_name)
        assert callable(get_write_protect_name)
        assert callable(get_device_family_name)

    def test_timestamp_helpers_importable(self) -> None:
        from hartip import hart_ticks_to_seconds, hart_ticks_to_timedelta

        assert callable(hart_ticks_to_seconds)
        assert callable(hart_ticks_to_timedelta)

    def test_lookup_dicts_importable(self) -> None:
        from hartip import (
            ALARM_SELECTION_CODES,
            CLASSIFICATION_CODES,
            DEVICE_FAMILY_CODES,
            HART_TICKS_PER_SECOND,
            OPERATING_MODE_CODES,
            TRANSFER_FUNCTION_CODES,
            WRITE_PROTECT_CODES,
        )

        assert isinstance(CLASSIFICATION_CODES, dict)
        assert isinstance(TRANSFER_FUNCTION_CODES, dict)
        assert isinstance(OPERATING_MODE_CODES, dict)
        assert isinstance(ALARM_SELECTION_CODES, dict)
        assert isinstance(WRITE_PROTECT_CODES, dict)
        assert isinstance(DEVICE_FAMILY_CODES, dict)
        assert isinstance(HART_TICKS_PER_SECOND, int)
