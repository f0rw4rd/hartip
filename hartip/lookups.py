"""
HART protocol lookup tables and bitfield decoders.

Provides human-readable names for status bytes, classification codes,
transfer function codes, and other enumerated fields.

Verified against:
- Wireshark packet-hartip.c dissector
- CISAGOV Zeek/Spicy parser (hart_ip_enum.spicy, hart_ip_universal_commands.spicy)
- FieldComm Group Common Tables Specification (TS20183 version 26.0)

All bit positions cross-referenced with CISAGOV Spicy bitfield definitions.
"""

from __future__ import annotations

from datetime import timedelta

# ---------------------------------------------------------------------------
# Device Status Byte (second byte of every HART response)
# Reference: HARTDeviceStatus in constants.py, verified against Wireshark
# ---------------------------------------------------------------------------


def decode_device_status(status_byte: int) -> dict[str, bool]:
    """Decode the device status byte into individual bit flags.

    The device status byte is the second byte in every HART response data
    field. Each bit indicates a specific device condition.

    Bit layout (from CISAGOV Spicy and Wireshark dissector)::

        Bit 7: device_malfunction
        Bit 6: config_changed
        Bit 5: cold_start
        Bit 4: more_status_available
        Bit 3: loop_current_fixed
        Bit 2: loop_current_saturated
        Bit 1: non_primary_var_out_of_limits
        Bit 0: primary_var_out_of_limits

    Args:
        status_byte: Raw device status byte (0-255).

    Returns:
        Dict mapping flag name to bool.
    """
    return {
        "device_malfunction": bool(status_byte & 0x80),
        "config_changed": bool(status_byte & 0x40),
        "cold_start": bool(status_byte & 0x20),
        "more_status_available": bool(status_byte & 0x10),
        "loop_current_fixed": bool(status_byte & 0x08),
        "loop_current_saturated": bool(status_byte & 0x04),
        "non_primary_var_out_of_limits": bool(status_byte & 0x02),
        "primary_var_out_of_limits": bool(status_byte & 0x01),
    }


# ---------------------------------------------------------------------------
# Command 0 Flags Byte
# Reference: CISAGOV hart_ip_universal_commands.spicy
#   ReadUniqueIdentifierResponse.flags bitfield(8)
#   Bit 7: C8PSK_IN_MULTI_DROP_ONLY
#   Bit 6: C8PSK_CAPABLE_FIELD_DEVICE
#   Bit 5: UNDEFINED_5
#   Bit 4: SAFEHART_CAPABLE_FIELD_DEVICE
#   Bit 3: IEEE_802_15_4_DSSS_O_QPSK_MODULATION
#   Bit 2: PROTOCOL_BRIDGE_DEVICE
#   Bit 1: EEPROM_CONTROL
#   Bit 0: MUTLI_SENSOR_FIELD_DEVICE
# ---------------------------------------------------------------------------


def decode_cmd0_flags(flags_byte: int) -> dict[str, bool]:
    """Decode the Command 0 flags byte into individual bit flags.

    Bit layout (verified from CISAGOV Spicy ReadUniqueIdentifierResponse)::

        Bit 7: c8psk_in_multi_drop_only
        Bit 6: c8psk_capable
        Bit 5: undefined_5
        Bit 4: safehart_capable
        Bit 3: ieee802_15_4_capable
        Bit 2: protocol_bridge
        Bit 1: eeprom_control
        Bit 0: multi_sensor_field_device

    Note: Bit 7 also serves as the write_protect indicator in some contexts.

    Args:
        flags_byte: Raw flags byte from Command 0 response byte 8.

    Returns:
        Dict mapping flag name to bool.
    """
    return {
        "c8psk_in_multi_drop_only": bool(flags_byte & 0x80),
        "c8psk_capable": bool(flags_byte & 0x40),
        "undefined_5": bool(flags_byte & 0x20),
        "safehart_capable": bool(flags_byte & 0x10),
        "ieee802_15_4_capable": bool(flags_byte & 0x08),
        "protocol_bridge": bool(flags_byte & 0x04),
        "eeprom_control": bool(flags_byte & 0x02),
        "multi_sensor_field_device": bool(flags_byte & 0x01),
    }


# ---------------------------------------------------------------------------
# Extended Field Device Status (Common Table 17)
# Reference: CISAGOV hart_ip_universal_commands.spicy
#   extendedFieldDeviceStatus bitfield(8)
#   Bits 6..7: UNDEFINED_BITS
#   Bit 5: FUNCTION_CHECK
#   Bit 4: OUT_OF_SPECIFICATION
#   Bit 3: FAILURE
#   Bit 2: CRITICAL_POWER_FAILURE
#   Bit 1: DEVICE_VARIABLE_ALERT
#   Bit 0: MAINTENANCE_REQUIRED
# ---------------------------------------------------------------------------


def decode_extended_device_status(status_byte: int) -> dict[str, bool]:
    """Decode the extended field device status byte.

    Present in Command 0 (byte 16), Command 9 (byte 0), and Command 48
    (byte 6). Bit layout from Common Table 17 (verified against CISAGOV
    Spicy parser).

    Args:
        status_byte: Raw extended device status byte (0-255).

    Returns:
        Dict mapping flag name to bool.
    """
    return {
        "maintenance_required": bool(status_byte & 0x01),
        "device_variable_alert": bool(status_byte & 0x02),
        "critical_power_failure": bool(status_byte & 0x04),
        "failure": bool(status_byte & 0x08),
        "out_of_specification": bool(status_byte & 0x10),
        "function_check": bool(status_byte & 0x20),
    }


# ---------------------------------------------------------------------------
# Device Variable Status (Command 9 per-slot status byte)
# Reference: CISAGOV hart_ip_universal_commands.spicy
#   slotNDeviceVariableStatus bitfield(8)
#   Bits 6..7: PROCESS_DATA_STATUS -> ProcessDataStatus enum
#   Bits 4..5: LIMIT_STATUS -> LimitStatus enum
#   Bit 3: MORE_DEVICE_VARIABLE_STATUS_AVAILABLE
#   Bits 0..2: DEVICE_FAMILY_SPECIFIC_STATUS
#
# ProcessDataStatus (Common Table A-3):
#   0=BAD, 1=POOR_ACCURACY, 2=MANUAL_FIXED, 3=GOOD
# LimitStatus (Common Table A-3):
#   0=NOT_LIMITED, 1=LOW_LIMITED, 2=HIGH_LIMITED, 3=CONSTANT
# ---------------------------------------------------------------------------

_PROCESS_DATA_STATUS_NAMES: dict[int, str] = {
    0: "Bad",
    1: "Poor Accuracy",
    2: "Manual/Fixed",
    3: "Good",
}

_LIMIT_STATUS_NAMES: dict[int, str] = {
    0: "Not Limited",
    1: "Low Limited",
    2: "High Limited",
    3: "Constant",
}


def decode_device_variable_status(status_byte: int) -> dict:
    """Decode the device variable status byte from Command 9.

    Each device variable in Command 9 has an 8-bit status field with
    sub-fields for process data quality, limits, and more-status-available.

    Bit layout (from CISAGOV Spicy parser, Common Table A-3)::

        Bits 7-6: process_data_status (0=Bad, 1=Poor Accuracy, 2=Manual/Fixed, 3=Good)
        Bits 5-4: limit_status (0=Not Limited, 1=Low, 2=High, 3=Constant)
        Bit 3:    more_device_variable_status_available
        Bits 2-0: device_family_specific_status

    Args:
        status_byte: Raw device variable status byte (0-255).

    Returns:
        Dict with decoded sub-fields and human-readable names.
    """
    process_data = (status_byte >> 6) & 0x03
    limit = (status_byte >> 4) & 0x03
    more_available = bool(status_byte & 0x08)
    family_specific = status_byte & 0x07

    return {
        "process_data_status": process_data,
        "process_data_status_name": _PROCESS_DATA_STATUS_NAMES.get(
            process_data, f"Unknown ({process_data})"
        ),
        "limit_status": limit,
        "limit_status_name": _LIMIT_STATUS_NAMES.get(limit, f"Unknown ({limit})"),
        "more_device_variable_status_available": more_available,
        "device_family_specific_status": family_specific,
    }


# ---------------------------------------------------------------------------
# Standardized Status Bytes 0-3 (Command 48)
# Reference: CISAGOV hart_ip_universal_commands.spicy
#   ReadAdditionalDeviceStatusContents
# ---------------------------------------------------------------------------


def decode_standardized_status_0(status_byte: int) -> dict[str, bool]:
    """Decode Standardized Status 0 byte from Command 48 (Common Table 29).

    Bit layout (verified from CISAGOV Spicy parser)::

        Bit 7: device_configuration_lock
        Bit 6: electronic_defect
        Bit 5: environmental_conditions_out_of_range
        Bit 4: power_supply_conditions_out_of_range
        Bit 3: watchdog_reset_executed
        Bit 2: volatile_memory_defect
        Bit 1: non_volatile_memory_defect
        Bit 0: device_variable_simulation_active

    Args:
        status_byte: Raw standardized status 0 byte.

    Returns:
        Dict mapping flag name to bool.
    """
    return {
        "device_configuration_lock": bool(status_byte & 0x80),
        "electronic_defect": bool(status_byte & 0x40),
        "environmental_conditions_out_of_range": bool(status_byte & 0x20),
        "power_supply_conditions_out_of_range": bool(status_byte & 0x10),
        "watchdog_reset_executed": bool(status_byte & 0x08),
        "volatile_memory_defect": bool(status_byte & 0x04),
        "non_volatile_memory_defect": bool(status_byte & 0x02),
        "device_variable_simulation_active": bool(status_byte & 0x01),
    }


def decode_standardized_status_1(status_byte: int) -> dict:
    """Decode Standardized Status 1 byte from Command 48 (Common Table 30).

    Bit layout (verified from CISAGOV Spicy parser)::

        Bits 7-5: undefined (reserved)
        Bit 4: reserved
        Bit 3: battery_or_power_supply_needs_maintenance
        Bit 2: event_notification_overflow
        Bit 1: discrete_variable_simulation_active
        Bit 0: status_simulation_active

    Args:
        status_byte: Raw standardized status 1 byte.

    Returns:
        Dict mapping flag name to bool (or int for undefined bits).
    """
    return {
        "undefined_bits": (status_byte >> 5) & 0x07,
        "reserved": bool(status_byte & 0x10),
        "battery_or_power_supply_needs_maintenance": bool(status_byte & 0x08),
        "event_notification_overflow": bool(status_byte & 0x04),
        "discrete_variable_simulation_active": bool(status_byte & 0x02),
        "status_simulation_active": bool(status_byte & 0x01),
    }


def decode_standardized_status_2(status_byte: int) -> dict:
    """Decode Standardized Status 2 byte from Command 48 (Common Table 31).

    Bit layout (verified from CISAGOV Spicy parser)::

        Bits 7-5: undefined (reserved)
        Bit 4: stale_data_notice
        Bit 3: sub_device_with_duplicate_id
        Bit 2: sub_device_mismatch
        Bit 1: duplicate_master_detected
        Bit 0: sub_device_list_changed

    Args:
        status_byte: Raw standardized status 2 byte.

    Returns:
        Dict mapping flag name to bool (or int for undefined bits).
    """
    return {
        "undefined_bits": (status_byte >> 5) & 0x07,
        "stale_data_notice": bool(status_byte & 0x10),
        "sub_device_with_duplicate_id": bool(status_byte & 0x08),
        "sub_device_mismatch": bool(status_byte & 0x04),
        "duplicate_master_detected": bool(status_byte & 0x02),
        "sub_device_list_changed": bool(status_byte & 0x01),
    }


def decode_standardized_status_3(status_byte: int) -> dict:
    """Decode Standardized Status 3 byte from Command 48 (Common Table 32).

    Bit layout (verified from CISAGOV Spicy parser)::

        Bits 7-5: undefined (reserved)
        Bit 4: radio_failure
        Bit 3: block_transfer_pending
        Bit 2: bandwidth_allocation_pending
        Bit 1: reserved
        Bit 0: capacity_denied

    Args:
        status_byte: Raw standardized status 3 byte.

    Returns:
        Dict mapping flag name to bool (or int for undefined bits).
    """
    return {
        "undefined_bits": (status_byte >> 5) & 0x07,
        "radio_failure": bool(status_byte & 0x10),
        "block_transfer_pending": bool(status_byte & 0x08),
        "bandwidth_allocation_pending": bool(status_byte & 0x04),
        "reserved": bool(status_byte & 0x02),
        "capacity_denied": bool(status_byte & 0x01),
    }


# ---------------------------------------------------------------------------
# Classification Codes (Common Table 21, DeviceVariableClassificationCodes)
# Reference: CISAGOV hart_ip_enum.spicy line 2891
# ---------------------------------------------------------------------------

CLASSIFICATION_CODES: dict[int, str] = {
    0: "Not Classified",
    64: "Temperature",
    65: "Pressure",
    66: "Volumetric Flow",
    67: "Velocity",
    68: "Volume",
    69: "Length",
    70: "Time",
    71: "Mass",
    72: "Mass Flow",
    73: "Mass per Volume",
    74: "Viscosity",
    75: "Angular Velocity",
    76: "Area",
    77: "Energy/Work",
    78: "Force",
    79: "Power",
    80: "Frequency",
    81: "Analytical",
    82: "Capacitance",
    83: "Electromotive Force/Electric Potential",
    84: "Current",
    85: "Resistance",
    86: "Angle",
    87: "Conductance",
    88: "Volume per Volume",
    89: "Volume per Mass",
    90: "Concentration",
    96: "Acceleration",
    97: "Turbidity",
    98: "Temperature Difference",
    99: "Volumetric Gas Flow per Second",
    100: "Volumetric Gas Flow per Minute",
    101: "Volumetric Gas Flow per Hour",
    102: "Volumetric Gas Flow per Day",
    103: "Volumetric Liquid Flow per Second",
    104: "Volumetric Liquid Flow per Minute",
    105: "Volumetric Liquid Flow per Hour",
    106: "Volumetric Liquid Flow per Day",
    107: "Thermal Expansion",
    108: "Volumetric Energy Density",
    109: "Mass Energy Density",
    110: "Torque",
    111: "Miscellaneous",
    112: "Torsional Stiffness",
    113: "Linear Stiffness",
}


def get_classification_name(code: int) -> str:
    """Look up human-readable name for a device variable classification code.

    Classification codes are defined in Common Table 21
    (DeviceVariableClassificationCodes). Codes 1-63 and 91-95 are reserved.

    Args:
        code: Device variable classification code (0-255).

    Returns:
        Human-readable name, or ``"Reserved (N)"`` / ``"Unknown (N)"``
        if not recognized.
    """
    name = CLASSIFICATION_CODES.get(code)
    if name is not None:
        return name
    if 1 <= code <= 63 or 91 <= code <= 95:
        return f"Reserved ({code})"
    return f"Unknown ({code})"


# ---------------------------------------------------------------------------
# Transfer Function Codes (Common Table 3, TransferFunctionCodes)
# Reference: CISAGOV hart_ip_enum.spicy line 201
# ---------------------------------------------------------------------------

TRANSFER_FUNCTION_CODES: dict[int, str] = {
    0: "Linear",
    1: "Square Root",
    2: "Square Root Third Power",
    3: "Square Root Fifth Power",
    4: "Special Curve",
    5: "Square",
    6: "Square Root with Cutoff (DP Orifice Plate)",
    10: "Equal Percentage 1.25",
    11: "Equal Percentage 1.33",
    12: "Equal Percentage 1.50",
    15: "Quick Open 1.25",
    16: "Quick Open 1.33",
    17: "Quick Open 1.50",
    30: "Hyperbolic Shape Factor 0.10",
    31: "Hyperbolic Shape Factor 0.20",
    32: "Hyperbolic Shape Factor 0.30",
    34: "Hyperbolic Shape Factor 0.50",
    37: "Hyperbolic Shape Factor 0.70",
    40: "Hyperbolic Shape Factor 1.00",
    41: "Hyperbolic Shape Factor 1.50",
    42: "Hyperbolic Shape Factor 2.00",
    43: "Hyperbolic Shape Factor 3.00",
    44: "Hyperbolic Shape Factor 4.00",
    45: "Hyperbolic Shape Factor 5.00",
    100: "Flat Bottom Tank",
    101: "Conical or Pyramidal Bottom Tank",
    102: "Parabolic Bottom Tank",
    103: "Spherical Bottom Tank",
    104: "Angled Bottom Tank",
    105: "Flat End Cylinder Tank",
    106: "Parabolic End Cylinder Tank",
    107: "Spherical Tank",
    230: "Discrete Switch",
    231: "Square Root plus Special Curve",
    232: "Square Root Third Power plus Special Curve",
    233: "Square Root Fifth Power plus Special Curve",
    250: "Not Used",
    251: "None",
    252: "Unknown",
    253: "Special",
}


def get_transfer_function_name(code: int) -> str:
    """Look up human-readable name for a transfer function code.

    Transfer function codes are defined in Common Table 3.

    Args:
        code: Transfer function code (0-255).

    Returns:
        Human-readable name, or ``"Unknown (N)"`` if not recognized.
    """
    return TRANSFER_FUNCTION_CODES.get(code, f"Unknown ({code})")


# ---------------------------------------------------------------------------
# Operating Mode Codes (Common Table 14)
# Reference: CISAGOV hart_ip_enum.spicy line 5
#   Only code 0 (RESERVED) is defined. The HART spec reserves the entire
#   byte for future use, with 0 being the only standardized value.
# ---------------------------------------------------------------------------

OPERATING_MODE_CODES: dict[int, str] = {
    0: "Reserved",
}


def get_operating_mode_name(code: int) -> str:
    """Look up human-readable name for an operating mode code.

    Operating mode codes are defined in Common Table 14. Currently only
    code 0 (Reserved) is standardized; other values are device-specific.

    Args:
        code: Operating mode code (0-255).

    Returns:
        Human-readable name, or ``"Device Specific (N)"`` if not recognized.
    """
    return OPERATING_MODE_CODES.get(code, f"Device Specific ({code})")


# ---------------------------------------------------------------------------
# Alarm Selection Codes (Common Table 6)
# Reference: CISAGOV hart_ip_enum.spicy line 180
# ---------------------------------------------------------------------------

ALARM_SELECTION_CODES: dict[int, str] = {
    0: "High",
    1: "Low",
    239: "Hold Last Output Value",
    250: "Not Used",
    251: "None",
    252: "Unknown",
    253: "Special",
}


def get_alarm_selection_name(code: int) -> str:
    """Look up human-readable name for an alarm selection code.

    Alarm selection codes are defined in Common Table 6. Codes 240-249
    are reserved for manufacturer-specific definitions.

    Args:
        code: Alarm selection code (0-255).

    Returns:
        Human-readable name, or ``"Manufacturer Specific (N)"`` /
        ``"Unknown (N)"`` if not recognized.
    """
    name = ALARM_SELECTION_CODES.get(code)
    if name is not None:
        return name
    if 240 <= code <= 249:
        return f"Manufacturer Specific ({code})"
    return f"Unknown ({code})"


# ---------------------------------------------------------------------------
# Write Protect Codes (Common Table 7)
# Reference: CISAGOV hart_ip_enum.spicy line 170
# ---------------------------------------------------------------------------

WRITE_PROTECT_CODES: dict[int, str] = {
    0: "No",
    1: "Yes",
    250: "Not Used",
    251: "None",
    252: "Unknown",
    253: "Special",
}


def get_write_protect_name(code: int) -> str:
    """Look up human-readable name for a write protect code.

    Write protect codes are defined in Common Table 7.

    Args:
        code: Write protect code (0-255).

    Returns:
        Human-readable name, or ``"Unknown (N)"`` if not recognized.
    """
    return WRITE_PROTECT_CODES.get(code, f"Unknown ({code})")


# ---------------------------------------------------------------------------
# Device Variable Family Codes (Common Table 20)
# Reference: CISAGOV hart_ip_enum.spicy DeviceVariableFamilyCode
# ---------------------------------------------------------------------------

DEVICE_FAMILY_CODES: dict[int, str] = {
    0: "Reserved",
    1: "Reserved",
    2: "Reserved",
    3: "Reserved",
    4: "Temperature",
    5: "Pressure",
    6: "Valve/Actuator",
    7: "Simple PID Control",
    8: "pH",
    9: "Conductivity",
    10: "Totalizer",
    11: "Level",
    12: "Vortex Flow",
    13: "Mag Flow",
    14: "Coriolis Flow",
    15: "Modulating Final Control",
    250: "Not Used",
}


def get_device_family_name(code: int) -> str:
    """Look up human-readable name for a device variable family code.

    Device variable family codes are defined in Common Table 20.

    Args:
        code: Device variable family code (0-255).

    Returns:
        Human-readable name, or ``"Unknown (N)"`` if not recognized.
    """
    return DEVICE_FAMILY_CODES.get(code, f"Unknown ({code})")


# ---------------------------------------------------------------------------
# Timestamp Conversion Helpers
# Reference: Wireshark packet-hartip.c dissect_timestamp() at line ~538
#   t = tvb_get_ntohl(tvb, offset);
#   t /= 32;   // convert from 1/32 ms to ms
#   ms = t % 1000; secs = (t/1000)%60; mins = (t/60000)%60; hrs = t/3600000
# ---------------------------------------------------------------------------

#: Number of ticks per second in HART timestamp format (1/32 ms = 32000 ticks/s).
HART_TICKS_PER_SECOND = 32000


def hart_ticks_to_seconds(ticks: int) -> float:
    """Convert a HART timestamp (1/32 ms ticks) to seconds.

    HART timestamps are uint32 values where each tick is 1/32 millisecond
    (i.e., 32000 ticks per second).

    Args:
        ticks: Raw uint32 timestamp value in 1/32 ms ticks.

    Returns:
        Time in seconds as a float.
    """
    return ticks / HART_TICKS_PER_SECOND


def hart_ticks_to_timedelta(ticks: int) -> timedelta:
    """Convert a HART timestamp (1/32 ms ticks) to a :class:`datetime.timedelta`.

    Args:
        ticks: Raw uint32 timestamp value in 1/32 ms ticks.

    Returns:
        A timedelta representing the elapsed time.
    """
    return timedelta(seconds=ticks / HART_TICKS_PER_SECOND)
