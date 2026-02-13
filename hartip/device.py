"""
HART device data models and response parsing.

Provides dataclasses for device information and helper functions
to parse universal HART command responses (Commands 0, 1, 2, 3, 9, 12, 13,
14, 15, 20, 48).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from .ascii import unpack_ascii
from .constants import COMM_ERROR_MASK, HARTCommErrorFlags
from .units import get_unit_name
from .vendors import get_vendor_name


@dataclass
class Variable:
    """A HART process variable with units."""

    value: float
    unit_code: int
    unit_name: str = ""
    label: str = ""

    def __post_init__(self) -> None:
        if not self.unit_name:
            self.unit_name = get_unit_name(self.unit_code)


@dataclass
class DeviceVariable:
    """A HART device variable with classification and status (Command 9)."""

    slot: int
    device_var_code: int
    classification: int
    unit_code: int
    unit_name: str
    value: float
    status: int


@dataclass
class DeviceInfo:
    """Identity and configuration from a HART device.

    Populated by parsing Command 0 (and optionally 13/20) responses.
    """

    manufacturer_id: int = 0
    manufacturer_name: str = ""
    device_type: int = 0
    expanded_device_type: int = 0  # uint16: (manufacturer_id << 8) | device_type
    device_id: int = 0
    unique_address: bytes = b""
    hart_revision: int = 0
    software_revision: int = 0
    hardware_revision: int = 0
    physical_signaling: int = 0
    flags: int = 0
    num_preambles: int = 5
    num_response_preambles: int = 5
    config_change_counter: int = 0
    extended_field_device_status: int = 0

    # HART 7 extended fields (from Command 0 bytes 17-21)
    manufacturer_id_16bit: int = 0  # 16-bit manufacturer identification code
    private_label: int = 0
    device_profile: int = 0

    # From Command 13 (tag / descriptor / date)
    tag: str = ""
    descriptor: str = ""
    date: str = ""

    # From Command 20 (long tag, HART 6+)
    long_tag: str = ""

    def __post_init__(self) -> None:
        if not self.manufacturer_name:
            self.manufacturer_name = get_vendor_name(self.manufacturer_id)


# ---------------------------------------------------------------------------
# Communication error flag utilities
# ---------------------------------------------------------------------------


def is_comm_error(response_code_byte: int) -> bool:
    """Check if the response code byte indicates a communication error.

    When the MSB (bit 7) of the response code byte is 1, the lower 7 bits
    are communication error summary flags, not a command response code.

    Args:
        response_code_byte: The raw first byte from the PDU data field.

    Returns:
        True if bit 7 is set (communication error), False otherwise.
    """
    return bool(response_code_byte & COMM_ERROR_MASK)


def decode_comm_error_flags(response_code_byte: int) -> HARTCommErrorFlags:
    """Decode communication error summary flags from a response code byte.

    Should only be called when :func:`is_comm_error` returns True.

    Args:
        response_code_byte: The raw first byte with MSB set.

    Returns:
        HARTCommErrorFlags with the active error flags.
    """
    return HARTCommErrorFlags(response_code_byte & 0x7F)


# ---------------------------------------------------------------------------
# Response parsers for universal commands
# ---------------------------------------------------------------------------


def parse_cmd0(payload: bytes) -> DeviceInfo:
    """Parse Command 0 (Read Unique Identifier) response payload.

    Standard layout (>=12 bytes after response-code + device-status)::

        Byte 0:    Expansion code (254 for HART 7, informational)
        Byte 1:    Manufacturer ID (8-bit)
        Byte 2:    Device Type Code
        Byte 3:    Minimum Number of Request Preambles
        Byte 4:    Universal Command Revision Level (HART revision)
        Byte 5:    Transmitter-Specific Command Revision Level
        Byte 6:    Software Revision Level
        Byte 7:    Hardware Revision / Physical Signaling Code
        Byte 8:    Flags
        Bytes 9-11: Device ID (24-bit)

    Extended fields (HART 6/7, payload > 12 bytes):
        Byte 12:   num_response_preambles
        Byte 13:   max_device_vars
        Bytes 14-15: config_change_counter (2B)
        Byte 16:   extended_field_device_status

    HART 7 additional fields (payload >= 19):
        Bytes 17-18: manufacturer_identification_code (16-bit)
        Bytes 19-20: private_label (16-bit)
        Byte 21:    device_profile
    """
    if len(payload) < 12:
        return DeviceInfo()

    manufacturer_id = payload[1]
    device_type = payload[2]
    expanded_device_type = (manufacturer_id << 8) | device_type
    num_preambles = payload[3]
    hart_revision = payload[4]
    device_revision = payload[5]
    software_revision = payload[6]
    hardware_revision = (payload[7] >> 3) & 0x1F
    physical_signaling = payload[7] & 0x07
    flags = payload[8]
    device_id = (payload[9] << 16) | (payload[10] << 8) | payload[11]

    # Extended fields present in HART 6/7 responses
    num_response_preambles = payload[12] if len(payload) > 12 else 5
    config_change_counter = 0
    extended_status = 0
    if len(payload) >= 16:
        config_change_counter = struct.unpack(">H", payload[14:16])[0]
    if len(payload) > 16:
        extended_status = payload[16]

    # HART 7 extended fields (Wireshark dissector: bodylen >= 18 / >= 22)
    manufacturer_id_16bit = 0
    private_label = 0
    device_profile = 0
    if len(payload) >= 19:
        manufacturer_id_16bit = struct.unpack(">H", payload[17:19])[0]
    if len(payload) >= 22:
        private_label = struct.unpack(">H", payload[19:21])[0]
        device_profile = payload[21]

    # Build 5-byte unique address for long-frame addressing
    unique_address = bytes(
        [
            0x80 | (manufacturer_id & 0x3F),
            device_type,
            (device_id >> 16) & 0xFF,
            (device_id >> 8) & 0xFF,
            device_id & 0xFF,
        ]
    )

    return DeviceInfo(
        manufacturer_id=manufacturer_id,
        device_type=device_type,
        expanded_device_type=expanded_device_type,
        device_id=device_id,
        unique_address=unique_address,
        hart_revision=hart_revision,
        software_revision=software_revision,
        hardware_revision=hardware_revision,
        physical_signaling=physical_signaling,
        flags=flags,
        num_preambles=num_preambles,
        num_response_preambles=num_response_preambles,
        config_change_counter=config_change_counter,
        extended_field_device_status=extended_status,
        manufacturer_id_16bit=manufacturer_id_16bit,
        private_label=private_label,
        device_profile=device_profile,
    )


def parse_cmd1(payload: bytes) -> Optional[Variable]:
    """Parse Command 1 (Read Primary Variable) response.

    Format (5 bytes): unit_code(1) + value(4 IEEE 754 float)
    """
    if len(payload) < 5:
        return None
    unit_code = payload[0]
    (value,) = struct.unpack(">f", payload[1:5])
    return Variable(value=value, unit_code=unit_code, label="PV")


def parse_cmd2(payload: bytes) -> dict:
    """Parse Command 2 (Read Loop Current and Percent of Range).

    Format (8 bytes): current(4 float) + percent(4 float)
    """
    if len(payload) < 8:
        return {}
    (current,) = struct.unpack(">f", payload[0:4])
    (percent,) = struct.unpack(">f", payload[4:8])
    return {"current_mA": current, "percent_range": percent}


def parse_cmd3(payload: bytes) -> dict:
    """Parse Command 3 (Read Dynamic Variables).

    Format: current(4 float) + up to 4 x [unit_code(1) + value(4 float)]

    Returns:
        Dict with ``loop_current`` (float) and ``variables`` (list of Variable).
        Returns empty dict if payload is too short.
    """
    if len(payload) < 4:
        return {}

    (current,) = struct.unpack(">f", payload[0:4])
    variables: list[Variable] = []
    labels = ["PV", "SV", "TV", "QV"]

    offset = 4
    for i, label in enumerate(labels):
        if offset + 5 > len(payload):
            break
        unit_code = payload[offset]
        (value,) = struct.unpack(">f", payload[offset + 1 : offset + 5])
        variables.append(Variable(value=value, unit_code=unit_code, label=label))
        offset += 5

    return {"loop_current": current, "variables": variables}


def parse_cmd9(payload: bytes) -> dict:
    """Parse Command 9 (Read Device Variables with Status) response.

    Format (Wireshark dissector, packet-hartip.c:664-733)::

        Byte 0:       extended_device_status
        Per slot (up to 8 slots, 8 bytes each):
          Byte N+0:   device_var_code
          Byte N+1:   classification
          Byte N+2:   unit_code
          Bytes N+3-6: value (IEEE 754 float)
          Byte N+7:   device_var_status
        After all slots:
          4 bytes:    timestamp (optional)

    Minimum response: 13 bytes (1 ext status + 1 slot of 8 bytes + 4 timestamp).
    But the minimum per the Wireshark check is 13 bytes for 1 slot (no timestamp).

    Returns:
        Dict with ``extended_device_status`` (int), ``variables`` (list of
        DeviceVariable), and ``timestamp`` (bytes or None).
    """
    if len(payload) < 9:  # 1 byte ext status + 8 bytes for 1 slot minimum
        return {}

    extended_device_status = payload[0]
    variables: list[DeviceVariable] = []
    offset = 1

    slot_num = 0
    while offset + 8 <= len(payload) and slot_num < 8:
        device_var_code = payload[offset]
        classification = payload[offset + 1]
        unit_code = payload[offset + 2]
        (value,) = struct.unpack(">f", payload[offset + 3 : offset + 7])
        status = payload[offset + 7]
        variables.append(
            DeviceVariable(
                slot=slot_num,
                device_var_code=device_var_code,
                classification=classification,
                unit_code=unit_code,
                unit_name=get_unit_name(unit_code),
                value=value,
                status=status,
            )
        )
        offset += 8
        slot_num += 1

    # Optional 4-byte timestamp after all slots
    timestamp = None
    if offset + 4 <= len(payload):
        timestamp = payload[offset : offset + 4]

    return {
        "extended_device_status": extended_device_status,
        "variables": variables,
        "timestamp": timestamp,
    }


def parse_cmd12(payload: bytes) -> str:
    """Parse Command 12 (Read Message) response.

    Format: 24 bytes of packed ASCII (yields 32 characters).

    Reference: Wireshark dissector line 1116-1117, hipflowapp cmd_12.h.
    """
    if len(payload) < 24:
        return ""
    return unpack_ascii(payload[:24])


def parse_cmd13(payload: bytes) -> dict:
    """Parse Command 13 (Read Tag, Descriptor, Date).

    Format: tag(6 packed) + descriptor(12 packed) + day(1) + month(1) + year(1)
    """
    if len(payload) < 21:
        return {}
    tag = unpack_ascii(payload[0:6])
    descriptor = unpack_ascii(payload[6:18])
    day = payload[18]
    month = payload[19]
    year = payload[20]
    return {
        "tag": tag,
        "descriptor": descriptor,
        "date": f"{year + 1900}-{month:02d}-{day:02d}" if year else "",
    }


def parse_cmd14(payload: bytes) -> dict:
    """Parse Command 14 (Read PV Transducer Information) response.

    Format (16 bytes, from Wireshark dissector packet-hartip.c:757-768)::

        Bytes 0-2:  transducer_serial_number (3 bytes, unsigned-24)
        Byte 3:     unit_code (transducer limits and minimum span units)
        Bytes 4-7:  upper_transducer_limit (float)
        Bytes 8-11: lower_transducer_limit (float)
        Bytes 12-15: minimum_span (float)
    """
    if len(payload) < 16:
        return {}

    serial = (payload[0] << 16) | (payload[1] << 8) | payload[2]
    unit_code = payload[3]
    (upper_limit,) = struct.unpack(">f", payload[4:8])
    (lower_limit,) = struct.unpack(">f", payload[8:12])
    (min_span,) = struct.unpack(">f", payload[12:16])

    return {
        "transducer_serial_number": serial,
        "unit_code": unit_code,
        "unit_name": get_unit_name(unit_code),
        "upper_transducer_limit": upper_limit,
        "lower_transducer_limit": lower_limit,
        "minimum_span": min_span,
    }


def parse_cmd15(payload: bytes) -> dict:
    """Parse Command 15 (Read Output Information) response.

    Format (18 bytes, from Wireshark dissector packet-hartip.c:774-783)::

        Byte 0:     alarm_selection_code
        Byte 1:     transfer_function_code
        Byte 2:     range_units_code
        Bytes 3-6:  upper_range_value (float)
        Bytes 7-10: lower_range_value (float)
        Bytes 11-14: damping_value (float)
        Byte 15:    write_protect_code
        Byte 16:    reserved (should be 250 = Not Used)
        Byte 17:    analog_channel_flags
    """
    if len(payload) < 18:
        return {}

    alarm_selection = payload[0]
    transfer_function = payload[1]
    range_units = payload[2]
    (upper_range,) = struct.unpack(">f", payload[3:7])
    (lower_range,) = struct.unpack(">f", payload[7:11])
    (damping,) = struct.unpack(">f", payload[11:15])
    write_protect = payload[15]
    reserved = payload[16]
    analog_channel_flags = payload[17]

    return {
        "alarm_selection_code": alarm_selection,
        "transfer_function_code": transfer_function,
        "range_units_code": range_units,
        "range_unit_name": get_unit_name(range_units),
        "upper_range_value": upper_range,
        "lower_range_value": lower_range,
        "damping_value": damping,
        "write_protect_code": write_protect,
        "analog_channel_flags": analog_channel_flags,
    }


def parse_cmd20(payload: bytes) -> str:
    """Parse Command 20 (Read Long Tag) response.

    Format: 32 bytes of ASCII long tag.
    """
    if len(payload) < 32:
        return ""
    return payload[:32].decode("ascii", errors="replace").rstrip("\x00 ")


def parse_cmd48(payload: bytes) -> dict:
    """Parse Command 48 (Read Additional Device Status) response.

    Format (Wireshark dissector packet-hartip.c:848-879)::

        Bytes 0-5:   device_specific_status (6 bytes)
        Byte 6:      extended_device_status (if bodylen >= 9)
        Byte 7:      operating_mode (if bodylen >= 9)
        Byte 8:      standardized_status_0 (if bodylen >= 9)
        Byte 9:      standardized_status_1 (if bodylen >= 13)
        Byte 10:     analog_channel_saturated (if bodylen >= 13)
        Byte 11:     standardized_status_2 (if bodylen >= 13)
        Byte 12:     standardized_status_3 (if bodylen >= 13)
        Byte 13:     analog_channel_fixed (if bodylen >= 14)
        Bytes 14-24: additional device_specific_status (if bodylen >= 24)

    Returns:
        Dict with parsed fields. Returns empty dict if payload < 6 bytes.
    """
    if len(payload) < 6:
        return {}

    result: dict = {
        "device_specific_status": payload[0:6],
    }

    if len(payload) >= 9:
        result["extended_device_status"] = payload[6]
        result["operating_mode"] = payload[7]
        result["standardized_status_0"] = payload[8]

    if len(payload) >= 13:
        result["standardized_status_1"] = payload[9]
        result["analog_channel_saturated"] = payload[10]
        result["standardized_status_2"] = payload[11]
        result["standardized_status_3"] = payload[12]

    if len(payload) >= 14:
        result["analog_channel_fixed"] = payload[13]

    if len(payload) >= 25:
        result["additional_device_specific_status"] = payload[14:25]

    return result
