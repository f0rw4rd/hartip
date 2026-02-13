"""
HART device data models and response parsing.

Provides dataclasses for device information and helper functions
to parse universal HART command responses (Commands 0, 1, 2, 3, 13, 20, 48).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from .ascii import unpack_ascii
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
class DeviceInfo:
    """Identity and configuration from a HART device.

    Populated by parsing Command 0 (and optionally 13/20) responses.
    """

    manufacturer_id: int = 0
    manufacturer_name: str = ""
    device_type: int = 0
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
# Response parsers for universal commands
# ---------------------------------------------------------------------------


def parse_cmd0(payload: bytes) -> DeviceInfo:
    """Parse Command 0 (Read Unique Identifier) response payload.

    Standard layout (≥12 bytes after response-code + device-status)::

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
        Byte 12+:  num_response_preambles, max_device_vars,
                   config_change_counter (2B), extended_field_device_status
    """
    if len(payload) < 12:
        return DeviceInfo()

    manufacturer_id = payload[1]
    device_type = payload[2]
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


def parse_cmd3(payload: bytes) -> list[Variable]:
    """Parse Command 3 (Read Dynamic Variables).

    Format: current(4 float) + up to 4 x [unit_code(1) + value(4 float)]
    """
    if len(payload) < 4:
        return []

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

    return variables


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


def parse_cmd20(payload: bytes) -> str:
    """Parse Command 20 (Read Long Tag) response.

    Format: 32 bytes of ASCII long tag.
    """
    if len(payload) < 32:
        return ""
    return payload[:32].decode("ascii", errors="replace").rstrip("\x00 ")
