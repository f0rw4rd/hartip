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

    Expected format (≥12 bytes after response-code + device-status):
        Byte 0:    Expansion code (254 = HART 6/7 extended)
        Byte 1-2:  Manufacturer ID (expanded) **or** Byte 1 only
        ...layout depends on expansion code...
        Last 3:    Device ID (24-bit unique serial)

    The exact layout varies by HART revision.  We handle both
    the legacy (HART 5) and expanded (HART 6/7) formats.
    """
    if len(payload) < 12:
        return DeviceInfo()

    expansion = payload[0]
    if expansion == 254 and len(payload) >= 16:
        # HART 6/7 expanded response
        manufacturer_id = (payload[1] << 8) | payload[2]
        device_type = payload[3]
        num_preambles = payload[4]
        hart_revision = payload[5]
        software_revision = payload[6]
        hardware_revision = payload[7]
        physical_signaling = payload[8]
        flags = payload[9]
        device_id = (payload[10] << 16) | (payload[11] << 8) | payload[12]
        num_response_preambles = payload[13] if len(payload) > 13 else 5
        config_change_counter = (
            struct.unpack(">H", payload[14:16])[0] if len(payload) >= 16 else 0
        )
        extended_status = payload[16] if len(payload) > 16 else 0
    else:
        # Legacy HART 5 response
        manufacturer_id = payload[1]
        device_type = payload[2]
        num_preambles = payload[3]
        hart_revision = payload[4]
        software_revision = payload[5]
        hardware_revision = payload[6]
        physical_signaling = payload[7]
        flags = payload[8]
        device_id = (payload[9] << 16) | (payload[10] << 8) | payload[11]
        num_response_preambles = 5
        config_change_counter = 0
        extended_status = 0

    # Build 5-byte unique address
    unique_address = bytes(
        [
            0x80 | ((manufacturer_id >> 8) & 0x3F),
            manufacturer_id & 0xFF,
            device_type,
            (device_id >> 16) & 0xFF,
            (device_id >> 8) & 0xFF,
            device_id & 0xFF,
        ]
    )
    # Actually unique address is 5 bytes: [mfr_hi|0x80, mfr_lo, dev_type, id_hi, id_mid, id_lo]
    # But HART defines it as 5 bytes for long-frame addressing, so trim:
    unique_address = unique_address[:5]

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
