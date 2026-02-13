"""
HART manufacturer ID lookup table.

Source: FieldComm Group registered manufacturer list.
Only a subset of commonly encountered vendors is included.
"""

from __future__ import annotations

# {manufacturer_id: name}
MANUFACTURERS: dict[int, str] = {
    0x00: "Unknown",
    0x01: "Fisher Controls (Emerson)",
    0x02: "ABB",
    0x03: "Emerson (Rosemount)",
    0x04: "Foxboro (Schneider Electric)",
    0x05: "Moore Industries",
    0x06: "Drexelbrook",
    0x07: "Elsag Bailey (ABB)",
    0x08: "Turck",
    0x09: "Pepperl+Fuchs",
    0x0A: "Krohne",
    0x0B: "Magnetrol",
    0x0C: "Ohmart",
    0x0D: "Milltronics (Siemens)",
    0x0E: "K-Tek",
    0x0F: "Ronan Engineering",
    0x10: "Endress+Hauser (Instruments)",
    0x11: "Endress+Hauser",
    0x12: "Envec Fluid Control",
    0x13: "Promag (Endress+Hauser)",
    0x14: "Micro Motion (Emerson)",
    0x15: "Deltabar (Endress+Hauser)",
    0x17: "Honeywell",
    0x1A: "Danfoss",
    0x1E: "Vega",
    0x26: "Rosemount (Emerson)",
    0x2A: "Siemens",
    0x2C: "Stahl",
    0x30: "Wika",
    0x37: "Yokogawa",
    0x39: "Schneider Electric",
    0x3A: "MTL",
    0x3F: "Phoenix Contact",
    0x42: "Samson",
    0x4F: "HIMA",
    0x53: "Azbil (Yamatake)",
    0x58: "Burkert",
    0x5A: "Mettler-Toledo",
    0x60: "VEGA Grieshaber",
    0x68: "Endress+Hauser (Flowtec)",
    0x69: "Emerson (Fisher-Rosemount)",
    0x75: "KROHNE Messtechnik",
    0x80: "IFM Electronic",
    0x9A: "Profibus Nutzerorganisation",
    0xDA: "FieldComm Group",
}


def get_vendor_name(manufacturer_id: int) -> str:
    """Look up manufacturer name by ID.

    Args:
        manufacturer_id: HART manufacturer identifier.

    Returns:
        Manufacturer name, or ``"Unknown (0xNN)"`` if not found.
    """
    return MANUFACTURERS.get(manufacturer_id, f"Unknown (0x{manufacturer_id:02X})")
