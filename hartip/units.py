"""
HART engineering unit code lookup table.

Source: FieldComm Group HART specification, Table of Engineering Units.
"""

from __future__ import annotations

# {unit_code: symbol}
UNITS: dict[int, str] = {
    # Pressure
    1: "inH2O",
    2: "inHg",
    3: "ftH2O",
    4: "mmH2O",
    5: "mmHg",
    6: "psi",
    7: "bar",
    8: "mbar",
    9: "g/cm2",
    10: "kg/cm2",
    11: "Pa",
    12: "kPa",
    13: "torr",
    14: "atm",
    # Temperature
    32: "degC",
    33: "degF",
    34: "degR",
    35: "K",
    # Flow / volume
    36: "mL/min",
    37: "mL/s",
    38: "mL/h",
    39: "mA",  # Special: current
    40: "cc/min",
    41: "cc/s",
    42: "cc/h",
    43: "L/min",
    44: "L/s",
    45: "L/h",
    # Electrical
    50: "Ohm",
    51: "V",
    52: "mV",
    53: "kOhm",
    # Percent / ratio
    57: "%",
    58: "pH",
    # Level / length
    60: "in",
    61: "ft",
    62: "m",
    63: "cm",
    64: "mm",
    # Mass / weight
    70: "g",
    71: "kg",
    72: "t",
    73: "lb",
    74: "oz",
    # Time
    80: "s",
    81: "min",
    82: "h",
    83: "day",
    # Frequency
    90: "Hz",
    91: "kHz",
    92: "MHz",
    # Volume
    100: "gal",
    101: "L",
    102: "m3",
    103: "ft3",
    104: "bbl",
    # Density
    120: "g/mL",
    121: "kg/m3",
    122: "lb/ft3",
    123: "lb/gal",
    # Viscosity
    130: "cP",
    131: "cSt",
    # Conductivity
    140: "uS/cm",
    141: "mS/cm",
    # Special
    250: "not used",
    251: "none",
    252: "unknown",
}


def get_unit_name(unit_code: int) -> str:
    """Look up engineering unit symbol by code.

    Args:
        unit_code: HART engineering unit code.

    Returns:
        Unit symbol string, or ``"Unit N"`` if unknown.
    """
    return UNITS.get(unit_code, f"Unit {unit_code}")
