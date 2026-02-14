"""
HART engineering unit code lookup table.

Source: FieldComm Group Common Tables Specification (FCG TS20183).
Cross-referenced against CISAGOV Zeek/Spicy parser (hart_ip_enum.spicy),
FieldComm hipflowapp reference implementation, and PyHART Table 2.
"""

from __future__ import annotations

# {unit_code: symbol}
UNITS: dict[int, str] = {
    # -- Pressure (codes 1-14) --
    1: "inH2O",         # inches H2O @ 68F
    2: "inHg",          # inches Hg @ 0C
    3: "ftH2O",         # feet H2O @ 68F
    4: "mmH2O",         # mm H2O @ 68F
    5: "mmHg",          # mm Hg @ 0C
    6: "psi",           # pounds per square inch
    7: "bar",           # bars
    8: "mbar",          # millibars
    9: "g/cm2",         # grams per square centimeter
    10: "kg/cm2",       # kilograms per square centimeter
    11: "Pa",           # Pascals
    12: "kPa",          # kiloPascals
    13: "torr",         # torr
    14: "atm",          # atmospheres
    # -- Flow / volume rate (codes 15-31) --
    15: "cfm",          # cubic feet per minute
    16: "gpm",          # gallons per minute
    17: "L/min",        # liters per minute
    18: "Igpm",         # Imperial gallons per minute
    19: "m3/h",         # cubic meters per hour
    20: "ft/s",         # feet per second
    21: "m/s",          # meters per second
    22: "gps",          # gallons per second
    23: "MGD",          # million gallons per day
    24: "L/s",          # liters per second
    25: "MLD",          # million liters per day
    26: "cfs",          # cubic feet per second
    27: "cfd",          # cubic feet per day
    28: "m3/s",         # cubic meters per second
    29: "m3/d",         # cubic meters per day
    30: "Igph",         # Imperial gallons per hour
    31: "Igpd",         # Imperial gallons per day
    # -- Temperature (codes 32-35) --
    32: "degC",         # degrees Celsius
    33: "degF",         # degrees Fahrenheit
    34: "degR",         # degrees Rankine
    35: "K",            # Kelvin
    # -- Electrical / misc (codes 36-39) --
    36: "mV",           # millivolts
    37: "ohm",          # ohms
    38: "Hz",           # hertz
    39: "mA",           # milliamperes
    # -- Volume / length (codes 40-49) --
    40: "gal",          # gallons
    41: "L",            # liters
    42: "Igal",         # Imperial gallons
    43: "m3",           # cubic meters
    44: "ft",           # feet
    45: "m",            # meters
    46: "bbl",          # barrels
    47: "in",           # inches
    48: "cm",           # centimeters
    49: "mm",           # millimeters
    # -- Time (codes 50-53) --
    50: "min",          # minutes
    51: "s",            # seconds
    52: "h",            # hours
    53: "d",            # days
    # -- Viscosity / conductivity (codes 54-56) --
    54: "cSt",          # centistokes
    55: "cP",           # centipoise
    56: "uS",           # microsiemens
    # -- Percent / electrical (codes 57-59) --
    57: "%",            # percent
    58: "V",            # volts
    59: "pH",           # pH (potential of hydrogen)
    # -- Mass (codes 60-65) --
    60: "g",            # grams
    61: "kg",           # kilograms
    62: "t",            # metric tons
    63: "lb",           # pounds
    64: "ton",          # short tons
    65: "lton",         # long tons
    # -- Conductivity (codes 66-67) --
    66: "mS/cm",        # millisiemens per centimeter
    67: "uS/cm",        # microsiemens per centimeter
    # -- Force (codes 68-69) --
    68: "N",            # Newtons
    69: "J",            # Joules
    # -- Mass flow (codes 70-88) --
    70: "g/s",          # grams per second
    71: "g/min",        # grams per minute
    72: "g/h",          # grams per hour
    73: "kg/s",         # kilograms per second
    74: "kg/min",       # kilograms per minute
    75: "kg/h",         # kilograms per hour
    76: "kg/d",         # kilograms per day
    77: "t/min",        # metric tons per minute
    78: "t/h",          # metric tons per hour
    79: "t/d",          # metric tons per day
    80: "lb/s",         # pounds per second
    81: "lb/min",       # pounds per minute
    82: "lb/h",         # pounds per hour
    83: "lb/d",         # pounds per day
    84: "ton/min",      # short tons per minute
    85: "ton/h",        # short tons per hour
    86: "ton/d",        # short tons per day
    87: "lton/h",       # long tons per hour
    88: "lton/d",       # long tons per day
    # -- Misc (code 89) --
    89: "dktherm",      # deka therms
    # -- Density / specific gravity (codes 90-99) --
    90: "SG",           # specific gravity
    91: "g/cc",         # grams per cubic centimeter
    92: "kg/m3",        # kilograms per cubic meter
    93: "lb/gal",       # pounds per gallon
    94: "lb/ft3",       # pounds per cubic foot
    95: "g/mL",         # grams per milliliter
    96: "kg/L",         # kilograms per liter
    97: "g/L",          # grams per liter
    98: "lb/in3",       # pounds per cubic inch
    99: "ton/yd3",      # short tons per cubic yard
    # -- Concentration / level (codes 100-109) --
    100: "degTw",       # degrees Twaddell
    101: "degBx",       # degrees Brix
    102: "degBe_h",     # degrees Baume heavy
    103: "degBe_l",     # degrees Baume light
    104: "degAPI",      # degrees API
    105: "%w",          # percent solids per weight
    106: "%v",          # percent solids per volume
    107: "degBall",     # degrees Balling
    108: "proof/v",     # proof per volume
    109: "proof/m",     # proof per mass
    # -- Volume (codes 110-113) --
    110: "bu",          # bushels
    111: "yd3",         # cubic yards
    112: "ft3",         # cubic feet
    113: "in3",         # cubic inches
    # -- Velocity / rotation (codes 114-123) --
    114: "in/s",        # inches per second
    115: "in/min",      # inches per minute
    116: "ft/min",      # feet per minute
    117: "deg/s",       # degrees per second
    118: "rps",         # revolutions per second
    119: "rpm",         # revolutions per minute
    120: "m/h",         # meters per hour
    121: "Nm3/h",       # normal cubic meters per hour
    122: "NL/h",        # normal liters per hour
    123: "scfm",        # standard cubic feet per minute
    # -- Additional volume / energy (codes 124-129) --
    124: "bbl_US",      # US barrels (liquid)
    125: "oz",          # ounces
    126: "ft*lbf",      # foot-pound force
    127: "kW",          # kilowatts
    128: "kWh",         # kilowatt hours
    129: "hp",          # horsepower
    # -- Additional flow rates (codes 130-138) --
    130: "ft3/h",       # cubic feet per hour
    131: "m3/min",      # cubic meters per minute
    132: "bbl/s",       # barrels per second
    133: "bbl/min",     # barrels per minute
    134: "bbl/h",       # barrels per hour
    135: "bbl/d",       # barrels per day
    136: "gal/h",       # gallons per hour
    137: "Igal/s",      # Imperial gallons per second
    138: "L/h",         # liters per hour
    # -- Concentration / energy (codes 139-144) --
    139: "ppm",         # parts per million
    140: "Mcal/h",      # megacalories per hour
    141: "MJ/h",        # megajoules per hour
    142: "BTU/h",       # British thermal units per hour
    143: "deg",         # degrees (angle)
    144: "rad",         # radians
    # -- Pressure variant / concentration (codes 145-155) --
    145: "inH2O@60F",   # inches H2O at 60F
    146: "ug/L",        # micrograms per liter
    147: "ug/m3",       # micrograms per cubic meter
    148: "%cons",       # percent consistency
    149: "vol%",        # volume percent
    150: "%SQ",         # percent steam quality
    151: "ft/16",       # feet in sixteenths
    152: "ft3/lb",      # cubic feet per pound
    153: "pF",          # picofarads
    154: "mL/L",        # milliliters per liter
    155: "uL/L",        # microliters per liter
    # -- Misc (code 156) --
    156: "dB",          # decibels
    # Codes 157-159 not defined in spec
    # -- Additional units (codes 160-169) --
    160: "%P",          # percent Plato
    161: "%LEL",        # percent lower explosion level
    162: "Mcal",        # megacalories
    163: "kohm",        # kilo-ohms
    164: "MJ",          # megajoules
    165: "BTU",         # British thermal units
    166: "Nm3",         # normal cubic meters
    167: "NL",          # normal liters
    168: "scf",         # standard cubic feet
    169: "ppb",         # parts per billion
    # Codes 170-219: device-classification-dependent (Table 21)
    # Codes 220 reserved
    220: "",            # no unit code
    # Codes 235-239: additional units
    235: "gal/d",       # gallons per day
    236: "hL",          # hectoliters
    237: "MPa",         # megaPascals
    238: "inH2O@4C",    # inches H2O at 4C
    239: "mmH2O@4C",    # mm H2O at 4C
    # Codes 240-249: manufacturer-specific
    # -- Special codes (250-255) --
    250: "NaN",         # not a number / not used
    251: "none",        # none
    252: "?",           # unknown
    253: "special",     # special
    254: "",            # not used
    255: "",            # not used
}


def get_unit_name(unit_code: int) -> str:
    """Look up engineering unit symbol by code.

    Args:
        unit_code: HART engineering unit code.

    Returns:
        Unit symbol string, or ``"Unit N"`` if unknown.
    """
    return UNITS.get(unit_code, f"Unit {unit_code}")
