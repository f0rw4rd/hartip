"""
HART protocol constants and enumerations.

Based on:
- FieldComm Group HART specification (HCF_SPEC-085)
- IEC 62591 (WirelessHART)
- TP10300 (HART-IP transport)
"""

from __future__ import annotations

from enum import IntEnum


class HARTIPVersion(IntEnum):
    """HART-IP protocol version."""

    V1 = 1  # Plaintext (TP10300)


class HARTIPMessageType(IntEnum):
    """HART-IP message types (TP10300 Section 6.2)."""

    REQUEST = 0
    RESPONSE = 1
    PUBLISH = 2
    NAK = 15


class HARTIPStatus(IntEnum):
    """HART-IP status codes (TP10300 Section 6.3)."""

    SUCCESS = 0
    WARNING = 1
    ERROR = 2
    BUSY = 3
    INVALID_MESSAGE_TYPE = 4
    INVALID_SESSION = 5
    TOO_FEW_BYTES = 6
    TOO_MANY_BYTES = 7
    BUFFER_OVERFLOW = 8


class HARTFrameType(IntEnum):
    """HART PDU frame delimiter types."""

    SHORT_FRAME = 0x02  # 1-byte polling address
    LONG_FRAME = 0x82  # 5-byte unique address
    BURST_SHORT = 0x01  # Burst mode (short)
    BURST_LONG = 0x81  # Burst mode (long)


class HARTCommand(IntEnum):
    """HART command numbers.

    Universal commands (0-19): required by all HART devices.
    Common practice commands (20-99): optional but standardized.
    WirelessHART commands (768+): IEC 62591.
    """

    # --- Universal commands ---
    READ_UNIQUE_ID = 0
    READ_PRIMARY_VARIABLE = 1
    READ_CURRENT_AND_PERCENT = 2
    READ_DYNAMIC_VARS = 3
    WRITE_POLL_ADDRESS = 6
    READ_LOOP_CONFIG = 7
    READ_DYNAMIC_VAR_CLASSIFICATION = 8
    READ_DEVICE_VARS_STATUS = 9
    READ_UNIQUE_ID_TAG = 11
    READ_MESSAGE = 12
    READ_TAG_DESCRIPTOR_DATE = 13
    READ_PRIMARY_VAR_INFO = 14
    READ_OUTPUT_INFO = 15
    READ_FINAL_ASSEMBLY = 16
    WRITE_MESSAGE = 17
    WRITE_TAG_DESCRIPTOR_DATE = 18
    WRITE_FINAL_ASSEMBLY = 19

    # --- Common practice commands ---
    READ_LONG_TAG = 20
    WRITE_LONG_TAG = 21
    SET_PRIMARY_RANGE = 35
    RESET_CONFIG_FLAG = 38
    PERFORM_SELF_TEST = 41
    PERFORM_MASTER_RESET = 42
    SET_DEVICE_VAR_ZERO = 43
    WRITE_PRIMARY_VAR_UNITS = 44
    TRIM_LOOP_CURRENT_ZERO = 45
    TRIM_LOOP_CURRENT_GAIN = 46
    WRITE_PRIMARY_VAR_XFER_FUNCTION = 47
    READ_ADDITIONAL_STATUS = 48
    WRITE_DAMPING = 50
    WRITE_DEVICE_VAR_UNITS = 59
    READ_ANALOG_CHANNELS = 66
    READ_ANALOG_CHANNEL_INFO = 67
    READ_IO_CHANNEL_FLAGS = 68

    # --- Device lock (HART 6+) ---
    READ_LOCK_DEVICE_STATE = 76
    WRITE_LOCK_DEVICE = 77

    # --- WirelessHART (HART 7 / IEC 62591) ---
    READ_SUB_DEVICE_IDENTITY = 84
    READ_SUB_DEVICE_COUNT = 85
    READ_NETWORK_ID = 768
    WRITE_NETWORK_ID = 769
    WRITE_JOIN_KEY = 770
    READ_NETWORK_TAG = 773
    READ_WIRELESS_DEVICE_STATUS = 779
    READ_WIRELESS_DEVICE_STATISTICS = 785
    READ_GRAPH_NEIGHBORS = 787
    READ_DEVICE_LIST_ENTRIES = 832


class HARTResponseCode(IntEnum):
    """HART response codes (first byte of response data)."""

    SUCCESS = 0
    UNDEFINED_COMMAND = 1
    INVALID_SELECTION = 2
    PARAMETER_TOO_LARGE = 3
    PARAMETER_TOO_SMALL = 4
    TOO_FEW_DATA_BYTES = 5
    TRANSMITTER_SPECIFIC = 6
    IN_WRITE_PROTECT_MODE = 7
    UPDATE_FAILURE = 8
    SET_TO_NEAREST_VALUE = 9
    INVALID_SPAN = 10
    LOWER_RANGE_TOO_HIGH = 11
    UPPER_RANGE_TOO_LOW = 12
    UPPER_LOWER_OUT_OF_LIMITS = 13
    LOOP_CURRENT_NOT_ACTIVE = 14
    LOOP_CURRENT_FIXED = 15
    DEVICE_BUSY = 16
    CMD_NOT_IMPLEMENTED = 32
    ACCESS_RESTRICTED = 33
    DEVICE_MALFUNCTION = 64


class HARTDeviceStatus(IntEnum):
    """Device status bit flags (second byte of response data)."""

    PRIMARY_VAR_OUT_OF_LIMITS = 0x01
    NON_PRIMARY_VAR_OUT_OF_LIMITS = 0x02
    LOOP_CURRENT_SATURATED = 0x04
    LOOP_CURRENT_FIXED = 0x08
    MORE_STATUS_AVAILABLE = 0x10
    COLD_START = 0x20
    CONFIG_CHANGED = 0x40
    DEVICE_MALFUNCTION = 0x80


# HART-IP default ports
HARTIP_UDP_PORT = 5094
HARTIP_TCP_PORT = 5095

# HART-IP header size (bytes)
HARTIP_HEADER_SIZE = 8
