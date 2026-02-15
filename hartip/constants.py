"""
HART protocol constants and enumerations.

Based on:
- FieldComm Group HART specification (HCF_SPEC-085)
- IEC 62591 (WirelessHART)
- TP10300 (HART-IP transport)
- Wireshark packet-hartip.c dissector
- CISAGOV Zeek hart_ip_enum.spicy
"""

from __future__ import annotations

from enum import IntEnum, IntFlag


class HARTIPVersion(IntEnum):
    """HART-IP protocol version."""

    V1 = 1  # Plaintext (TP10300)
    V2 = 2  # Mandatory TLS/DTLS (TP10300 rev 2020)


class HARTIPMessageType(IntEnum):
    """HART-IP message types (TP10300 Section 6.2)."""

    REQUEST = 0
    RESPONSE = 1
    PUBLISH = 2
    ERROR = 3
    NAK = 15


class HARTIPMessageID(IntEnum):
    """HART-IP message ID (TP10300 Section 6.4).

    Identifies the purpose of the message within the session.
    """

    SESSION_INITIATE = 0
    SESSION_CLOSE = 1
    KEEP_ALIVE = 2
    HART_PDU = 3  # Token-passing PDU (pass-through)
    DIRECT_PDU = 4  # Native HART-IP frame (WirelessHART gateways)
    READ_AUDIT_LOG = 5  # Session audit log retrieval


# Session Initiate master type codes
MASTER_TYPE_PRIMARY = 1
MASTER_TYPE_SECONDARY = 0

# Default inactivity close timer (milliseconds)
# C# reference: INACTIVITY_CLOSE_TIME = 600000 (10 minutes)
DEFAULT_INACTIVITY_TIMER = 600000


class HARTIPStatus(IntEnum):
    """HART-IP status codes (TP10300 Section 6.3 / 20081/TS20081/9.1 Section 10.3.2).

    Reference: CISAGOV hart_ip_enum.spicy StatusCode, FieldComm C# HARTIPConnect.cs,
    hipserver hstypes.h HARTIP_SESSION_ERROR_TYPE.
    """

    SUCCESS = 0
    ERROR_INVALID_SELECTION = 2  # Invalid Master Type (hstypes.h: INVALID_MASTER_TYPE)
    ERROR_TOO_FEW_DATA_BYTES = 5  # Too Few Data Bytes Received
    ERROR_DEVICE_SPECIFIC = 6  # Device Specific Command Error
    WARNING_SET_TO_NEAREST_VALUE = 8  # Inactivity Timer set to nearest possible value
    ERROR_SECURITY_NOT_INITIALIZED = 9
    WARNING_PROTOCOL_VERSION_NOT_SUPPORTED = 14
    ERROR_ALL_SESSIONS_IN_USE = 15
    ERROR_SESSION_ALREADY_EXISTS = 16  # Session already established (hstypes.h: SESSION_EXISTS)
    WARNING_INSECURE_SESSION_EXISTS = 30


class HARTFrameType(IntEnum):
    """HART PDU frame delimiter types."""

    # Master -> Slave (STX)
    SHORT_FRAME = 0x02  # 1-byte polling address
    LONG_FRAME = 0x82  # 5-byte unique address
    # Slave -> Master (ACK)
    ACK_SHORT = 0x06  # 1-byte polling address
    ACK_LONG = 0x86  # 5-byte unique address
    # Burst mode
    BURST_SHORT = 0x01  # Burst (short)
    BURST_LONG = 0x81  # Burst (long)


class HARTCommand(IntEnum):
    """HART command numbers.

    Universal commands (0-19): required by all HART devices.
    Common practice commands (20-89): optional but standardized.
    WirelessHART commands (768+): IEC 62591.

    Full list per CISAGOV hart_ip_enum.spicy (90 standard commands).
    """

    # --- Universal commands (0-19) ---
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

    # --- Common practice commands (20-89) ---
    READ_LONG_TAG = 20
    READ_UNIQUE_ID_LONG_TAG = 21
    WRITE_LONG_TAG = 22
    READ_DEVICE_VARIABLES = 33
    WRITE_PV_DAMPING = 34
    SET_PRIMARY_RANGE = 35
    SET_PV_UPPER_RANGE = 36
    SET_PV_LOWER_RANGE = 37
    RESET_CONFIG_FLAG = 38
    EEPROM_CONTROL = 39
    ENTER_EXIT_FIXED_CURRENT = 40
    PERFORM_SELF_TEST = 41
    PERFORM_MASTER_RESET = 42
    SET_DEVICE_VAR_ZERO = 43
    WRITE_PRIMARY_VAR_UNITS = 44
    TRIM_LOOP_CURRENT_ZERO = 45
    TRIM_LOOP_CURRENT_GAIN = 46
    WRITE_PRIMARY_VAR_XFER_FUNCTION = 47
    READ_ADDITIONAL_STATUS = 48
    WRITE_PV_TRANSDUCER_SERIAL = 49
    READ_DYNAMIC_VAR_ASSIGNMENTS = 50
    WRITE_DYNAMIC_VAR_ASSIGNMENTS = 51
    SET_DEVICE_VAR_ZERO_DV = 52
    WRITE_DEVICE_VAR_UNITS = 53
    READ_DEVICE_VAR_INFO = 54
    WRITE_DEVICE_VAR_DAMPING = 55
    WRITE_DEVICE_VAR_TRANSDUCER_SERIAL = 56
    READ_UNIT_TAG_DESCRIPTOR_DATE = 57
    WRITE_UNIT_TAG_DESCRIPTOR_DATE = 58
    WRITE_NUM_RESPONSE_PREAMBLES = 59
    READ_ANALOG_CHANNEL_PERCENT = 60
    READ_DYNAMIC_VARS_PV_ANALOG = 61
    READ_ANALOG_CHANNELS = 62
    READ_ANALOG_CHANNEL_INFO = 63
    WRITE_ANALOG_CHANNEL_DAMPING = 64
    WRITE_ANALOG_CHANNEL_RANGE = 65
    ENTER_EXIT_FIXED_ANALOG_CHANNEL = 66
    TRIM_ANALOG_CHANNEL_ZERO = 67
    TRIM_ANALOG_CHANNEL_GAIN = 68
    WRITE_ANALOG_CHANNEL_XFER_FUNCTION = 69
    READ_ANALOG_CHANNEL_ENDPOINTS = 70
    LOCK_DEVICE = 71
    SQUAWK = 72
    FIND_DEVICE = 73
    READ_IO_SYSTEM_CAPABILITIES = 74
    POLL_SUB_DEVICE = 75
    READ_LOCK_DEVICE_STATE = 76
    SEND_COMMAND_TO_SUB_DEVICE = 77
    READ_AGGREGATED_COMMANDS = 78
    WRITE_DEVICE_VARIABLE = 79
    READ_DEVICE_VAR_TRIM_POINTS = 80
    READ_DEVICE_VAR_TRIM_GUIDELINES = 81
    WRITE_DEVICE_VAR_TRIM_POINT = 82
    RESET_DEVICE_VAR_TRIM = 83
    READ_SUB_DEVICE_IDENTITY = 84
    READ_IO_CHANNEL_STATISTICS = 85
    READ_SUB_DEVICE_STATISTICS = 86
    WRITE_IO_SYSTEM_MASTER_MODE = 87
    WRITE_IO_SYSTEM_RETRY_COUNT = 88
    SET_REAL_TIME_CLOCK = 89

    # --- WirelessHART (HART 7 / IEC 62591) ---
    READ_NETWORK_ID = 768
    WRITE_NETWORK_ID = 769
    WRITE_JOIN_KEY = 770
    READ_NETWORK_TAG = 773
    READ_WIRELESS_DEVICE_STATUS = 779
    READ_WIRELESS_DEVICE_STATISTICS = 785
    READ_GRAPH_NEIGHBORS = 787
    READ_DEVICE_LIST_ENTRIES = 832


class HARTResponseCode(IntEnum):
    """HART response codes (first byte of response data).

    Codes 0-15 are universal response codes (Spec 307).
    Codes 16-31 have command-specific meanings (some universal defaults below).
    Codes 32-36 are delayed-response / busy codes.
    Code 64 means command not implemented.

    Reference: hartdefs.h (hipserver), HARTMessage.cs (FieldComm C#),
    Wireshark packet-hartip.c dissector.
    """

    SUCCESS = 0
    UNDEFINED_COMMAND = 1  # Not defined / Invalid command
    INVALID_SELECTION = 2  # RC_INVALID
    PARAMETER_TOO_LARGE = 3  # RC_TOO_LRG
    PARAMETER_TOO_SMALL = 4  # RC_TOO_SML
    TOO_FEW_DATA_BYTES = 5  # RC_TOO_FEW
    TRANSMITTER_SPECIFIC = 6  # RC_DEV_SPEC (Device Specific Command Error)
    IN_WRITE_PROTECT_MODE = 7  # RC_WRT_PROT
    UPDATE_FAILURE = 8  # RC_WARN_8 (Warning: Update Failure)
    SET_TO_NEAREST_VALUE = 9  # RC_MULTIPLE_9
    INVALID_TIME_CODE = 10  # RC_MULTIPLE_10
    INVALID_POLARITY = 11  # RC_MULTIPLE_11
    INVALID_BURST_MODE = 12  # RC_MULTIPLE_12
    UNKNOWN_MESSAGE_ID = 13  # RC_MULTIPLE_13
    LOOP_CURRENT_NOT_ACTIVE = 14  # RC_WARN_14
    LOOP_CURRENT_FIXED = 15
    ACCESS_RESTRICTED = 16  # RC_ACC_RESTR (Access Restricted)
    INVALID_DEVICE_VAR_INDEX = 17  # RC_BAD_INDEX
    INVALID_UNITS_CODE = 18  # RC_BAD_UNITS
    DEVICE_VAR_INDEX_NOT_ALLOWED = 19  # RC_INDEX_DISALLOWED
    INVALID_EXTENDED_CMD_NUMBER = 20  # RC_BAD_EXT_CMD
    INVALID_ANALOG_CHANNEL_NUMBER = 21
    # 22-27: reserved / command-specific
    INVALID_RANGE_VALUE = 28
    INVALID_DAMPING_VALUE = 29
    RESPONSE_TRUNCATED = 30  # RC_TRUNCATED (Warning: Response Truncated)
    INVALID_DEVICE_VAR_CLASSIFICATION = 31
    DEVICE_BUSY = 32  # RC_BUSY
    DR_INITIATED = 33  # RC_DR_INIT (Delayed Response Initiated)
    DR_RUNNING = 34  # RC_DR_RUNNING (Delayed Response Running)
    DR_DEAD = 35  # RC_DR_DEAD (Delayed Response Dead)
    DR_CONFLICT = 36  # RC_DR_CONFL (Delayed Response Conflict)
    CMD_NOT_IMPLEMENTED = 64  # RC_NOT_IMPLEM


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


class HARTCommErrorFlags(IntFlag):
    """Communication error summary flags.

    When the MSB (bit 7) of the response code byte is set to 1, the lower 7 bits
    represent communication error flags rather than a command response code.

    Reference: Go hart library communicationsErrorSummaryFlags.go
    """

    NONE = 0x00
    UNDEFINED = 0x01
    BUFFER_OVERFLOW = 0x02
    # Bit 2 (0x04) is reserved
    LONGITUDINAL_PARITY = 0x08
    FRAMING_ERROR = 0x10
    OVERRUN_ERROR = 0x20
    VERTICAL_PARITY = 0x40
    # Bit 7 (0x80) is the comm-error indicator bit itself


# HART-IP default ports (TP10300 specifies port 5094 for both UDP and TCP)
HARTIP_UDP_PORT = 5094
HARTIP_TCP_PORT = 5094

# HART-IP header size (bytes)
HARTIP_HEADER_SIZE = 8

# Communication error: bit 7 set in response code byte means comm error summary
COMM_ERROR_MASK = 0x80

# Extended command threshold: commands > 253 use Command 31 wrapper
MAX_SINGLE_BYTE_CMD = 253
CMD_EXTENDED_CMD = 31

# Delayed-response retry defaults (from FieldComm C# reference)
DR_RETRY_DELAY_MS = 20
DR_MAX_RETRIES = 100

# Delayed-response response codes that trigger retry.
# Matches C# FieldComm: RSP_DEVICE_BUSY(32), RSP_DR_INITIATE(33),
# RSP_DR_RUNNING(34), RSP_DR_CONFLICT(36).
DR_RETRY_CODES = frozenset({32, 33, 34, 36})

# ---------------------------------------------------------------------------
# HART-IP v2 security constants (TP10300 rev 2020 / hipserver reference)
# ---------------------------------------------------------------------------

# v2 cipher suites (from hipserver hsconnectionmanager.h)
HARTIP_V2_PSK_CIPHERS = "PSK-AES128-GCM-SHA256:PSK-AES128-CBC-SHA256:PSK-AES128-CCM"
HARTIP_V2_SRP_CIPHERS = "SRP-AES-128-CBC-SHA"
HARTIP_V2_ALL_CIPHERS = (
    "PSK-AES128-GCM-SHA256:PSK-AES128-CBC-SHA256:PSK-AES128-CCM:SRP-AES-128-CBC-SHA"
)

# Minimum TLS/DTLS version required by HART-IP v2
HARTIP_V2_MIN_TLS_VERSION = "TLSv1.2"
HARTIP_V2_MIN_DTLS_VERSION = "DTLSv1.2"

# Direct PDU (msg_id=4) header overhead: device_status(1) + extended_status(1)
DIRECT_PDU_HEADER_SIZE = 2

# Direct PDU per-command overhead: command_number(2) + byte_count(1)
DIRECT_PDU_CMD_HEADER_SIZE = 3

# Read Audit Log (msg_id=5) request size: start_record(1) + number_of_records(1)
AUDIT_LOG_REQUEST_SIZE = 2

# Session log record size per CISAGOV Spicy parser (fixed-length record)
# ipv4(4) + ipv6(16) + client_port(2) + server_port(2) + connect_time(8)
# + disconnect_time(8) + session_status(2) + start_config(2) + end_config(2)
# + num_publish(4) + num_request(4) + num_response(4)
SESSION_LOG_RECORD_SIZE = 58


class HARTIPServerStatus(IntFlag):
    """Server status flags from Read Audit Log response (TP10300 Section 10.3.2.6)."""

    NONE = 0x0000
    UNABLE_TO_LOCATE_SYSLOG_SERVER = 0x0001
    SYSLOG_CONNECTION_FAILED = 0x0002
    INSECURE_SYSLOG_CONNECTION = 0x0004


class HARTIPSessionStatus(IntFlag):
    """Session status summary flags (TP10300 Section 10.3.2.6)."""

    NONE = 0x0000
    WRITES_OCCURRED = 0x0001
    BAD_SESSION_INITIALIZATION = 0x0002
    ABORTED_SESSION = 0x0004
    SESSION_TIMEOUT = 0x0008
    INSECURE_SESSION = 0x0010
