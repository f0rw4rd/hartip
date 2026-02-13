"""
HART-IP protocol library for Python.

A pure-Python implementation of the HART-IP transport (TP10300 / HCF_SPEC-085)
and HART application layer, using the ``construct`` library for binary parsing.

Quickstart::

    from hartip import HARTIPClient, parse_cmd0

    with HARTIPClient("192.168.1.100") as client:
        resp = client.read_unique_id()
        info = parse_cmd0(resp.payload)
        print(info.manufacturer_name, info.device_id)
"""

from .ascii import pack_ascii, unpack_ascii
from .client import HARTIPClient, HARTIPResponse
from .constants import (
    COMM_ERROR_MASK,
    DEFAULT_INACTIVITY_TIMER,
    HARTIP_HEADER_SIZE,
    HARTIP_TCP_PORT,
    HARTIP_UDP_PORT,
    MASTER_TYPE_PRIMARY,
    MASTER_TYPE_SECONDARY,
    HARTCommand,
    HARTCommErrorFlags,
    HARTDeviceStatus,
    HARTFrameType,
    HARTIPMessageID,
    HARTIPMessageType,
    HARTIPStatus,
    HARTIPVersion,
    HARTResponseCode,
)
from .device import (
    DeviceInfo,
    DeviceVariable,
    Variable,
    decode_comm_error_flags,
    is_comm_error,
    parse_cmd0,
    parse_cmd1,
    parse_cmd2,
    parse_cmd3,
    parse_cmd9,
    parse_cmd12,
    parse_cmd13,
    parse_cmd14,
    parse_cmd15,
    parse_cmd20,
    parse_cmd48,
)
from .exceptions import (
    HARTChecksumError,
    HARTCommunicationError,
    HARTError,
    HARTIPConnectionError,
    HARTIPError,
    HARTIPStatusError,
    HARTIPTimeoutError,
    HARTProtocolError,
    HARTResponseError,
)
from .protocol import (
    HARTIPHeader,
    HARTPdu,
    build_keep_alive,
    build_pdu,
    build_request,
    build_session_close,
    build_session_init,
    parse_pdu,
    parse_response,
    xor_checksum,
)
from .units import UNITS, get_unit_name
from .vendors import MANUFACTURERS, get_vendor_name

__version__ = "0.1.0"

__all__ = [
    # Client
    "HARTIPClient",
    "HARTIPResponse",
    # Protocol structs
    "HARTIPHeader",
    "HARTPdu",
    "build_keep_alive",
    "build_pdu",
    "build_request",
    "build_session_close",
    "build_session_init",
    "parse_pdu",
    "parse_response",
    "xor_checksum",
    # Constants / enums
    "HARTIPVersion",
    "HARTIPMessageID",
    "HARTIPMessageType",
    "HARTIPStatus",
    "HARTFrameType",
    "HARTCommand",
    "HARTResponseCode",
    "HARTDeviceStatus",
    "HARTCommErrorFlags",
    "COMM_ERROR_MASK",
    "HARTIP_HEADER_SIZE",
    "HARTIP_UDP_PORT",
    "HARTIP_TCP_PORT",
    "MASTER_TYPE_PRIMARY",
    "MASTER_TYPE_SECONDARY",
    "DEFAULT_INACTIVITY_TIMER",
    # Device / parsing
    "DeviceInfo",
    "DeviceVariable",
    "Variable",
    "is_comm_error",
    "decode_comm_error_flags",
    "parse_cmd0",
    "parse_cmd1",
    "parse_cmd2",
    "parse_cmd3",
    "parse_cmd9",
    "parse_cmd12",
    "parse_cmd13",
    "parse_cmd14",
    "parse_cmd15",
    "parse_cmd20",
    "parse_cmd48",
    # ASCII
    "pack_ascii",
    "unpack_ascii",
    # Lookup tables
    "MANUFACTURERS",
    "UNITS",
    "get_vendor_name",
    "get_unit_name",
    # Exceptions
    "HARTError",
    "HARTIPError",
    "HARTIPTimeoutError",
    "HARTIPConnectionError",
    "HARTIPStatusError",
    "HARTProtocolError",
    "HARTChecksumError",
    "HARTCommunicationError",
    "HARTResponseError",
]
