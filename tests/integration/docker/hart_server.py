#!/usr/bin/env python3
"""
HART-IP Mock Server for the hartip integration tests

Supports:
- UDP (port 5094) and TCP (port 5095) transport
- Basic mode: Single device at poll address 0
- Multi-drop mode: Multiple devices at addresses 0-3
- All universal HART commands (0-19, 38, 48)
- Common practice commands (35, 41, 42)

Configuration via environment variables:
- HART_MODE: "basic" or "multidrop" (default: basic)
- HART_UDP_PORT: UDP port (default: 5094)
- HART_TCP_PORT: TCP port (default: 5095)
"""

import asyncio
import logging
import os
import struct
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import IntEnum

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
log = logging.getLogger("HART-Server")


# ============================================================================
# HART Protocol Constants
# ============================================================================


class HARTCommand(IntEnum):
    """HART command numbers"""

    READ_UNIQUE_ID = 0
    READ_PRIMARY_VARIABLE = 1
    READ_CURRENT_AND_PERCENT = 2
    READ_DYNAMIC_VARS = 3
    WRITE_POLL_ADDRESS = 6
    READ_LOOP_CONFIG = 7
    READ_DYNAMIC_VAR_CLASS = 8
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
    READ_LONG_TAG = 20
    SET_PRIMARY_RANGE = 35
    RESET_CONFIG_FLAG = 38
    PERFORM_SELF_TEST = 41
    PERFORM_MASTER_RESET = 42
    READ_ADDITIONAL_STATUS = 48
    # WirelessHART commands
    READ_SUB_DEVICE_IDENTITY = 84
    READ_SUB_DEVICE_COUNT = 85
    READ_NETWORK_ID = 768


class HARTResponseCode(IntEnum):
    """HART response codes"""

    SUCCESS = 0
    UNDEFINED_COMMAND = 1
    INVALID_SELECTION = 2
    PARAMETER_TOO_LARGE = 3
    PARAMETER_TOO_SMALL = 4
    TOO_FEW_DATA_BYTES = 5
    TRANSMITTER_SPECIFIC = 6
    IN_WRITE_PROTECT_MODE = 7
    CMD_NOT_IMPLEMENTED = 32


class HARTFrameType(IntEnum):
    """HART frame delimiter types"""

    SHORT_FRAME = 0x02
    LONG_FRAME = 0x82


class HARTIPMessageType(IntEnum):
    """HART-IP message types"""

    REQUEST = 0
    RESPONSE = 1
    PUBLISH = 2
    NAK = 15


# HART Units codes
HART_UNITS = {
    "psi": 6,
    "bar": 7,
    "mbar": 8,
    "kPa": 12,
    "degC": 32,
    "degF": 33,
    "mA": 39,
    "percent": 57,
    "gal_min": 61,
    "m3_hr": 63,
    "m": 45,
}


# ============================================================================
# Device Simulation
# ============================================================================


@dataclass
class HARTDevice:
    """Simulated HART device"""

    poll_address: int = 0
    manufacturer_id: int = 0x26  # Rosemount/Emerson (official FieldComm Group ID)
    device_type: int = 42
    protocol_revision: int = 7  # HART protocol version (5, 6, or 7)
    device_revision: int = 7
    software_revision: int = 5
    hardware_revision: int = 2
    physical_signaling: int = 0  # 0=Bell 202, 2=FSK, 4=WirelessHART
    unique_id: bytes = field(default_factory=lambda: bytes([0x12, 0x34, 0x56]))
    tag: str = "PT-101"
    long_tag: str = ""  # 32-char tag for WirelessHART
    descriptor: str = "Pressure Sensor"
    message: str = "HART Mock Device"
    date: Tuple[int, int, int] = (15, 12, 24)  # day, month, year
    final_assembly: int = 123456

    # Process variables
    pv_value: float = 25.5
    pv_units: int = 6  # psi
    sv_value: float = 23.2
    sv_units: int = 32  # degC
    tv_value: float = 50.0
    tv_units: int = 57  # percent
    qv_value: float = 12.5
    qv_units: int = 39  # mA

    # Loop current
    loop_current: float = 12.5  # mA
    percent_range: float = 50.0

    # Output configuration
    alarm_selection: int = 0
    transfer_function: int = 0
    upper_range: float = 100.0
    lower_range: float = 0.0
    damping: float = 1.0

    # State
    write_protect: bool = False
    config_changed: bool = False

    # WirelessHART gateway mode
    is_gateway: bool = False
    network_id: int = 0x1234
    sub_devices: List[Dict[str, Any]] = field(default_factory=list)

    def simulate_values(self):
        """Add some variation to process values"""
        self.pv_value += random.uniform(-0.5, 0.5)
        self.sv_value += random.uniform(-0.2, 0.2)
        self.loop_current = 4.0 + (self.pv_value / self.upper_range) * 16.0
        self.percent_range = (
            (self.pv_value - self.lower_range) / (self.upper_range - self.lower_range) * 100
        )


# WirelessHART Gateway with simulated sub-devices
GATEWAY_DEVICE = HARTDevice(
    poll_address=0,
    manufacturer_id=0x26,  # Rosemount/Emerson
    device_type=90,  # Gateway device type
    protocol_revision=7,
    physical_signaling=4,  # WirelessHART (2.4 GHz)
    unique_id=bytes([0xAB, 0xCD, 0xEF]),
    tag="GW-001",
    long_tag="WIRELESSHART-GATEWAY-001",
    descriptor="WirelessHART Gateway",
    is_gateway=True,
    network_id=0x1A2B,
    sub_devices=[
        {
            "manufacturer_id": 0x26,
            "device_type": 42,
            "device_id": "112233",
            "tag": "PT-101",
            "long_tag": "PRESSURE-SENSOR-FIELD-1",
        },
        {
            "manufacturer_id": 0x17,
            "device_type": 51,
            "device_id": "445566",
            "tag": "TT-201",
            "long_tag": "TEMPERATURE-XMTR-FIELD-2",
        },
        {
            "manufacturer_id": 0x37,
            "device_type": 62,
            "device_id": "778899",
            "tag": "FT-301",
            "long_tag": "FLOW-METER-FIELD-3",
        },
    ],
)

# Predefined devices for multi-drop mode (using official FieldComm Group manufacturer IDs)
MULTIDROP_DEVICES = [
    HARTDevice(
        poll_address=0,
        manufacturer_id=0x26,  # Rosemount/Emerson (FCG ID)
        device_type=42,
        unique_id=bytes([0x12, 0x34, 0x56]),
        tag="PT-101",
        descriptor="Pressure Sensor",
        pv_value=25.5,
        pv_units=HART_UNITS["psi"],
        sv_value=23.2,
        sv_units=HART_UNITS["degC"],
    ),
    HARTDevice(
        poll_address=1,
        manufacturer_id=0x17,  # Honeywell (FCG ID)
        device_type=51,
        unique_id=bytes([0x23, 0x45, 0x67]),
        tag="TT-201",
        descriptor="Temperature Xmtr",
        pv_value=85.3,
        pv_units=HART_UNITS["degC"],
        sv_value=101.3,
        sv_units=HART_UNITS["kPa"],
    ),
    HARTDevice(
        poll_address=2,
        manufacturer_id=0x37,  # Yokogawa (FCG ID)
        device_type=62,
        unique_id=bytes([0x34, 0x56, 0x78]),
        tag="FT-301",
        descriptor="Flow Meter",
        pv_value=125.7,
        pv_units=HART_UNITS["gal_min"],
        sv_value=22.5,
        sv_units=HART_UNITS["degC"],
    ),
    HARTDevice(
        poll_address=3,
        manufacturer_id=0x2A,  # Siemens (FCG ID)
        device_type=73,
        unique_id=bytes([0x45, 0x67, 0x89]),
        tag="LT-401",
        descriptor="Level Transmitter",
        pv_value=2.35,
        pv_units=HART_UNITS["m"],
        sv_value=25.0,
        sv_units=HART_UNITS["degC"],
    ),
]


# ============================================================================
# HART-IP Frame Handling
# ============================================================================


HARTIP_HEADER_LEN = 8
# Version(1) MessageType(1) MessageID(1) Status(1) SequenceNumber(2)
# ByteCount(2). ByteCount is the TOTAL message length, header included.
_HEADER_FMT = ">BBBBHH"


@dataclass
class HARTIPHeader:
    """HART-IP header (8 bytes).

    ``payload_len`` is the body length; the wire ByteCount field is
    ``payload_len + 8``. The old ``>BBHBBH`` layout read MessageID and Status
    as one 16-bit id (so Session Close 0x01 parsed as 256 and went
    unanswered), read only the low byte of the 16-bit sequence number, and
    wrote a ByteCount without the header, which tshark flags as malformed.
    """

    version: int = 1
    msg_type: int = 0
    msg_id: int = 0
    status: int = 0
    sequence: int = 0
    payload_len: int = 0

    def pack(self) -> bytes:
        return struct.pack(
            _HEADER_FMT,
            self.version,
            self.msg_type,
            self.msg_id,
            self.status,
            self.sequence,
            HARTIP_HEADER_LEN + self.payload_len,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "HARTIPHeader":
        if len(data) < HARTIP_HEADER_LEN:
            raise ValueError("Header too short")
        v, mt, mid, st, seq, byte_count = struct.unpack(_HEADER_FMT, data[:HARTIP_HEADER_LEN])
        return cls(v, mt, mid, st, seq, max(byte_count - HARTIP_HEADER_LEN, 0))


def xor_checksum(data: bytes) -> int:
    """Calculate XOR checksum"""
    result = 0
    for b in data:
        result ^= b
    return result


def pack_ascii(text: str, length: int = 8) -> bytes:
    """Pack ASCII string using HART 6-bit encoding"""
    text = text.upper().ljust(length)[:length]
    result = bytearray()

    for i in range(0, len(text), 4):
        chars = text[i : i + 4].ljust(4)
        c = []
        for ch in chars:
            v = ord(ch)
            if 64 <= v <= 95:
                c.append(v - 64)
            elif 32 <= v <= 63:
                c.append(v)
            else:
                c.append(32)

        b0 = (c[0] << 2) | (c[1] >> 4)
        b1 = ((c[1] & 0x0F) << 4) | (c[2] >> 2)
        b2 = ((c[2] & 0x03) << 6) | c[3]
        result.extend([b0, b1, b2])

    return bytes(result)


def parse_pdu(data: bytes) -> Tuple[int, int, int, bytes]:
    """Parse HART PDU, return (delimiter, address, command, data)"""
    if len(data) < 4:
        raise ValueError("PDU too short")

    delimiter = data[0]

    # Determine address length
    if delimiter & 0x80:  # Long frame
        addr_len = 5
    else:  # Short frame
        addr_len = 1

    if len(data) < 3 + addr_len:
        raise ValueError("PDU too short for frame type")

    address = data[1] if addr_len == 1 else data[1:6]
    command = data[1 + addr_len]
    byte_count = data[2 + addr_len]

    data_start = 3 + addr_len
    cmd_data = data[data_start : data_start + byte_count]

    return delimiter, address if addr_len == 1 else address[0], command, cmd_data


def build_response_pdu(
    delimiter: int, address: int, command: int, response_code: int, device_status: int, data: bytes
) -> bytes:
    """Build HART response PDU"""
    if delimiter & 0x80:  # Long frame
        addr_bytes = bytes([address]) + bytes(4)  # Simplified
    else:
        addr_bytes = bytes([address & 0x0F])

    # Response data includes response code and device status
    response_data = bytes([response_code, device_status]) + data
    byte_count = len(response_data)

    pdu = bytes([delimiter]) + addr_bytes + bytes([command, byte_count]) + response_data
    checksum = xor_checksum(pdu)
    return pdu + bytes([checksum])


# ============================================================================
# Command Handlers
# ============================================================================


class HARTCommandHandler:
    """Handle HART commands for simulated devices"""

    def __init__(self, devices: Dict[int, HARTDevice]):
        self.devices = devices

    def get_device(self, address: int) -> Optional[HARTDevice]:
        """Get device by poll address"""
        return self.devices.get(address & 0x0F)

    def handle_command(self, address: int, command: int, data: bytes) -> Tuple[int, int, bytes]:
        """
        Handle HART command, return (response_code, device_status, response_data)
        """
        device = self.get_device(address)
        if not device:
            return HARTResponseCode.UNDEFINED_COMMAND, 0, b""

        # Simulate value changes
        device.simulate_values()

        handlers = {
            HARTCommand.READ_UNIQUE_ID: self._cmd_0_read_unique_id,
            HARTCommand.READ_PRIMARY_VARIABLE: self._cmd_1_read_pv,
            HARTCommand.READ_CURRENT_AND_PERCENT: self._cmd_2_read_current,
            HARTCommand.READ_DYNAMIC_VARS: self._cmd_3_read_dynamic_vars,
            HARTCommand.WRITE_POLL_ADDRESS: self._cmd_6_write_poll_addr,
            HARTCommand.READ_TAG_DESCRIPTOR_DATE: self._cmd_13_read_tag,
            HARTCommand.READ_OUTPUT_INFO: self._cmd_15_read_output,
            HARTCommand.WRITE_MESSAGE: self._cmd_17_write_message,
            HARTCommand.WRITE_TAG_DESCRIPTOR_DATE: self._cmd_18_write_tag,
            HARTCommand.RESET_CONFIG_FLAG: self._cmd_38_reset_config,
            HARTCommand.PERFORM_SELF_TEST: self._cmd_41_self_test,
            HARTCommand.PERFORM_MASTER_RESET: self._cmd_42_master_reset,
            HARTCommand.READ_ADDITIONAL_STATUS: self._cmd_48_additional_status,
            # WirelessHART commands
            HARTCommand.READ_LONG_TAG: self._cmd_20_read_long_tag,
            HARTCommand.READ_SUB_DEVICE_IDENTITY: self._cmd_84_read_sub_device_identity,
            HARTCommand.READ_SUB_DEVICE_COUNT: self._cmd_85_read_sub_device_count,
            HARTCommand.READ_NETWORK_ID: self._cmd_768_read_network_id,
        }

        handler = handlers.get(command)
        if handler:
            return handler(device, data)
        else:
            # Unknown command
            return HARTResponseCode.CMD_NOT_IMPLEMENTED, 0, b""

    def _cmd_0_read_unique_id(self, device: HARTDevice, data: bytes) -> Tuple[int, int, bytes]:
        """Command 0: Read Unique Identifier

        Response format (per HART spec):
        [0] Extended device status
        [1] Manufacturer ID
        [2] Device Type
        [3] Number of preambles
        [4] HART Protocol Revision (5, 6, 7, etc.)
        [5] Device Revision
        [6] Software Revision
        [7] Hardware Revision (bits 7-3) + Physical Signaling (bits 2-0)
        [8] Flags (bit 7=write protect, bit 6=config changed)
        [9-11] Device Unique ID (3 bytes)
        """
        # Build flags byte
        flags = 0x00
        if device.write_protect:
            flags |= 0x80  # Write protected
        if device.config_changed:
            flags |= 0x40  # Configuration changed

        response = (
            bytes(
                [
                    0x00,  # Extended device status
                    device.manufacturer_id,
                    device.device_type,
                    0x05,  # Number of preambles required
                    device.protocol_revision,  # HART protocol version from device config
                    device.device_revision,
                    device.software_revision,
                    (device.hardware_revision << 3)
                    | (device.physical_signaling & 0x07),  # HW rev + physical signaling
                    flags,  # Flags
                ]
            )
            + device.unique_id
        )

        return HARTResponseCode.SUCCESS, 0, response

    def _cmd_1_read_pv(self, device: HARTDevice, data: bytes) -> Tuple[int, int, bytes]:
        """Command 1: Read Primary Variable"""
        response = bytes([device.pv_units]) + struct.pack(">f", device.pv_value)
        return HARTResponseCode.SUCCESS, 0, response

    def _cmd_2_read_current(self, device: HARTDevice, data: bytes) -> Tuple[int, int, bytes]:
        """Command 2: Read Loop Current and Percent of Range"""
        response = struct.pack(">f", device.loop_current)
        response += struct.pack(">f", device.percent_range)
        return HARTResponseCode.SUCCESS, 0, response

    def _cmd_3_read_dynamic_vars(self, device: HARTDevice, data: bytes) -> Tuple[int, int, bytes]:
        """Command 3: Read Dynamic Variables and Loop Current"""
        response = struct.pack(">f", device.loop_current)  # Current

        # PV
        response += bytes([device.pv_units])
        response += struct.pack(">f", device.pv_value)

        # SV
        response += bytes([device.sv_units])
        response += struct.pack(">f", device.sv_value)

        # TV
        response += bytes([device.tv_units])
        response += struct.pack(">f", device.tv_value)

        # QV
        response += bytes([device.qv_units])
        response += struct.pack(">f", device.qv_value)

        return HARTResponseCode.SUCCESS, 0, response

    def _cmd_6_write_poll_addr(self, device: HARTDevice, data: bytes) -> Tuple[int, int, bytes]:
        """Command 6: Write Polling Address"""
        if device.write_protect:
            return HARTResponseCode.IN_WRITE_PROTECT_MODE, 0, b""

        if len(data) < 1:
            return HARTResponseCode.TOO_FEW_DATA_BYTES, 0, b""

        new_addr = data[0] & 0x0F
        device.poll_address = new_addr
        device.config_changed = True

        return HARTResponseCode.SUCCESS, 0, bytes([new_addr])

    def _cmd_13_read_tag(self, device: HARTDevice, data: bytes) -> Tuple[int, int, bytes]:
        """Command 13: Read Tag, Descriptor, Date"""
        tag_packed = pack_ascii(device.tag, 8)[:6]
        desc_packed = pack_ascii(device.descriptor, 16)[:12]
        date_bytes = bytes(device.date)

        response = tag_packed + desc_packed + date_bytes
        return HARTResponseCode.SUCCESS, 0, response

    def _cmd_15_read_output(self, device: HARTDevice, data: bytes) -> Tuple[int, int, bytes]:
        """Command 15: Read Output Information (18 bytes per HART spec)"""
        response = bytes(
            [
                device.alarm_selection,
                device.transfer_function,
                device.pv_units,
            ]
        )
        response += struct.pack(">f", device.upper_range)
        response += struct.pack(">f", device.lower_range)
        response += struct.pack(">f", device.damping)
        response += bytes(
            [
                0x01 if device.write_protect else 0x00,  # write_protect_code
                250,  # reserved (250 = Not Used)
                0x00,  # analog_channel_flags
            ]
        )

        return HARTResponseCode.SUCCESS, 0, response

    def _cmd_17_write_message(self, device: HARTDevice, data: bytes) -> Tuple[int, int, bytes]:
        """Command 17: Write Message"""
        if device.write_protect:
            return HARTResponseCode.IN_WRITE_PROTECT_MODE, 0, b""

        # Message is 24 chars packed in 18 bytes
        device.config_changed = True
        return HARTResponseCode.SUCCESS, 0, b""

    def _cmd_18_write_tag(self, device: HARTDevice, data: bytes) -> Tuple[int, int, bytes]:
        """Command 18: Write Tag, Descriptor, Date"""
        if device.write_protect:
            return HARTResponseCode.IN_WRITE_PROTECT_MODE, 0, b""

        device.config_changed = True
        return HARTResponseCode.SUCCESS, 0, b""

    def _cmd_38_reset_config(self, device: HARTDevice, data: bytes) -> Tuple[int, int, bytes]:
        """Command 38: Reset Configuration Changed Flag"""
        device.config_changed = False
        return HARTResponseCode.SUCCESS, 0, b""

    def _cmd_41_self_test(self, device: HARTDevice, data: bytes) -> Tuple[int, int, bytes]:
        """Command 41: Perform Self-Test"""
        return HARTResponseCode.SUCCESS, 0, b""

    def _cmd_42_master_reset(self, device: HARTDevice, data: bytes) -> Tuple[int, int, bytes]:
        """Command 42: Perform Master Reset"""
        if device.write_protect:
            return HARTResponseCode.IN_WRITE_PROTECT_MODE, 0, b""

        # Reset to defaults
        device.config_changed = False
        return HARTResponseCode.SUCCESS, 0, b""

    def _cmd_48_additional_status(self, device: HARTDevice, data: bytes) -> Tuple[int, int, bytes]:
        """Command 48: Read Additional Device Status"""
        # Extended device status bytes
        response = bytes([0x00] * 9)  # All OK
        return HARTResponseCode.SUCCESS, 0, response

    def _cmd_20_read_long_tag(self, device: HARTDevice, data: bytes) -> Tuple[int, int, bytes]:
        """Command 20: Read Long Tag (32 characters, WirelessHART)"""
        # Long tag is 32 chars packed as 24 bytes
        long_tag = device.long_tag or device.tag.ljust(32)
        response = pack_ascii(long_tag, 32)[:24]
        return HARTResponseCode.SUCCESS, 0, response

    def _cmd_84_read_sub_device_identity(
        self, device: HARTDevice, data: bytes
    ) -> Tuple[int, int, bytes]:
        """Command 84: Read Sub-Device Identity (WirelessHART gateway)"""
        if not device.is_gateway or not device.sub_devices:
            return HARTResponseCode.CMD_NOT_IMPLEMENTED, 0, b""

        if len(data) < 2:
            return HARTResponseCode.TOO_FEW_DATA_BYTES, 0, b""

        sub_device_index = struct.unpack(">H", data[:2])[0]

        if sub_device_index >= len(device.sub_devices):
            return HARTResponseCode.INVALID_SELECTION, 0, b""

        sub = device.sub_devices[sub_device_index]

        # Build response: mfr_id(1), dev_type(1), dev_id(3), ucmd_rev(1), long_tag(24)
        response = bytes(
            [
                sub.get("manufacturer_id", 0x26),
                sub.get("device_type", 42),
            ]
        )
        response += bytes.fromhex(sub.get("device_id", "123456"))[:3]
        response += bytes([7])  # Universal command revision
        response += pack_ascii(sub.get("long_tag", sub.get("tag", "")), 32)[:24]

        return HARTResponseCode.SUCCESS, 0, response

    def _cmd_85_read_sub_device_count(
        self, device: HARTDevice, data: bytes
    ) -> Tuple[int, int, bytes]:
        """Command 85: Read Sub-Device Count (WirelessHART gateway)"""
        if not device.is_gateway:
            return HARTResponseCode.CMD_NOT_IMPLEMENTED, 0, b""

        count = len(device.sub_devices)
        response = struct.pack(">H", count)
        return HARTResponseCode.SUCCESS, 0, response

    def _cmd_768_read_network_id(self, device: HARTDevice, data: bytes) -> Tuple[int, int, bytes]:
        """Command 768: Read Network ID (WirelessHART)"""
        if device.physical_signaling != 4:  # Not WirelessHART
            return HARTResponseCode.CMD_NOT_IMPLEMENTED, 0, b""

        response = struct.pack(">H", device.network_id)
        return HARTResponseCode.SUCCESS, 0, response


# ============================================================================
# HART-IP Server
# ============================================================================


class HARTIPServer:
    """HART-IP mock server supporting UDP and TCP"""

    def __init__(self, mode: str = "basic", udp_port: int = 5094, tcp_port: int = 5095):
        self.mode = mode
        self.udp_port = udp_port
        self.tcp_port = tcp_port

        # Initialize devices based on mode
        if mode == "gateway":
            self.devices = {0: GATEWAY_DEVICE}
        elif mode == "multidrop":
            self.devices = {d.poll_address: d for d in MULTIDROP_DEVICES}
        else:
            # Basic mode: single device at address 0
            self.devices = {0: HARTDevice()}

        self.handler = HARTCommandHandler(self.devices)
        self.msg_id = 0
        self.sequence = 0

    def _next_msg_id(self) -> int:
        self.msg_id = (self.msg_id + 1) & 0xFFFF
        return self.msg_id

    def _next_sequence(self) -> int:
        self.sequence = (self.sequence + 1) & 0xFFFF
        return self.sequence

    def process_request(self, data: bytes) -> bytes:
        """Process HART-IP request and return response"""
        try:
            if len(data) < 8:
                log.warning(f"Request too short: {len(data)} bytes")
                return b""

            # Parse header
            header = HARTIPHeader.unpack(data[:8])
            log.debug(
                f"Request: type={header.msg_type}, id={header.msg_id}, len={header.payload_len}"
            )

            # Handle session management messages (msg_id 0 = Session Init, 1 = Session Close)
            if header.msg_id == 0:
                # Reject HART-IP v2 Session Initiate (this is a v1-only server)
                if header.version >= 2:
                    log.info("HART-IP v2 Session Initiate rejected (v1-only server)")
                    resp_header = HARTIPHeader(
                        version=1,
                        msg_type=HARTIPMessageType.RESPONSE,
                        msg_id=0,
                        status=15,  # NAK / error
                        sequence=header.sequence,
                        payload_len=0,
                    )
                    return resp_header.pack()

                # Session Initiate - respond with success
                log.info("Session Initiate request received")
                resp_header = HARTIPHeader(
                    version=1,
                    msg_type=HARTIPMessageType.RESPONSE,
                    msg_id=0,
                    status=0,  # SUCCESS
                    sequence=header.sequence,
                    payload_len=5,  # master_type(1) + inactivity_timer(4)
                )
                # Echo back the payload (master_type + inactivity_timer)
                payload = data[8 : 8 + header.payload_len]
                if len(payload) < 5:
                    payload = b"\x01\x00\x00\x75\x30"  # master=1, timer=30000ms
                return resp_header.pack() + payload[:5]

            if header.msg_id == 1:
                # Session Close - respond with success
                log.info("Session Close request received")
                resp_header = HARTIPHeader(
                    version=1,
                    msg_type=HARTIPMessageType.RESPONSE,
                    msg_id=1,
                    status=0,
                    sequence=header.sequence,
                    payload_len=0,
                )
                return resp_header.pack()

            if header.msg_id == 2:
                # Keep Alive - respond with success
                log.debug("Keep Alive received")
                resp_header = HARTIPHeader(
                    version=1,
                    msg_type=HARTIPMessageType.RESPONSE,
                    msg_id=2,
                    status=0,
                    sequence=header.sequence,
                    payload_len=0,
                )
                return resp_header.pack()

            # msg_id == 3: Pass-through (normal HART command)
            # Parse PDU
            pdu_data = data[8 : 8 + header.payload_len]
            delimiter, address, command, cmd_data = parse_pdu(pdu_data)

            log.info(f"Command {command} from address {address}")

            # Handle command
            response_code, device_status, response_data = self.handler.handle_command(
                address, command, cmd_data
            )

            # Build response PDU
            response_pdu = build_response_pdu(
                delimiter, address, command, response_code, device_status, response_data
            )

            # Build response header
            resp_header = HARTIPHeader(
                version=1,
                msg_type=HARTIPMessageType.RESPONSE,
                msg_id=header.msg_id,
                status=0,
                sequence=header.sequence,
                payload_len=len(response_pdu),
            )

            return resp_header.pack() + response_pdu

        except Exception as e:
            log.error(f"Error processing request: {e}")
            return b""


class UDPServerProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler"""

    def __init__(self, server: HARTIPServer):
        self.server = server
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        log.debug(f"UDP request from {addr}: {data.hex()}")
        response = self.server.process_request(data)
        if response:
            self.transport.sendto(response, addr)
            log.debug(f"UDP response to {addr}: {response.hex()}")


class TCPServerProtocol(asyncio.Protocol):
    """TCP protocol handler"""

    def __init__(self, server: HARTIPServer):
        self.server = server
        self.transport = None
        self.buffer = b""

    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info("peername")
        log.info(f"TCP connection from {peername}")

    def data_received(self, data: bytes):
        self.buffer += data

        # Process complete messages (header says length)
        while len(self.buffer) >= 8:
            header = HARTIPHeader.unpack(self.buffer[:8])
            total_len = 8 + header.payload_len

            if len(self.buffer) < total_len:
                break

            request = self.buffer[:total_len]
            self.buffer = self.buffer[total_len:]

            log.debug(f"TCP request: {request.hex()}")
            response = self.server.process_request(request)
            if response:
                self.transport.write(response)
                log.debug(f"TCP response: {response.hex()}")

    def connection_lost(self, exc):
        log.info("TCP connection closed")


async def main():
    """Start HART-IP mock server"""
    mode = os.environ.get("HART_MODE", "basic")
    udp_port = int(os.environ.get("HART_UDP_PORT", "5094"))
    tcp_port = int(os.environ.get("HART_TCP_PORT", "5095"))
    protocol_version = int(os.environ.get("HART_PROTOCOL_VERSION", "7"))

    log.info("Starting HART-IP Mock Server")
    log.info(f"  Mode: {mode}")
    log.info(f"  Protocol Version: HART {protocol_version}")
    log.info(f"  UDP Port: {udp_port}")
    log.info(f"  TCP Port: {tcp_port}")

    server = HARTIPServer(mode=mode, udp_port=udp_port, tcp_port=tcp_port)

    # Override protocol version for all devices
    for device in server.devices.values():
        device.protocol_revision = protocol_version
        # HART 5 devices don't have device lock
        if protocol_version <= 5:
            device.write_protect = False

    # Show configured devices
    for addr, device in server.devices.items():
        if device.is_gateway:
            log.info(
                f"  Device {addr}: {device.tag} (WirelessHART Gateway, {len(device.sub_devices)} sub-devices)"
            )
            for i, sub in enumerate(device.sub_devices):
                log.info(f"    Sub-device {i}: {sub.get('tag', 'Unknown')}")
        else:
            log.info(
                f"  Device {addr}: {device.tag} (HART {device.protocol_revision}, Type {device.device_type})"
            )

    loop = asyncio.get_event_loop()

    # Start UDP server
    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: UDPServerProtocol(server), local_addr=("0.0.0.0", udp_port)
    )
    log.info(f"UDP server listening on port {udp_port}")

    # Start TCP server
    tcp_server = await loop.create_server(lambda: TCPServerProtocol(server), "0.0.0.0", tcp_port)
    log.info(f"TCP server listening on port {tcp_port}")

    log.info("Server ready - waiting for connections...")

    try:
        await asyncio.gather(
            asyncio.sleep(float("inf")),  # Keep UDP running
            tcp_server.serve_forever(),
        )
    finally:
        udp_transport.close()
        tcp_server.close()


if __name__ == "__main__":
    asyncio.run(main())
