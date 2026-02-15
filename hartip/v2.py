"""
HART-IP v2 protocol extensions.

Adds Direct PDU (msg_id=4) and Read Audit Log (msg_id=5) support,
as specified by TP10300 rev 2020.

Reference implementations:
- FieldCommGroup/hipserver hscommands.cpp (DMCommands class)
- CISAGOV icsnpp-hart-ip hart_ip.spicy (DirectPDU, ReadAuditLog types)
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from construct import Int16ub, Int32ub, Int64ub

from .constants import (
    DIRECT_PDU_CMD_HEADER_SIZE,
    DIRECT_PDU_HEADER_SIZE,
    HARTIP_HEADER_SIZE,
    SESSION_LOG_RECORD_SIZE,
    HARTIPMessageID,
    HARTIPMessageType,
    HARTIPServerStatus,
    HARTIPSessionStatus,
    HARTIPVersion,
)
from .protocol import HARTIPHeader

# ---------------------------------------------------------------------------
# Direct PDU (msg_id=4) -- TP10300 Section 10.3.2.5
# ---------------------------------------------------------------------------
#
# Native HART-IP framing without the serial token-passing wrapper.
# Used by WirelessHART gateways and modern HART-IP v2 devices.
#
# Request payload:
#   device_status     (1 byte) -- typically 0x00 for requests
#   extended_status   (1 byte) -- typically 0x00 for requests
#   command_list:
#     command_number  (2 bytes, big-endian)
#     byte_count      (1 byte) -- length of data that follows
#     data            (byte_count bytes) -- command request data
#     ... (repeat for each command)
#
# Response payload:
#   device_status     (1 byte)
#   extended_status   (1 byte)
#   command_list:
#     command_number  (2 bytes, big-endian)
#     byte_count      (1 byte) -- length of data that follows
#     response_code   (1 byte) -- within byte_count
#     data            (byte_count - 1 bytes) -- command response data
#     ... (repeat for each command)
# ---------------------------------------------------------------------------


@dataclass
class DirectPDUCommand:
    """A single command within a Direct PDU frame.

    For requests, ``response_code`` is ``None`` and ``data`` contains the
    request payload.  For responses, ``response_code`` is the first byte
    of the command data and ``data`` contains the remaining bytes.
    """

    command_number: int
    data: bytes = b""
    response_code: Optional[int] = None

    @property
    def is_response(self) -> bool:
        return self.response_code is not None

    def encode_request(self) -> bytes:
        """Encode as a Direct PDU request command entry."""
        if len(self.data) > 255:
            raise ValueError(
                f"Direct PDU command {self.command_number}: "
                f"data length {len(self.data)} exceeds 255"
            )
        return Int16ub.build(self.command_number) + bytes([len(self.data)]) + self.data

    def encode_response(self) -> bytes:
        """Encode as a Direct PDU response command entry."""
        rc = self.response_code if self.response_code is not None else 0
        payload = bytes([rc]) + self.data
        if len(payload) > 255:
            raise ValueError(
                f"Direct PDU command {self.command_number}: "
                f"response payload length {len(payload)} exceeds 255"
            )
        return Int16ub.build(self.command_number) + bytes([len(payload)]) + payload


@dataclass
class DirectPDU:
    """A complete Direct PDU (msg_id=4) body.

    Contains device/extended status and a list of commands.
    Supports iteration and indexing over commands::

        for cmd in result:
            print(cmd.command_number, cmd.response_code)

        first = result[0]
        print(len(result))
    """

    device_status: int = 0
    extended_status: int = 0
    commands: list[DirectPDUCommand] = field(default_factory=list)

    def __iter__(self) -> Iterator[DirectPDUCommand]:
        return iter(self.commands)

    def __len__(self) -> int:
        return len(self.commands)

    def __getitem__(self, index: int) -> DirectPDUCommand:
        return self.commands[index]


def build_direct_pdu_request(
    sequence: int,
    commands: Sequence[DirectPDUCommand],
    *,
    device_status: int = 0,
    extended_status: int = 0,
    version: int = HARTIPVersion.V2,
) -> bytes:
    """Build a HART-IP Direct PDU request (msg_id=4).

    Args:
        sequence: Sequence number (0-65535).
        commands: List of :class:`DirectPDUCommand` to include.
        device_status: Device status byte (usually 0 for requests).
        extended_status: Extended status byte (usually 0 for requests).
        version: HART-IP version (default 2).

    Returns:
        Complete HART-IP message bytes.

    Raises:
        ValueError: If no commands are provided.
    """
    if not commands:
        raise ValueError("Direct PDU requires at least one command")

    payload = bytes([device_status, extended_status])
    for cmd in commands:
        payload += cmd.encode_request()

    total_len = HARTIP_HEADER_SIZE + len(payload)
    header = HARTIPHeader.build(
        {
            "version": version,
            "msg_type": HARTIPMessageType.REQUEST,
            "msg_id": HARTIPMessageID.DIRECT_PDU,
            "status": 0,
            "sequence": sequence & 0xFFFF,
            "byte_count": total_len,
        }
    )
    return header + payload


def parse_direct_pdu_response(data: bytes) -> DirectPDU:
    """Parse a Direct PDU response payload (after the 8-byte HART-IP header).

    Args:
        data: Raw payload bytes (everything after the HART-IP header).

    Returns:
        Parsed :class:`DirectPDU` with response commands.

    Raises:
        ValueError: If the payload is too short or malformed.
    """
    if len(data) < DIRECT_PDU_HEADER_SIZE:
        raise ValueError(
            f"Direct PDU payload too short: {len(data)} bytes, "
            f"need at least {DIRECT_PDU_HEADER_SIZE}"
        )

    device_status = data[0]
    extended_status = data[1]
    commands: List[DirectPDUCommand] = []

    offset = DIRECT_PDU_HEADER_SIZE
    while offset < len(data):
        if offset + DIRECT_PDU_CMD_HEADER_SIZE > len(data):
            raise ValueError(
                f"Direct PDU truncated at offset {offset}: "
                f"need {DIRECT_PDU_CMD_HEADER_SIZE} bytes for command header, "
                f"have {len(data) - offset}"
            )

        command_number = Int16ub.parse(data[offset : offset + 2])
        offset += 2
        byte_count = data[offset]
        offset += 1

        if offset + byte_count > len(data):
            raise ValueError(
                f"Direct PDU command {command_number} truncated: "
                f"byte_count={byte_count} but only {len(data) - offset} bytes remain"
            )

        if byte_count >= 1:
            response_code = data[offset]
            cmd_data = bytes(data[offset + 1 : offset + byte_count])
        else:
            response_code = 0
            cmd_data = b""

        commands.append(
            DirectPDUCommand(
                command_number=command_number,
                data=cmd_data,
                response_code=response_code,
            )
        )
        offset += byte_count

    return DirectPDU(
        device_status=device_status,
        extended_status=extended_status,
        commands=commands,
    )


def parse_direct_pdu_request(data: bytes) -> DirectPDU:
    """Parse a Direct PDU request payload (after the 8-byte HART-IP header).

    In request mode, there is no response_code -- all bytes are command data.

    Args:
        data: Raw payload bytes (everything after the HART-IP header).

    Returns:
        Parsed :class:`DirectPDU` with request commands.
    """
    if len(data) < DIRECT_PDU_HEADER_SIZE:
        raise ValueError(
            f"Direct PDU payload too short: {len(data)} bytes, "
            f"need at least {DIRECT_PDU_HEADER_SIZE}"
        )

    device_status = data[0]
    extended_status = data[1]
    commands: List[DirectPDUCommand] = []

    offset = DIRECT_PDU_HEADER_SIZE
    while offset < len(data):
        if offset + DIRECT_PDU_CMD_HEADER_SIZE > len(data):
            raise ValueError(
                f"Direct PDU truncated at offset {offset}: "
                f"need {DIRECT_PDU_CMD_HEADER_SIZE} bytes for command header, "
                f"have {len(data) - offset}"
            )

        command_number = Int16ub.parse(data[offset : offset + 2])
        offset += 2
        byte_count = data[offset]
        offset += 1

        if offset + byte_count > len(data):
            raise ValueError(
                f"Direct PDU command {command_number} truncated: "
                f"byte_count={byte_count} but only {len(data) - offset} bytes remain"
            )

        cmd_data = bytes(data[offset : offset + byte_count])
        commands.append(
            DirectPDUCommand(
                command_number=command_number,
                data=cmd_data,
                response_code=None,
            )
        )
        offset += byte_count

    return DirectPDU(
        device_status=device_status,
        extended_status=extended_status,
        commands=commands,
    )


# ---------------------------------------------------------------------------
# Read Audit Log (msg_id=5) -- TP10300 Section 10.3.2.6
# ---------------------------------------------------------------------------
#
# Request payload:
#   start_record      (1 byte)
#   number_of_records (1 byte)
#
# Response payload:
#   start_record      (1 byte)
#   number_of_records (1 byte)
#   power_up_time     (8 bytes, uint64 seconds since epoch)
#   last_security_change (8 bytes, uint64 seconds since epoch)
#   server_status     (2 bytes, bitfield)
#   session_record_size (2 bytes)
#   session_log_records (number_of_records * session_record_size bytes)
#
# Session log record (58 bytes per CISAGOV Spicy parser):
#   client_ipv4       (4 bytes)
#   client_ipv6       (16 bytes)
#   client_port       (2 bytes)
#   server_port       (2 bytes)
#   connect_time      (8 bytes, uint64)
#   disconnect_time   (8 bytes, uint64)
#   session_status    (2 bytes, bitfield)
#   start_config_count (2 bytes)
#   end_config_count  (2 bytes)
#   num_publish_pdu   (4 bytes)
#   num_request_pdu   (4 bytes)
#   num_response_pdu  (4 bytes)
# ---------------------------------------------------------------------------


@dataclass
class SessionLogRecord:
    """A single session log entry from Read Audit Log response."""

    client_ipv4: str = "0.0.0.0"
    client_ipv6: str = "::"
    client_port: int = 0
    server_port: int = 0
    connect_time: int = 0  # seconds since epoch
    disconnect_time: int = 0  # seconds since epoch
    session_status: int = 0
    start_config_count: int = 0
    end_config_count: int = 0
    num_publish_pdu: int = 0
    num_request_pdu: int = 0
    num_response_pdu: int = 0

    @property
    def status_flags(self) -> HARTIPSessionStatus:
        """Decode session status as flag enum."""
        return HARTIPSessionStatus(self.session_status & 0x001F)

    @property
    def writes_occurred(self) -> bool:
        return bool(self.session_status & HARTIPSessionStatus.WRITES_OCCURRED)

    @property
    def insecure(self) -> bool:
        return bool(self.session_status & HARTIPSessionStatus.INSECURE_SESSION)


@dataclass
class AuditLogResponse:
    """Parsed Read Audit Log (msg_id=5) response."""

    start_record: int = 0
    number_of_records: int = 0
    power_up_time: int = 0  # seconds since epoch
    last_security_change: int = 0  # seconds since epoch
    server_status: int = 0
    session_record_size: int = SESSION_LOG_RECORD_SIZE
    records: List[SessionLogRecord] = field(default_factory=list)

    @property
    def server_status_flags(self) -> HARTIPServerStatus:
        """Decode server status as flag enum."""
        return HARTIPServerStatus(self.server_status & 0x0007)


def build_audit_log_request(
    sequence: int,
    start_record: int = 0,
    number_of_records: int = 10,
    *,
    version: int = HARTIPVersion.V2,
) -> bytes:
    """Build a HART-IP Read Audit Log request (msg_id=5).

    Args:
        sequence: Sequence number (0-65535).
        start_record: First record index to retrieve.
        number_of_records: Number of records to retrieve.
        version: HART-IP version (default 2).

    Returns:
        Complete HART-IP message bytes.
    """
    if not (0 <= start_record <= 255):
        raise ValueError(f"start_record must be 0-255, got {start_record}")
    if not (0 <= number_of_records <= 255):
        raise ValueError(f"number_of_records must be 0-255, got {number_of_records}")
    payload = bytes([start_record, number_of_records])
    total_len = HARTIP_HEADER_SIZE + len(payload)
    header = HARTIPHeader.build(
        {
            "version": version,
            "msg_type": HARTIPMessageType.REQUEST,
            "msg_id": HARTIPMessageID.READ_AUDIT_LOG,
            "status": 0,
            "sequence": sequence & 0xFFFF,
            "byte_count": total_len,
        }
    )
    return header + payload


def parse_audit_log_response(data: bytes) -> AuditLogResponse:
    """Parse a Read Audit Log response payload (after the 8-byte HART-IP header).

    Args:
        data: Raw payload bytes (everything after the HART-IP header).

    Returns:
        Parsed :class:`AuditLogResponse`.

    Raises:
        ValueError: If the payload is too short or malformed.
    """
    # Minimum response: start_record(1) + number_of_records(1) + power_up_time(8)
    # + last_security_change(8) + server_status(2) + session_record_size(2) = 22
    min_header = 22
    if len(data) < min_header:
        raise ValueError(
            f"Audit log response too short: {len(data)} bytes, need at least {min_header}"
        )

    start_record = data[0]
    number_of_records = data[1]
    power_up_time = Int64ub.parse(data[2:10])
    last_security_change = Int64ub.parse(data[10:18])
    server_status = Int16ub.parse(data[18:20])
    session_record_size = Int16ub.parse(data[20:22])

    records: List[SessionLogRecord] = []
    offset = min_header

    for _ in range(number_of_records):
        if offset + session_record_size > len(data):
            break  # truncated -- parse what we can

        record = _parse_session_log_record(data[offset : offset + session_record_size])
        records.append(record)
        offset += session_record_size

    return AuditLogResponse(
        start_record=start_record,
        number_of_records=number_of_records,
        power_up_time=power_up_time,
        last_security_change=last_security_change,
        server_status=server_status,
        session_record_size=session_record_size,
        records=records,
    )


def _parse_session_log_record(data: bytes) -> SessionLogRecord:
    """Parse a single session log record.

    Layout per CISAGOV hart_ip.spicy SessionLogRecord:
        client_ipv4(4) + client_ipv6(16) + client_port(2) + server_port(2)
        + connect_time(8) + disconnect_time(8) + session_status(2)
        + start_config_count(2) + end_config_count(2) + num_publish(4)
        + num_request(4) + num_response(4) = 58 bytes
    """
    if len(data) < SESSION_LOG_RECORD_SIZE:
        raise ValueError(
            f"Session log record too short: {len(data)} bytes, need {SESSION_LOG_RECORD_SIZE}"
        )

    ipv4_bytes = data[0:4]
    ipv6_bytes = data[4:20]
    client_port = Int16ub.parse(data[20:22])
    server_port = Int16ub.parse(data[22:24])
    connect_time = Int64ub.parse(data[24:32])
    disconnect_time = Int64ub.parse(data[32:40])
    session_status = Int16ub.parse(data[40:42])
    start_config_count = Int16ub.parse(data[42:44])
    end_config_count = Int16ub.parse(data[44:46])
    num_publish = Int32ub.parse(data[46:50])
    num_request = Int32ub.parse(data[50:54])
    num_response = Int32ub.parse(data[54:58])

    return SessionLogRecord(
        client_ipv4=str(ipaddress.IPv4Address(ipv4_bytes)),
        client_ipv6=str(ipaddress.IPv6Address(ipv6_bytes)),
        client_port=client_port,
        server_port=server_port,
        connect_time=connect_time,
        disconnect_time=disconnect_time,
        session_status=session_status,
        start_config_count=start_config_count,
        end_config_count=end_config_count,
        num_publish_pdu=num_publish,
        num_request_pdu=num_request,
        num_response_pdu=num_response,
    )
