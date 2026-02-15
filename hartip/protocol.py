"""
HART-IP protocol structures using the ``construct`` library.

Defines declarative binary parsers/builders for:
- HART-IP transport header (TP10300 / HCF_SPEC-085)
- HART PDU frames (short and long)
- Complete HART-IP messages

All multi-byte integers are big-endian as per the HART specification.
"""

from __future__ import annotations

from dataclasses import dataclass

from construct import (
    Bytes,
    Computed,
    IfThenElse,
    Int8ub,
    Int16ub,
    Int32ub,
    Struct,
    this,
)

from .constants import HARTIP_HEADER_SIZE, HARTIPMessageID, HARTIPMessageType

# ---------------------------------------------------------------------------
# HART-IP transport header  (8 bytes, TP10300)
# ---------------------------------------------------------------------------
#   Offset  Size  Field
#   0       1     version      (always 1 for plaintext)
#   1       1     msg_type     (0=request, 1=response, 2=publish, 15=NAK)
#   2       1     msg_id       (message ID: 0=session init, 3=HART PDU)
#   3       1     status       (0=success, see HARTIPStatus)
#   4       2     sequence     (big-endian sequence number)
#   6       2     byte_count   (total message length including this header)
# ---------------------------------------------------------------------------

HARTIPHeader = Struct(
    "version" / Int8ub,
    "msg_type" / Int8ub,
    "msg_id" / Int8ub,
    "status" / Int8ub,
    "sequence" / Int16ub,
    "byte_count" / Int16ub,
    "payload_len" / Computed(lambda ctx: max(0, ctx.byte_count - HARTIP_HEADER_SIZE)),
)
"""HART-IP header (8 bytes).

``byte_count`` is the total message length (header + payload).
``payload_len`` is a computed field: ``byte_count - 8``.
"""

# ---------------------------------------------------------------------------
# HART PDU frame
# ---------------------------------------------------------------------------
#   delimiter (1B) determines frame type:
#     0x02 = short frame -> 1-byte polling address
#     0x82 = long frame  -> 5-byte unique address
#     0x01 / 0x81 = burst (short / long)
#
#   After the address:
#     [expansion bytes]  (0-3 bytes, count from delimiter bits 5-6)
#     command    (1B)
#     byte_count (1B) - length of data field only
#     data       (byte_count bytes)
#     checksum   (1B) - XOR of all preceding bytes
# ---------------------------------------------------------------------------

HARTPdu = Struct(
    "delimiter" / Int8ub,
    "address"
    / IfThenElse(
        lambda ctx: bool(ctx.delimiter & 0x80),
        Bytes(5),  # long frame
        Bytes(1),  # short frame
    ),
    "command" / Int8ub,
    "byte_count" / Int8ub,
    "data" / Bytes(this.byte_count),
    "checksum" / Int8ub,
)
"""HART PDU frame.

Address length is automatically determined from the delimiter:
- ``0x02`` / ``0x01``: 1-byte short address
- ``0x82`` / ``0x81``: 5-byte long (unique) address

Note: This construct does not handle preambles or expansion bytes.
Use :func:`parse_pdu` for robust parsing that handles both.
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class PduContainer:
    """Parsed HART PDU frame (public replacement for internal construct Container).

    Returned by :func:`parse_pdu` with all frame fields extracted.
    """

    delimiter: int
    address: bytes
    command: int
    byte_count: int
    data: bytes
    checksum: int
    preamble_count: int = 0
    expansion_bytes: bytes = b""

    def __repr__(self) -> str:
        return (
            f"PduContainer(cmd={self.command}, bc={self.byte_count}, "
            f"delimiter=0x{self.delimiter:02X}, cksum=0x{self.checksum:02X})"
        )


def xor_checksum(data: bytes) -> int:
    """Calculate XOR checksum over all bytes."""
    result = 0
    for b in data:
        result ^= b
    return result


def build_pdu(
    delimiter: int,
    address: bytes,
    command: int,
    data: bytes = b"",
) -> bytes:
    """Build a HART PDU frame with computed checksum.

    Args:
        delimiter: Frame type (see :class:`HARTFrameType`).
        address: 1-byte (short) or 5-byte (long) address.
        command: HART command number (0-255).
        data: Command data payload.

    Returns:
        Complete PDU bytes including checksum.

    Raises:
        ValueError: If data length exceeds 255 bytes (byte_count is uint8).
    """
    if len(data) > 255:
        raise ValueError(f"PDU data length {len(data)} exceeds maximum of 255 bytes")
    byte_count = len(data)
    frame_no_cksum = bytes([delimiter]) + address + bytes([command, byte_count]) + data
    checksum = xor_checksum(frame_no_cksum)
    return frame_no_cksum + bytes([checksum])


def parse_pdu(data: bytes) -> object:
    """Parse a HART PDU frame, handling preambles and expansion bytes.

    This function:
    1. Skips any leading 0xFF preamble bytes
    2. Parses the delimiter to determine address length
    3. Extracts expansion bytes (delimiter bits 5-6 encode count)
    4. Parses command, byte_count, data, and checksum

    Args:
        data: Raw PDU bytes, possibly prefixed with preamble bytes.

    Returns:
        A construct Container with fields: delimiter, address, command,
        byte_count, data, checksum, preamble_count, expansion_bytes.

    Raises:
        ValueError: If the data is too short or malformed.
    """
    offset = 0
    length = len(data)

    # 1. Skip preamble bytes (0xFF)
    preamble_count = 0
    while offset < length and data[offset] == 0xFF:
        preamble_count += 1
        offset += 1

    if offset >= length:
        raise ValueError("PDU contains only preamble bytes")

    # 2. Parse delimiter
    delimiter = data[offset]
    offset += 1

    # 3. Parse address (determined by bit 7 of delimiter)
    is_long = bool(delimiter & 0x80)
    addr_len = 5 if is_long else 1
    if offset + addr_len > length:
        raise ValueError(
            f"PDU too short for {'long' if is_long else 'short'} address: "
            f"need {addr_len} bytes at offset {offset}, have {length - offset}"
        )
    address = data[offset : offset + addr_len]
    offset += addr_len

    # 4. Parse expansion bytes (delimiter bits 5-6)
    expansion_count = (delimiter >> 5) & 0x03
    expansion_bytes = b""
    if expansion_count > 0:
        if offset + expansion_count > length:
            raise ValueError(f"PDU too short for {expansion_count} expansion bytes")
        expansion_bytes = data[offset : offset + expansion_count]
        offset += expansion_count

    # 5. Parse command, byte_count, data, checksum
    if offset + 2 > length:
        raise ValueError("PDU too short for command and byte_count fields")

    command = data[offset]
    offset += 1
    byte_count = data[offset]
    offset += 1

    if offset + byte_count > length:
        raise ValueError(f"PDU byte_count={byte_count} but only {length - offset} bytes remain")
    pdu_data = data[offset : offset + byte_count]
    offset += byte_count

    checksum = 0
    if offset < length:
        checksum = data[offset]

    return PduContainer(
        delimiter=delimiter,
        address=address,
        command=command,
        byte_count=byte_count,
        data=pdu_data,
        checksum=checksum,
        preamble_count=preamble_count,
        expansion_bytes=expansion_bytes,
    )


def build_session_init(
    sequence: int,
    *,
    master_type: int = 1,
    inactivity_timer: int = 30000,
    version: int = 1,
) -> bytes:
    """Build a HART-IP Session Initiate request.

    Args:
        sequence: Sequence number.
        master_type: 1=primary master, 0=secondary master.
        inactivity_timer: Inactivity close timer in milliseconds.
        version: HART-IP version (default 1).

    Returns:
        Complete Session Initiate message bytes.
    """

    payload = Int8ub.build(master_type) + Int32ub.build(inactivity_timer)
    total_len = HARTIP_HEADER_SIZE + len(payload)
    header = HARTIPHeader.build(
        {
            "version": version,
            "msg_type": HARTIPMessageType.REQUEST,
            "msg_id": HARTIPMessageID.SESSION_INITIATE,
            "status": 0,
            "sequence": sequence & 0xFFFF,
            "byte_count": total_len,
        }
    )
    return header + payload


def build_session_close(sequence: int, *, version: int = 1) -> bytes:
    """Build a HART-IP Session Close request."""

    header = HARTIPHeader.build(
        {
            "version": version,
            "msg_type": HARTIPMessageType.REQUEST,
            "msg_id": HARTIPMessageID.SESSION_CLOSE,
            "status": 0,
            "sequence": sequence & 0xFFFF,
            "byte_count": HARTIP_HEADER_SIZE,
        }
    )
    return header


def build_keep_alive(sequence: int, *, version: int = 1) -> bytes:
    """Build a HART-IP Keep Alive request."""

    header = HARTIPHeader.build(
        {
            "version": version,
            "msg_type": HARTIPMessageType.REQUEST,
            "msg_id": HARTIPMessageID.KEEP_ALIVE,
            "status": 0,
            "sequence": sequence & 0xFFFF,
            "byte_count": HARTIP_HEADER_SIZE,
        }
    )
    return header


def build_request(
    sequence: int,
    delimiter: int,
    address: bytes,
    command: int,
    data: bytes = b"",
    *,
    version: int = 1,
) -> bytes:
    """Build a complete HART-IP pass-through request (header + PDU).

    The ``msg_id`` is always set to 3 (HART_PDU / token-passing pass-through).

    Args:
        sequence: Sequence number (0-65535).
        delimiter: PDU frame type.
        address: 1-byte or 5-byte address.
        command: HART command number.
        data: Command data payload.
        version: HART-IP version (default 1).

    Returns:
        Complete HART-IP message bytes.
    """

    pdu = build_pdu(delimiter, address, command, data)
    total_len = HARTIP_HEADER_SIZE + len(pdu)
    header = HARTIPHeader.build(
        {
            "version": version,
            "msg_type": HARTIPMessageType.REQUEST,
            "msg_id": HARTIPMessageID.HART_PDU,
            "status": 0,
            "sequence": sequence & 0xFFFF,
            "byte_count": total_len,
        }
    )
    return header + pdu


def parse_response(data: bytes) -> dict:
    """Parse a complete HART-IP response (header + PDU).

    Handles preamble bytes and expansion bytes in the PDU payload.

    Args:
        data: Raw response bytes (at least 8 bytes).

    Returns:
        Dict with keys ``header`` and ``pdu`` (construct-like containers).

    Raises:
        ValueError: If data is too short or payload is truncated.
    """
    if len(data) < HARTIP_HEADER_SIZE:
        raise ValueError(f"HART-IP response too short: {len(data)} bytes")

    header = HARTIPHeader.parse(data[:HARTIP_HEADER_SIZE])

    pdu = None
    if header.payload_len > 0:
        payload_data = data[HARTIP_HEADER_SIZE:]
        if len(payload_data) < header.payload_len:
            raise ValueError(
                f"HART-IP payload truncated: header claims {header.payload_len} bytes, "
                f"got {len(payload_data)}"
            )
        pdu = parse_pdu(payload_data)

    return {"header": header, "pdu": pdu}
