"""
HART-IP protocol structures using the ``construct`` library.

Defines declarative binary parsers/builders for:
- HART-IP transport header (TP10300 / HCF_SPEC-085)
- HART PDU frames (short and long)
- Complete HART-IP messages

All multi-byte integers are big-endian as per the HART specification.
"""

from __future__ import annotations

import struct as _struct

from construct import (
    Bytes,
    Computed,
    IfThenElse,
    Int8ub,
    Int16ub,
    Struct,
    this,
)

from .constants import HARTIP_HEADER_SIZE

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
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
    """
    byte_count = len(data)
    frame_no_cksum = bytes([delimiter]) + address + bytes([command, byte_count]) + data
    checksum = xor_checksum(frame_no_cksum)
    return frame_no_cksum + bytes([checksum])


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
    from .constants import HARTIPMessageID, HARTIPMessageType

    payload = _struct.pack(">BI", master_type, inactivity_timer)
    total_len = HARTIP_HEADER_SIZE + len(payload)
    header = HARTIPHeader.build(
        dict(
            version=version,
            msg_type=HARTIPMessageType.REQUEST,
            msg_id=HARTIPMessageID.SESSION_INITIATE,
            status=0,
            sequence=sequence & 0xFFFF,
            byte_count=total_len,
        )
    )
    return header + payload


def build_session_close(sequence: int, *, version: int = 1) -> bytes:
    """Build a HART-IP Session Close request."""
    from .constants import HARTIPMessageID, HARTIPMessageType

    header = HARTIPHeader.build(
        dict(
            version=version,
            msg_type=HARTIPMessageType.REQUEST,
            msg_id=HARTIPMessageID.SESSION_CLOSE,
            status=0,
            sequence=sequence & 0xFFFF,
            byte_count=HARTIP_HEADER_SIZE,
        )
    )
    return header


def build_keep_alive(sequence: int, *, version: int = 1) -> bytes:
    """Build a HART-IP Keep Alive request."""
    from .constants import HARTIPMessageID, HARTIPMessageType

    header = HARTIPHeader.build(
        dict(
            version=version,
            msg_type=HARTIPMessageType.REQUEST,
            msg_id=HARTIPMessageID.KEEP_ALIVE,
            status=0,
            sequence=sequence & 0xFFFF,
            byte_count=HARTIP_HEADER_SIZE,
        )
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
    from .constants import HARTIPMessageID, HARTIPMessageType

    pdu = build_pdu(delimiter, address, command, data)
    total_len = HARTIP_HEADER_SIZE + len(pdu)
    header = HARTIPHeader.build(
        dict(
            version=version,
            msg_type=HARTIPMessageType.REQUEST,
            msg_id=HARTIPMessageID.HART_PDU,
            status=0,
            sequence=sequence & 0xFFFF,
            byte_count=total_len,
        )
    )
    return header + pdu


def parse_response(data: bytes) -> dict:
    """Parse a complete HART-IP response (header + PDU).

    Args:
        data: Raw response bytes (at least 8 bytes).

    Returns:
        Dict with keys ``header`` and ``pdu`` (construct Containers).

    Raises:
        ValueError: If data is too short.
    """
    if len(data) < HARTIP_HEADER_SIZE:
        raise ValueError(f"HART-IP response too short: {len(data)} bytes")

    header = HARTIPHeader.parse(data[:HARTIP_HEADER_SIZE])

    pdu = None
    if header.payload_len > 0:
        pdu = HARTPdu.parse(data[HARTIP_HEADER_SIZE:])

    return {"header": header, "pdu": pdu}
