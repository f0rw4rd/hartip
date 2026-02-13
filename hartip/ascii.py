"""
HART 6-bit packed ASCII encoding.

HART uses a compact 6-bit character set where 4 characters pack into 3 bytes.
The character set maps:
    - ASCII 0x40-0x5F (@ A-Z [ \\ ] ^ _) -> HART 0x00-0x1F
    - ASCII 0x20-0x3F (space ! " ... 0-9 ... ?) -> HART 0x20-0x3F

Reference: FieldComm Group HART specification, Packed ASCII encoding.
"""

from __future__ import annotations


def _ascii_to_6bit(c: str) -> int:
    """Convert ASCII character to HART 6-bit value."""
    v = ord(c.upper())
    if 64 <= v <= 95:  # @ through _
        return v - 64
    elif 32 <= v <= 63:  # space through ?
        return v
    return 32  # default: space


def _6bit_to_ascii(v: int) -> str:
    """Convert HART 6-bit value to ASCII character."""
    v = v & 0x3F
    if v <= 31:
        return chr(v + 64)
    return chr(v)


def pack_ascii(text: str) -> bytes:
    """Encode a string using HART 6-bit packed ASCII.

    4 characters pack into 3 bytes.  The input is padded with spaces
    to the next multiple of 4 before encoding.

    Args:
        text: ASCII string to encode.

    Returns:
        Packed bytes (length = ceil(len(text)/4) * 3).
    """
    # Pad to multiple of 4
    text = text.ljust(((len(text) + 3) // 4) * 4)
    result = bytearray()
    for i in range(0, len(text), 4):
        c0 = _ascii_to_6bit(text[i])
        c1 = _ascii_to_6bit(text[i + 1])
        c2 = _ascii_to_6bit(text[i + 2])
        c3 = _ascii_to_6bit(text[i + 3])
        result.append((c0 << 2) | (c1 >> 4))
        result.append(((c1 & 0x0F) << 4) | (c2 >> 2))
        result.append(((c2 & 0x03) << 6) | c3)
    return bytes(result)


def unpack_ascii(data: bytes) -> str:
    """Decode HART 6-bit packed ASCII bytes to a string.

    3 bytes unpack to 4 characters.

    Args:
        data: Packed ASCII bytes.

    Returns:
        Decoded string with trailing spaces stripped.
    """
    result: list[str] = []
    for i in range(0, len(data) - 2, 3):
        b0, b1, b2 = data[i], data[i + 1], data[i + 2]
        result.append(_6bit_to_ascii(b0 >> 2))
        result.append(_6bit_to_ascii(((b0 & 0x03) << 4) | (b1 >> 4)))
        result.append(_6bit_to_ascii(((b1 & 0x0F) << 2) | (b2 >> 6)))
        result.append(_6bit_to_ascii(b2 & 0x3F))
    return "".join(result).rstrip()
