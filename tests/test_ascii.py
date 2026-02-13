"""Tests for HART 6-bit packed ASCII encoding."""

from hartip.ascii import pack_ascii, unpack_ascii


class TestPackAscii:
    def test_empty_string(self) -> None:
        assert pack_ascii("") == b""

    def test_four_spaces(self) -> None:
        # Space = HART 0x20; 4 spaces -> 3 bytes
        packed = pack_ascii("    ")
        assert len(packed) == 3

    def test_roundtrip_simple(self) -> None:
        text = "HELLO"
        packed = pack_ascii(text)
        unpacked = unpack_ascii(packed)
        # Input is padded to 8 chars (next multiple of 4), then trailing spaces stripped
        assert unpacked == "HELLO"

    def test_roundtrip_tag(self) -> None:
        # Typical HART tag: 8 packed-ASCII chars -> 6 bytes
        tag = "TT-101A"
        packed = pack_ascii(tag)
        assert len(packed) == 6  # 8 chars (padded) -> 6 bytes
        assert unpack_ascii(packed) == "TT-101A"

    def test_roundtrip_descriptor(self) -> None:
        desc = "PRESSURE XMTR"
        packed = pack_ascii(desc)
        assert unpack_ascii(packed) == "PRESSURE XMTR"

    def test_lowercase_uppercased(self) -> None:
        packed = pack_ascii("hello")
        assert unpack_ascii(packed) == "HELLO"

    def test_numbers_preserved(self) -> None:
        packed = pack_ascii("1234")
        assert len(packed) == 3
        assert unpack_ascii(packed) == "1234"

    def test_special_chars(self) -> None:
        packed = pack_ascii("@A/ ")
        assert len(packed) == 3
        # trailing space is stripped by unpack_ascii
        assert unpack_ascii(packed) == "@A/"


class TestUnpackAscii:
    def test_known_bytes(self) -> None:
        # "HART" -> H=0x08, A=0x01, R=0x12, T=0x14
        # Pack: b0 = (0x08<<2)|(0x01>>4) = 0x20
        #       b1 = ((0x01&0xF)<<4)|(0x12>>2) = 0x14
        #       b2 = ((0x12&0x3)<<6)|0x14 = 0x94
        expected = "HART"
        packed = pack_ascii(expected)
        assert unpack_ascii(packed) == expected

    def test_short_input(self) -> None:
        # Less than 3 bytes -> empty
        assert unpack_ascii(b"\x00\x00") == ""
