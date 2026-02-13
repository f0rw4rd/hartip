"""Tests for HART-IP protocol structs and helpers."""

from hartip.constants import HARTIP_HEADER_SIZE, HARTFrameType, HARTIPMessageType
from hartip.protocol import (
    HARTIPHeader,
    HARTPdu,
    build_pdu,
    build_request,
    parse_response,
    xor_checksum,
)


class TestXorChecksum:
    def test_empty(self) -> None:
        assert xor_checksum(b"") == 0

    def test_single_byte(self) -> None:
        assert xor_checksum(b"\x42") == 0x42

    def test_two_bytes(self) -> None:
        assert xor_checksum(b"\xFF\xFF") == 0x00

    def test_known_sequence(self) -> None:
        assert xor_checksum(b"\x02\x00\x00\x00") == 0x02


class TestHARTIPHeader:
    def test_build_parse_roundtrip(self) -> None:
        hdr = dict(
            version=1,
            msg_type=HARTIPMessageType.REQUEST,
            msg_id=5,
            status=0,
            sequence=100,
            byte_count=13,
        )
        raw = HARTIPHeader.build(hdr)
        assert len(raw) == HARTIP_HEADER_SIZE

        parsed = HARTIPHeader.parse(raw)
        assert parsed.version == 1
        assert parsed.msg_type == 0
        assert parsed.msg_id == 5
        assert parsed.status == 0
        assert parsed.sequence == 100
        assert parsed.byte_count == 13
        assert parsed.payload_len == 5

    def test_payload_len_computed(self) -> None:
        hdr = dict(version=1, msg_type=0, msg_id=0, status=0, sequence=0, byte_count=8)
        parsed = HARTIPHeader.parse(HARTIPHeader.build(hdr))
        assert parsed.payload_len == 0


class TestHARTPdu:
    def test_short_frame_parse(self) -> None:
        # delimiter=0x02, address=0x00, command=0, byte_count=0, checksum=0x02
        raw = bytes([0x02, 0x00, 0x00, 0x00, 0x02])
        pdu = HARTPdu.parse(raw)
        assert pdu.delimiter == 0x02
        assert pdu.address == b"\x00"
        assert pdu.command == 0
        assert pdu.byte_count == 0

    def test_long_frame_parse(self) -> None:
        # delimiter=0x82, address=5 bytes, command=0, byte_count=0, checksum
        addr = bytes([0x80, 0x03, 0x01, 0x00, 0x01])
        frame_no_cksum = bytes([0x82]) + addr + bytes([0x00, 0x00])
        cksum = xor_checksum(frame_no_cksum)
        raw = frame_no_cksum + bytes([cksum])
        pdu = HARTPdu.parse(raw)
        assert pdu.delimiter == 0x82
        assert pdu.address == addr
        assert pdu.command == 0
        assert pdu.byte_count == 0
        assert pdu.checksum == cksum


class TestBuildPdu:
    def test_short_frame(self) -> None:
        raw = build_pdu(HARTFrameType.SHORT_FRAME, b"\x00", 0)
        assert len(raw) == 5  # delimiter + addr + cmd + bytecount + cksum
        # checksum should be XOR of first 4 bytes
        assert raw[-1] == xor_checksum(raw[:-1])

    def test_with_data(self) -> None:
        data = bytes([0x01, 0x02, 0x03])
        raw = build_pdu(HARTFrameType.SHORT_FRAME, b"\x00", 1, data)
        # delimiter(1) + addr(1) + cmd(1) + bc(1) + data(3) + cksum(1)
        assert len(raw) == 8
        assert raw[3] == 3  # byte_count field
        assert raw[-1] == xor_checksum(raw[:-1])


class TestBuildRequest:
    def test_builds_valid_frame(self) -> None:
        frame = build_request(
            msg_id=1,
            sequence=1,
            delimiter=HARTFrameType.SHORT_FRAME,
            address=b"\x00",
            command=0,
        )
        assert len(frame) == HARTIP_HEADER_SIZE + 5
        # Header version
        assert frame[0] == 1
        # Header msg_type = REQUEST
        assert frame[1] == 0
        # byte_count should be total length
        byte_count = (frame[6] << 8) | frame[7]
        assert byte_count == len(frame)


class TestParseResponse:
    def test_header_only(self) -> None:
        hdr = HARTIPHeader.build(
            dict(version=1, msg_type=1, msg_id=1, status=0, sequence=1, byte_count=8)
        )
        result = parse_response(hdr)
        assert result["header"].byte_count == 8
        assert result["pdu"] is None

    def test_with_pdu(self) -> None:
        pdu_raw = build_pdu(HARTFrameType.SHORT_FRAME, b"\x00", 0)
        total = HARTIP_HEADER_SIZE + len(pdu_raw)
        hdr = HARTIPHeader.build(
            dict(version=1, msg_type=1, msg_id=1, status=0, sequence=1, byte_count=total)
        )
        result = parse_response(hdr + pdu_raw)
        assert result["pdu"] is not None
        assert result["pdu"].command == 0
