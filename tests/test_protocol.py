"""Tests for HART-IP protocol structs and helpers."""

import pytest

from hartip.constants import (
    HARTIP_HEADER_SIZE,
    HARTFrameType,
    HARTIPMessageID,
    HARTIPMessageType,
)
from hartip.protocol import (
    HARTIPHeader,
    HARTPdu,
    PduContainer,
    build_keep_alive,
    build_pdu,
    build_request,
    build_session_close,
    build_session_init,
    parse_pdu,
    parse_response,
    xor_checksum,
)


class TestXorChecksum:
    def test_empty(self) -> None:
        assert xor_checksum(b"") == 0

    def test_single_byte(self) -> None:
        assert xor_checksum(b"\x42") == 0x42

    def test_two_bytes(self) -> None:
        assert xor_checksum(b"\xff\xff") == 0x00

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

    def test_data_too_long_raises(self) -> None:
        data = bytes(256)
        with pytest.raises(ValueError, match="exceeds maximum of 255"):
            build_pdu(HARTFrameType.SHORT_FRAME, b"\x00", 0, data)

    def test_data_max_255(self) -> None:
        data = bytes(255)
        raw = build_pdu(HARTFrameType.SHORT_FRAME, b"\x00", 0, data)
        assert raw[3] == 255

    def test_long_frame(self) -> None:
        addr = bytes([0x80, 0x26, 0x01, 0x02, 0x03])
        raw = build_pdu(HARTFrameType.LONG_FRAME, addr, 0)
        assert len(raw) == 9  # delimiter(1) + addr(5) + cmd(1) + bc(1) + cksum(1)
        assert raw[-1] == xor_checksum(raw[:-1])


class TestBuildRequest:
    def test_builds_valid_frame(self) -> None:
        frame = build_request(
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
        # Header msg_id = HART_PDU (3)
        assert frame[2] == 3
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

    def test_truncated_payload_raises(self) -> None:
        hdr = HARTIPHeader.build(
            dict(version=1, msg_type=1, msg_id=3, status=0, sequence=1, byte_count=20)
        )
        with pytest.raises(ValueError, match="truncated"):
            parse_response(hdr + b"\x02\x00\x00")

    def test_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            parse_response(b"\x01\x02\x03")


# ---------------------------------------------------------------------------
# parse_pdu
# ---------------------------------------------------------------------------


class TestParsePdu:
    def test_short_frame_no_preamble(self) -> None:
        raw = build_pdu(HARTFrameType.SHORT_FRAME, b"\x00", 0)
        pdu = parse_pdu(raw)
        assert pdu.delimiter == 0x02
        assert pdu.address == b"\x00"
        assert pdu.command == 0
        assert pdu.byte_count == 0
        assert pdu.preamble_count == 0
        assert pdu.expansion_bytes == b""

    def test_long_frame_no_preamble(self) -> None:
        addr = bytes([0x80, 0x26, 0x01, 0x02, 0x03])
        raw = build_pdu(HARTFrameType.LONG_FRAME, addr, 0)
        pdu = parse_pdu(raw)
        assert pdu.delimiter == 0x82
        assert pdu.address == addr
        assert pdu.command == 0

    def test_with_preamble(self) -> None:
        preamble = b"\xff\xff\xff\xff\xff"
        raw = preamble + build_pdu(HARTFrameType.SHORT_FRAME, b"\x00", 0)
        pdu = parse_pdu(raw)
        assert pdu.preamble_count == 5
        assert pdu.command == 0

    def test_with_data(self) -> None:
        data = bytes([0x00, 0x00, 0x01, 0x02, 0x03])
        raw = build_pdu(HARTFrameType.SHORT_FRAME, b"\x00", 3, data)
        pdu = parse_pdu(raw)
        assert pdu.command == 3
        assert pdu.byte_count == 5
        assert bytes(pdu.data) == data

    def test_expansion_bytes(self) -> None:
        # Delimiter with 1 expansion byte (bits 5-6 = 01 → 0x22)
        delim = 0x02 | (1 << 5)  # 0x22
        frame_no_cksum = bytes([delim, 0x00, 0xAA, 0x00, 0x00])
        cksum = xor_checksum(frame_no_cksum)
        raw = frame_no_cksum + bytes([cksum])
        pdu = parse_pdu(raw)
        assert pdu.expansion_bytes == bytes([0xAA])
        assert pdu.command == 0
        assert pdu.byte_count == 0

    def test_ack_short_frame(self) -> None:
        # ACK short frame (0x06) - response delimiter
        frame_no_cksum = bytes([0x06, 0x00, 0x00, 0x00])
        cksum = xor_checksum(frame_no_cksum)
        raw = frame_no_cksum + bytes([cksum])
        pdu = parse_pdu(raw)
        assert pdu.delimiter == 0x06
        assert len(pdu.address) == 1  # short frame (bit 7 clear)

    def test_ack_long_frame(self) -> None:
        # ACK long frame (0x86) - response delimiter
        addr = bytes([0x80, 0x26, 0x01, 0x02, 0x03])
        frame_no_cksum = bytes([0x86]) + addr + bytes([0x00, 0x00])
        cksum = xor_checksum(frame_no_cksum)
        raw = frame_no_cksum + bytes([cksum])
        pdu = parse_pdu(raw)
        assert pdu.delimiter == 0x86
        assert len(pdu.address) == 5  # long frame (bit 7 set)

    def test_only_preambles_raises(self) -> None:
        with pytest.raises(ValueError, match="only preamble"):
            parse_pdu(b"\xff\xff\xff")

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="only preamble"):
            parse_pdu(b"")

    def test_truncated_address_raises(self) -> None:
        # Long frame delimiter but only 2 address bytes
        with pytest.raises(ValueError, match="too short"):
            parse_pdu(bytes([0x82, 0x00, 0x00]))


# ---------------------------------------------------------------------------
# Session builders
# ---------------------------------------------------------------------------


class TestBuildSessionInit:
    def test_structure(self) -> None:
        frame = build_session_init(sequence=1)
        assert len(frame) == HARTIP_HEADER_SIZE + 5  # 5-byte payload
        hdr = HARTIPHeader.parse(frame[:HARTIP_HEADER_SIZE])
        assert hdr.version == 1
        assert hdr.msg_type == HARTIPMessageType.REQUEST
        assert hdr.msg_id == HARTIPMessageID.SESSION_INITIATE
        assert hdr.sequence == 1
        assert hdr.byte_count == len(frame)

    def test_payload_master_type(self) -> None:
        frame = build_session_init(sequence=1, master_type=0)
        payload = frame[HARTIP_HEADER_SIZE:]
        assert payload[0] == 0  # secondary master

    def test_payload_inactivity_timer(self) -> None:
        import struct

        frame = build_session_init(sequence=1, inactivity_timer=60000)
        payload = frame[HARTIP_HEADER_SIZE:]
        timer = struct.unpack(">I", payload[1:5])[0]
        assert timer == 60000


class TestBuildSessionClose:
    def test_structure(self) -> None:
        frame = build_session_close(sequence=5)
        assert len(frame) == HARTIP_HEADER_SIZE  # no payload
        hdr = HARTIPHeader.parse(frame[:HARTIP_HEADER_SIZE])
        assert hdr.msg_id == HARTIPMessageID.SESSION_CLOSE
        assert hdr.sequence == 5
        assert hdr.byte_count == HARTIP_HEADER_SIZE


class TestBuildKeepAlive:
    def test_structure(self) -> None:
        frame = build_keep_alive(sequence=10)
        assert len(frame) == HARTIP_HEADER_SIZE
        hdr = HARTIPHeader.parse(frame[:HARTIP_HEADER_SIZE])
        assert hdr.msg_id == HARTIPMessageID.KEEP_ALIVE
        assert hdr.sequence == 10


# ---------------------------------------------------------------------------
# PduContainer dataclass
# ---------------------------------------------------------------------------


class TestPduContainer:
    def test_parse_pdu_returns_pdu_container(self) -> None:
        raw = build_pdu(HARTFrameType.SHORT_FRAME, b"\x00", 0)
        result = parse_pdu(raw)
        assert isinstance(result, PduContainer)

    def test_pdu_container_fields(self) -> None:
        data = bytes([0x01, 0x02, 0x03])
        raw = build_pdu(HARTFrameType.SHORT_FRAME, b"\x00", 3, data)
        result = parse_pdu(raw)
        assert result.delimiter == 0x02
        assert result.address == b"\x00"
        assert result.command == 3
        assert result.byte_count == 3
        assert bytes(result.data) == data
        assert result.preamble_count == 0
        assert result.expansion_bytes == b""

    def test_pdu_container_repr(self) -> None:
        raw = build_pdu(HARTFrameType.SHORT_FRAME, b"\x00", 0)
        result = parse_pdu(raw)
        r = repr(result)
        assert "cmd=0" in r
        assert "bc=0" in r
        assert "0x02" in r

    def test_pdu_container_is_dataclass(self) -> None:
        from dataclasses import fields

        f = fields(PduContainer)
        names = [field.name for field in f]
        assert "delimiter" in names
        assert "command" in names
        assert "data" in names
