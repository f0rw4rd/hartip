"""Tests for usability improvements: default address, TypedDicts, Device class.

Covers:
1. Default address on HARTIPClient (sentinel-based resolution)
2. Typed response objects (TypedDicts importable and structurally correct)
3. High-level Device class (context manager, cached identity, live properties)
"""

import struct
from unittest.mock import MagicMock, patch

from hartip.client import _UNSET, HARTIPClient
from hartip.constants import HARTIP_HEADER_SIZE, HARTFrameType, HARTIPMessageType
from hartip.device import (
    DeviceInfo,
    parse_cmd0,
    parse_cmd2,
    parse_cmd3,
    parse_cmd8,
    parse_cmd9,
    parse_cmd13,
    parse_cmd15,
    parse_cmd48,
    parse_cmd54,
)
from hartip.high_level import Device
from hartip.protocol import HARTIPHeader, build_pdu

# ---------------------------------------------------------------------------
# Helpers (same pattern as test_client.py)
# ---------------------------------------------------------------------------

_ADDR = ("127.0.0.1", 5094)


def _build_session_init_response(status: int = 0) -> bytes:
    payload = struct.pack(">BI", 1, 30000)
    total = HARTIP_HEADER_SIZE + len(payload)
    hdr = HARTIPHeader.build(
        dict(
            version=1,
            msg_type=HARTIPMessageType.RESPONSE,
            msg_id=0,
            status=status,
            sequence=1,
            byte_count=total,
        )
    )
    return hdr + payload


def _build_session_close_response() -> bytes:
    return HARTIPHeader.build(
        dict(
            version=1,
            msg_type=HARTIPMessageType.RESPONSE,
            msg_id=1,
            status=0,
            sequence=1,
            byte_count=HARTIP_HEADER_SIZE,
        )
    )


def _build_mock_response(
    command: int = 0,
    response_code: int = 0,
    device_status: int = 0,
    payload: bytes = b"",
    status: int = 0,
) -> bytes:
    data = bytes([response_code, device_status]) + payload
    pdu = build_pdu(HARTFrameType.SHORT_FRAME, b"\x00", command, data)
    total = HARTIP_HEADER_SIZE + len(pdu)
    hdr = HARTIPHeader.build(
        dict(
            version=1,
            msg_type=HARTIPMessageType.RESPONSE,
            msg_id=3,
            status=status,
            sequence=1,
            byte_count=total,
        )
    )
    return hdr + pdu


def _make_cmd0_payload(
    manufacturer_id: int = 0x26,
    device_type: int = 0x01,
    device_id_bytes: tuple = (0x01, 0x02, 0x03),
) -> bytes:
    """Build a standard 12-byte Command 0 response payload."""
    return bytes(
        [
            0x00,  # expansion code
            manufacturer_id,
            device_type,
            0x05,  # num_preambles
            0x05,  # hart_revision
            0x03,  # device_revision
            0x02,  # software_revision
            0x10,  # hw_rev | phys_sig
            0x00,  # flags
            *device_id_bytes,
        ]
    )


# ---------------------------------------------------------------------------
# Feature 1: Default address on HARTIPClient
# ---------------------------------------------------------------------------


class TestDefaultAddress:
    def test_default_address_initial_values(self) -> None:
        """Client starts with default_address=0, default_unique_addr=None."""
        client = HARTIPClient("127.0.0.1")
        assert client.default_address == 0
        assert client.default_unique_addr is None

    def test_default_address_settable(self) -> None:
        """Users can set default_address directly."""
        client = HARTIPClient("127.0.0.1")
        client.default_address = 5
        assert client.default_address == 5

    def test_default_unique_addr_settable(self) -> None:
        """Users can set default_unique_addr directly."""
        client = HARTIPClient("127.0.0.1")
        addr = bytes([0x80, 0x26, 0x01, 0x02, 0x03])
        client.default_unique_addr = addr
        assert client.default_unique_addr == addr

    def test_read_unique_id_auto_populates_default_unique_addr(self) -> None:
        """read_unique_id() auto-sets default_unique_addr on success."""
        session_resp = _build_session_init_response()
        cmd0_payload = _make_cmd0_payload()
        cmd_resp = _build_mock_response(command=0, payload=cmd0_payload)
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session_resp, _ADDR),
                (cmd_resp, _ADDR),
                (close_resp, _ADDR),
            ]
            client = HARTIPClient("127.0.0.1", protocol="udp")
            client.connect()
            assert client.default_unique_addr is None

            resp = client.read_unique_id()
            assert resp.success
            assert client.default_unique_addr is not None
            assert len(client.default_unique_addr) == 5

            # Verify the unique address was built correctly
            info = parse_cmd0(cmd0_payload)
            assert client.default_unique_addr == info.unique_address
            client.close()

    def test_subsequent_calls_use_default_unique_addr(self) -> None:
        """After read_unique_id, subsequent methods use the default address."""
        session_resp = _build_session_init_response()
        cmd0_payload = _make_cmd0_payload()
        cmd0_resp = _build_mock_response(command=0, payload=cmd0_payload)
        cmd1_payload = bytes([7]) + struct.pack(">f", 1.5)
        cmd1_resp = _build_mock_response(command=1, payload=cmd1_payload)
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session_resp, _ADDR),
                (cmd0_resp, _ADDR),
                (cmd1_resp, _ADDR),
                (close_resp, _ADDR),
            ]
            client = HARTIPClient("127.0.0.1", protocol="udp")
            client.connect()
            client.read_unique_id()

            # Now read PV without passing address -- should use long frame
            resp = client.read_primary_variable()
            assert resp.response_code == 0

            # Verify long frame was used (unique_addr was resolved)
            sent_frame = mock_sock.sendto.call_args_list[-1][0][0]
            pdu_bytes = sent_frame[HARTIP_HEADER_SIZE:]
            # Long frame delimiter is 0x82 (HARTFrameType.LONG_FRAME)
            assert pdu_bytes[0] == HARTFrameType.LONG_FRAME
            client.close()

    def test_explicit_address_overrides_default(self) -> None:
        """Explicit address=5 overrides default_address=0."""
        session_resp = _build_session_init_response()
        cmd_resp = _build_mock_response(command=0, payload=_make_cmd0_payload())
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session_resp, _ADDR),
                (cmd_resp, _ADDR),
                (close_resp, _ADDR),
            ]
            client = HARTIPClient("127.0.0.1", protocol="udp")
            client.default_address = 3
            client.connect()

            # Explicit address=5 should override the default of 3
            client.read_unique_id(address=5)
            sent_frame = mock_sock.sendto.call_args_list[-1][0][0]
            pdu_bytes = sent_frame[HARTIP_HEADER_SIZE:]
            # Short frame: address byte at index 1 should be (5 | 0x80) = 0x85
            assert pdu_bytes[1] == 0x85
            client.close()

    def test_explicit_none_overrides_default_unique_addr(self) -> None:
        """Passing unique_addr=None explicitly should use short frame."""
        session_resp = _build_session_init_response()
        cmd_resp = _build_mock_response(command=1, payload=bytes([7]) + struct.pack(">f", 1.0))
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session_resp, _ADDR),
                (cmd_resp, _ADDR),
                (close_resp, _ADDR),
            ]
            client = HARTIPClient("127.0.0.1", protocol="udp")
            client.default_unique_addr = bytes([0x80, 0x26, 0x01, 0x02, 0x03])
            client.connect()

            # Pass None explicitly to bypass the default
            resp = client.read_primary_variable(unique_addr=None)
            assert resp.response_code == 0

            # Should use short frame (delimiter 0x02 / SHORT_FRAME)
            sent_frame = mock_sock.sendto.call_args_list[-1][0][0]
            pdu_bytes = sent_frame[HARTIP_HEADER_SIZE:]
            assert pdu_bytes[0] == HARTFrameType.SHORT_FRAME
            client.close()

    def test_unset_sentinel_identity(self) -> None:
        """_UNSET is a unique sentinel object."""
        assert _UNSET is not None
        assert _UNSET != 0
        assert _UNSET is _UNSET


# ---------------------------------------------------------------------------
# Feature 2: Typed response objects (TypedDicts)
# ---------------------------------------------------------------------------


class TestTypedDicts:
    """Verify TypedDicts are importable and structurally correct."""

    def test_cmd2_response_keys(self) -> None:
        result = parse_cmd2(struct.pack(">f", 4.0) + struct.pack(">f", 50.0))
        assert "current_mA" in result
        assert "percent_range" in result

    def test_cmd3_response_keys(self) -> None:
        payload = struct.pack(">f", 4.0) + bytes([7]) + struct.pack(">f", 1.0)
        result = parse_cmd3(payload)
        assert "loop_current" in result
        assert "variables" in result

    def test_cmd8_response_keys(self) -> None:
        result = parse_cmd8(bytes([64, 65, 66, 67]))
        assert "pv_classification" in result
        assert "pv_classification_name" in result

    def test_cmd9_response_keys(self) -> None:
        payload = bytes([0x00, 0x00, 0x40, 0x07]) + struct.pack(">f", 1.5) + bytes([0x00])
        result = parse_cmd9(payload)
        assert "extended_device_status" in result
        assert "variables" in result
        assert "timestamp" in result

    def test_cmd13_response_keys(self) -> None:
        from hartip.ascii import pack_ascii

        tag = pack_ascii("TAG12345")[:6].ljust(6, b"\x00")
        desc = pack_ascii("DESCRIPTION TEST")[:12].ljust(12, b"\x00")
        payload = tag + desc + bytes([15, 6, 124])
        result = parse_cmd13(payload)
        assert "tag" in result
        assert "descriptor" in result
        assert "date" in result

    def test_cmd15_response_keys(self) -> None:
        payload = bytes([0x00, 0x00, 0x07])
        payload += struct.pack(">f", 100.0)
        payload += struct.pack(">f", 0.0)
        payload += struct.pack(">f", 2.0)
        payload += bytes([0xFB, 0xFA, 0x00])
        result = parse_cmd15(payload)
        assert "alarm_selection_code" in result
        assert "range_unit_name" in result

    def test_cmd48_response_keys(self) -> None:
        payload = bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x20])
        result = parse_cmd48(payload)
        assert "device_specific_status" in result
        assert "extended_device_status" in result

    def test_cmd54_response_keys(self) -> None:
        payload = bytes([0x00, 0x00, 0x01, 0x02, 0x07])
        payload += struct.pack(">f", 100.0)
        payload += struct.pack(">f", 0.0)
        result = parse_cmd54(payload)
        assert "device_variable_code" in result
        assert "unit_name" in result

    def test_typeddict_imports(self) -> None:
        """All TypedDict types are importable from hartip.types and hartip."""
        import hartip
        import hartip.types

        # Importable from top-level package
        assert hasattr(hartip, "Cmd2Response")
        assert hasattr(hartip, "Cmd3Response")
        assert hasattr(hartip, "Cmd8Response")
        assert hasattr(hartip, "Cmd9Response")
        assert hasattr(hartip, "Cmd13Response")
        assert hasattr(hartip, "Cmd15Response")
        assert hasattr(hartip, "Cmd48Response")
        assert hasattr(hartip, "Cmd54Response")

        # They should be types (not instances)
        assert isinstance(hartip.types.Cmd2Response, type)
        assert isinstance(hartip.types.Cmd9Response, type)
        assert isinstance(hartip.types.Cmd48Response, type)


# ---------------------------------------------------------------------------
# Feature 3: High-level Device class
# ---------------------------------------------------------------------------


def _make_device_responses():
    """Build standard responses for Device.__init__ (cmd0, cmd13, cmd20)."""
    session = _build_session_init_response()
    cmd0_payload = _make_cmd0_payload()
    cmd0 = _build_mock_response(command=0, payload=cmd0_payload)

    # Command 13 response
    from hartip.ascii import pack_ascii

    tag = pack_ascii("MYTAG123")[:6].ljust(6, b"\x00")
    desc = pack_ascii("SOMEDESCRIPTION!")[:12].ljust(12, b"\x00")
    cmd13_payload = tag + desc + bytes([15, 2, 126])
    cmd13 = _build_mock_response(command=13, payload=cmd13_payload)

    # Command 20 response
    long_tag = b"Temperature Transmitter\x00" + b"\x00" * 9
    cmd20 = _build_mock_response(command=20, payload=long_tag)

    return session, cmd0, cmd13, cmd20


class TestDeviceClass:
    def test_device_creates_and_reads_identity(self) -> None:
        """Device.__init__ connects and reads Commands 0, 13, 20."""
        session, cmd0, cmd13, cmd20 = _make_device_responses()
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session, _ADDR),
                (cmd0, _ADDR),
                (cmd13, _ADDR),
                (cmd20, _ADDR),
                (close_resp, _ADDR),
            ]
            dev = Device("127.0.0.1", protocol="udp")
            assert "Rosemount" in dev.manufacturer_name
            assert dev.device_id == 0x010203
            assert "MYTAG" in dev.tag
            assert "Temperature Transmitter" in dev.long_tag
            dev.close()

    def test_device_context_manager(self) -> None:
        """Device supports with-statement."""
        session, cmd0, cmd13, cmd20 = _make_device_responses()
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session, _ADDR),
                (cmd0, _ADDR),
                (cmd13, _ADDR),
                (cmd20, _ADDR),
                (close_resp, _ADDR),
            ]
            with Device("127.0.0.1", protocol="udp") as dev:
                assert dev.client.connected
            assert not dev.client.connected

    def test_device_primary_variable(self) -> None:
        """Device.primary_variable reads Command 1 on access."""
        session, cmd0, cmd13, cmd20 = _make_device_responses()
        cmd1_payload = bytes([7]) + struct.pack(">f", 25.3)
        cmd1 = _build_mock_response(command=1, payload=cmd1_payload)
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session, _ADDR),
                (cmd0, _ADDR),
                (cmd13, _ADDR),
                (cmd20, _ADDR),
                (cmd1, _ADDR),
                (close_resp, _ADDR),
            ]
            dev = Device("127.0.0.1", protocol="udp")
            pv = dev.primary_variable
            assert pv is not None
            assert abs(pv.value - 25.3) < 0.1
            assert pv.unit_name == "bar"
            dev.close()

    def test_device_loop_current(self) -> None:
        """Device.loop_current reads Command 2 on access."""
        session, cmd0, cmd13, cmd20 = _make_device_responses()
        cmd2_payload = struct.pack(">f", 12.5) + struct.pack(">f", 45.2)
        cmd2 = _build_mock_response(command=2, payload=cmd2_payload)
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session, _ADDR),
                (cmd0, _ADDR),
                (cmd13, _ADDR),
                (cmd20, _ADDR),
                (cmd2, _ADDR),
                (close_resp, _ADDR),
            ]
            dev = Device("127.0.0.1", protocol="udp")
            current = dev.loop_current
            assert current is not None
            assert abs(current - 12.5) < 0.1
            dev.close()

    def test_device_percent_range(self) -> None:
        """Device.percent_range reads Command 2 on access."""
        session, cmd0, cmd13, cmd20 = _make_device_responses()
        cmd2_payload = struct.pack(">f", 12.5) + struct.pack(">f", 45.2)
        cmd2 = _build_mock_response(command=2, payload=cmd2_payload)
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session, _ADDR),
                (cmd0, _ADDR),
                (cmd13, _ADDR),
                (cmd20, _ADDR),
                (cmd2, _ADDR),
                (close_resp, _ADDR),
            ]
            dev = Device("127.0.0.1", protocol="udp")
            pct = dev.percent_range
            assert pct is not None
            assert abs(pct - 45.2) < 0.1
            dev.close()

    def test_device_dynamic_variables(self) -> None:
        """Device.dynamic_variables reads Command 3 on access."""
        session, cmd0, cmd13, cmd20 = _make_device_responses()
        cmd3_payload = struct.pack(">f", 4.0)
        cmd3_payload += bytes([7]) + struct.pack(">f", 1.0)
        cmd3_payload += bytes([32]) + struct.pack(">f", 25.0)
        cmd3 = _build_mock_response(command=3, payload=cmd3_payload)
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session, _ADDR),
                (cmd0, _ADDR),
                (cmd13, _ADDR),
                (cmd20, _ADDR),
                (cmd3, _ADDR),
                (close_resp, _ADDR),
            ]
            dev = Device("127.0.0.1", protocol="udp")
            dvars = dev.dynamic_variables
            assert len(dvars) == 2
            assert dvars[0].label == "PV"
            dev.close()

    def test_device_variables_cmd9(self) -> None:
        """Device.device_variables() reads Command 9."""
        session, cmd0, cmd13, cmd20 = _make_device_responses()
        cmd9_payload = bytes([0x00])  # ext status
        cmd9_payload += bytes([0x00, 0x40, 0x07]) + struct.pack(">f", 1.5) + bytes([0x00])
        cmd9 = _build_mock_response(command=9, payload=cmd9_payload)
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session, _ADDR),
                (cmd0, _ADDR),
                (cmd13, _ADDR),
                (cmd20, _ADDR),
                (cmd9, _ADDR),
                (close_resp, _ADDR),
            ]
            dev = Device("127.0.0.1", protocol="udp")
            dvars = dev.device_variables([0])
            assert len(dvars) == 1
            assert abs(dvars[0].value - 1.5) < 0.001
            dev.close()

    def test_device_status_cmd48(self) -> None:
        """Device.status reads Command 48 on access."""
        session, cmd0, cmd13, cmd20 = _make_device_responses()
        cmd48_payload = bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x20])
        cmd48 = _build_mock_response(command=48, payload=cmd48_payload)
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session, _ADDR),
                (cmd0, _ADDR),
                (cmd13, _ADDR),
                (cmd20, _ADDR),
                (cmd48, _ADDR),
                (close_resp, _ADDR),
            ]
            dev = Device("127.0.0.1", protocol="udp")
            status = dev.status
            assert "device_specific_status" in status
            assert status["extended_device_status"] == 0x10
            dev.close()

    def test_device_message_cmd12(self) -> None:
        """Device.message reads Command 12 on access."""
        from hartip.ascii import pack_ascii

        session, cmd0, cmd13, cmd20 = _make_device_responses()
        packed_msg = pack_ascii("HELLO WORLD TEST MESSAGE")
        packed_msg = packed_msg + bytes(24 - len(packed_msg))
        cmd12 = _build_mock_response(command=12, payload=packed_msg[:24])
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session, _ADDR),
                (cmd0, _ADDR),
                (cmd13, _ADDR),
                (cmd20, _ADDR),
                (cmd12, _ADDR),
                (close_resp, _ADDR),
            ]
            dev = Device("127.0.0.1", protocol="udp")
            msg = dev.message
            assert "HELLO" in msg
            dev.close()

    def test_device_client_attribute(self) -> None:
        """Device.client exposes the underlying HARTIPClient."""
        session, cmd0, cmd13, cmd20 = _make_device_responses()
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session, _ADDR),
                (cmd0, _ADDR),
                (cmd13, _ADDR),
                (cmd20, _ADDR),
                (close_resp, _ADDR),
            ]
            dev = Device("127.0.0.1", protocol="udp")
            assert isinstance(dev.client, HARTIPClient)
            dev.close()

    def test_device_repr(self) -> None:
        """Device has a useful repr."""
        session, cmd0, cmd13, cmd20 = _make_device_responses()
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session, _ADDR),
                (cmd0, _ADDR),
                (cmd13, _ADDR),
                (cmd20, _ADDR),
                (close_resp, _ADDR),
            ]
            dev = Device("127.0.0.1", protocol="udp")
            r = repr(dev)
            assert "Device(" in r
            assert "Rosemount" in r
            dev.close()

    def test_device_info_property(self) -> None:
        """Device.info returns the full DeviceInfo dataclass."""
        session, cmd0, cmd13, cmd20 = _make_device_responses()
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session, _ADDR),
                (cmd0, _ADDR),
                (cmd13, _ADDR),
                (cmd20, _ADDR),
                (close_resp, _ADDR),
            ]
            dev = Device("127.0.0.1", protocol="udp")
            assert isinstance(dev.info, DeviceInfo)
            assert dev.info.manufacturer_id == 0x26
            dev.close()

    def test_device_cached_identity_properties(self) -> None:
        """Identity properties delegate to cached DeviceInfo."""
        session, cmd0, cmd13, cmd20 = _make_device_responses()
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session, _ADDR),
                (cmd0, _ADDR),
                (cmd13, _ADDR),
                (cmd20, _ADDR),
                (close_resp, _ADDR),
            ]
            dev = Device("127.0.0.1", protocol="udp")
            assert dev.manufacturer_id == 0x26
            assert dev.device_type == 0x01
            assert dev.hart_revision == 5
            assert dev.software_revision == 2
            assert dev.hardware_revision == 2
            assert len(dev.unique_address) == 5
            dev.close()

    def test_device_auto_read_tags_false(self) -> None:
        """auto_read_tags=False skips Commands 13 and 20."""
        session = _build_session_init_response()
        cmd0_payload = _make_cmd0_payload()
        cmd0 = _build_mock_response(command=0, payload=cmd0_payload)
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session, _ADDR),
                (cmd0, _ADDR),
                (close_resp, _ADDR),
            ]
            dev = Device("127.0.0.1", protocol="udp", auto_read_tags=False)
            assert dev.tag == ""
            assert dev.long_tag == ""
            assert "Rosemount" in dev.manufacturer_name
            dev.close()

    def test_device_kwargs_passed_to_client(self) -> None:
        """Extra kwargs (e.g. timeout) are forwarded to HARTIPClient."""
        session = _build_session_init_response()
        cmd0_payload = _make_cmd0_payload()
        cmd0 = _build_mock_response(command=0, payload=cmd0_payload)
        close_resp = _build_session_close_response()

        with patch("hartip.client.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recvfrom.side_effect = [
                (session, _ADDR),
                (cmd0, _ADDR),
                (close_resp, _ADDR),
            ]
            dev = Device("127.0.0.1", protocol="udp", timeout=10.0, auto_read_tags=False)
            assert dev.client.timeout == 10.0
            dev.close()


# ---------------------------------------------------------------------------
# Public imports from top-level hartip package
# ---------------------------------------------------------------------------


class TestPublicImports:
    def test_device_importable(self) -> None:
        import hartip

        assert hartip.Device is Device

    def test_typed_dicts_importable_from_package(self) -> None:
        import hartip

        assert isinstance(hartip.Cmd2Response, type)
        assert isinstance(hartip.Cmd9Response, type)
        assert isinstance(hartip.Cmd48Response, type)
