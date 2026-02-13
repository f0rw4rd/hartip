"""Tests for HART constants and enumerations."""

from hartip.constants import (
    CMD_EXTENDED_CMD,
    COMM_ERROR_MASK,
    DR_MAX_RETRIES,
    DR_RETRY_CODES,
    DR_RETRY_DELAY_MS,
    HARTIP_HEADER_SIZE,
    HARTIP_TCP_PORT,
    HARTIP_UDP_PORT,
    MAX_SINGLE_BYTE_CMD,
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


class TestHARTIPMessageType:
    def test_request(self) -> None:
        assert HARTIPMessageType.REQUEST == 0

    def test_response(self) -> None:
        assert HARTIPMessageType.RESPONSE == 1

    def test_publish(self) -> None:
        assert HARTIPMessageType.PUBLISH == 2

    def test_error(self) -> None:
        assert HARTIPMessageType.ERROR == 3

    def test_nak(self) -> None:
        assert HARTIPMessageType.NAK == 15


class TestHARTIPMessageID:
    def test_session_initiate(self) -> None:
        assert HARTIPMessageID.SESSION_INITIATE == 0

    def test_session_close(self) -> None:
        assert HARTIPMessageID.SESSION_CLOSE == 1

    def test_keep_alive(self) -> None:
        assert HARTIPMessageID.KEEP_ALIVE == 2

    def test_hart_pdu(self) -> None:
        assert HARTIPMessageID.HART_PDU == 3

    def test_direct_pdu(self) -> None:
        assert HARTIPMessageID.DIRECT_PDU == 4

    def test_read_audit_log(self) -> None:
        assert HARTIPMessageID.READ_AUDIT_LOG == 5


class TestHARTIPStatus:
    def test_success(self) -> None:
        assert HARTIPStatus.SUCCESS == 0

    def test_invalid_session(self) -> None:
        assert HARTIPStatus.INVALID_SESSION == 5

    def test_buffer_overflow(self) -> None:
        assert HARTIPStatus.BUFFER_OVERFLOW == 8

    def test_security_not_initialized(self) -> None:
        assert HARTIPStatus.ERROR_SECURITY_NOT_INITIALIZED == 9

    def test_all_sessions_in_use(self) -> None:
        assert HARTIPStatus.ERROR_ALL_SESSIONS_IN_USE == 15

    def test_access_restricted(self) -> None:
        assert HARTIPStatus.ERROR_ACCESS_RESTRICTED == 16


class TestHARTFrameType:
    def test_short_frame(self) -> None:
        assert HARTFrameType.SHORT_FRAME == 0x02

    def test_long_frame(self) -> None:
        assert HARTFrameType.LONG_FRAME == 0x82

    def test_ack_short(self) -> None:
        assert HARTFrameType.ACK_SHORT == 0x06

    def test_ack_long(self) -> None:
        assert HARTFrameType.ACK_LONG == 0x86

    def test_burst_short(self) -> None:
        assert HARTFrameType.BURST_SHORT == 0x01

    def test_burst_long(self) -> None:
        assert HARTFrameType.BURST_LONG == 0x81


class TestHARTCommand:
    def test_universal_commands(self) -> None:
        assert HARTCommand.READ_UNIQUE_ID == 0
        assert HARTCommand.READ_PRIMARY_VARIABLE == 1
        assert HARTCommand.READ_DYNAMIC_VARS == 3
        assert HARTCommand.READ_TAG_DESCRIPTOR_DATE == 13
        assert HARTCommand.READ_OUTPUT_INFO == 15

    def test_common_practice_commands(self) -> None:
        assert HARTCommand.READ_LONG_TAG == 20
        assert HARTCommand.PERFORM_SELF_TEST == 41
        assert HARTCommand.PERFORM_MASTER_RESET == 42
        assert HARTCommand.READ_ADDITIONAL_STATUS == 48
        assert HARTCommand.LOCK_DEVICE == 71
        assert HARTCommand.SQUAWK == 72
        assert HARTCommand.SET_REAL_TIME_CLOCK == 89

    def test_wirelesshart_commands(self) -> None:
        assert HARTCommand.READ_NETWORK_ID == 768


class TestHARTResponseCode:
    def test_success(self) -> None:
        assert HARTResponseCode.SUCCESS == 0

    def test_undefined_command(self) -> None:
        assert HARTResponseCode.UNDEFINED_COMMAND == 1

    def test_delayed_response_codes(self) -> None:
        assert HARTResponseCode.DR_RUNNING == 34
        assert HARTResponseCode.DR_DEAD == 35
        assert HARTResponseCode.DR_CONFLICT == 36
        assert HARTResponseCode.DELAYED_RESPONSE_INITIATED == 65
        assert HARTResponseCode.DELAYED_RESPONSE_COMPLETED == 66


class TestHARTCommErrorFlags:
    def test_flag_values(self) -> None:
        assert HARTCommErrorFlags.BUFFER_OVERFLOW == 0x02
        assert HARTCommErrorFlags.LONGITUDINAL_PARITY == 0x08
        assert HARTCommErrorFlags.FRAMING_ERROR == 0x10
        assert HARTCommErrorFlags.OVERRUN_ERROR == 0x20
        assert HARTCommErrorFlags.VERTICAL_PARITY == 0x40

    def test_flag_combination(self) -> None:
        combined = HARTCommErrorFlags.BUFFER_OVERFLOW | HARTCommErrorFlags.FRAMING_ERROR
        assert HARTCommErrorFlags.BUFFER_OVERFLOW in combined
        assert HARTCommErrorFlags.FRAMING_ERROR in combined
        assert HARTCommErrorFlags.OVERRUN_ERROR not in combined


class TestConstants:
    def test_ports(self) -> None:
        assert HARTIP_UDP_PORT == 5094
        assert HARTIP_TCP_PORT == 5094

    def test_header_size(self) -> None:
        assert HARTIP_HEADER_SIZE == 8

    def test_extended_cmd(self) -> None:
        assert CMD_EXTENDED_CMD == 31
        assert MAX_SINGLE_BYTE_CMD == 253

    def test_comm_error_mask(self) -> None:
        assert COMM_ERROR_MASK == 0x80

    def test_dr_retry_codes(self) -> None:
        assert 32 in DR_RETRY_CODES
        assert 33 in DR_RETRY_CODES
        assert 34 in DR_RETRY_CODES
        assert 36 in DR_RETRY_CODES
        # DR_DEAD (35) is NOT retried
        assert 35 not in DR_RETRY_CODES

    def test_dr_defaults(self) -> None:
        assert DR_MAX_RETRIES == 100
        assert DR_RETRY_DELAY_MS == 20
