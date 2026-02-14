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
    """Verify HART-IP status codes per TP10300 / CISAGOV / hstypes.h."""

    def test_success(self) -> None:
        assert HARTIPStatus.SUCCESS == 0

    def test_invalid_selection(self) -> None:
        # hstypes.h: HARTIP_SESS_ERR_INVALID_MASTER_TYPE = 2
        assert HARTIPStatus.ERROR_INVALID_SELECTION == 2

    def test_too_few_data_bytes(self) -> None:
        # hstypes.h: HARTIP_SESS_ERR_TOO_FEW_BYTES = 5
        assert HARTIPStatus.ERROR_TOO_FEW_DATA_BYTES == 5

    def test_device_specific(self) -> None:
        # C# HARTIPConnect: "Device Specific Command Error" = 6
        assert HARTIPStatus.ERROR_DEVICE_SPECIFIC == 6

    def test_set_to_nearest_value(self) -> None:
        # hstypes.h: HARTIP_SESS_ERR_TOO_FEW_TIME = 8 (set to nearest)
        assert HARTIPStatus.WARNING_SET_TO_NEAREST_VALUE == 8

    def test_security_not_initialized(self) -> None:
        assert HARTIPStatus.ERROR_SECURITY_NOT_INITIALIZED == 9

    def test_all_sessions_in_use(self) -> None:
        assert HARTIPStatus.ERROR_ALL_SESSIONS_IN_USE == 15

    def test_session_already_exists(self) -> None:
        # hstypes.h: HARTIP_SESS_ERR_SESSION_EXISTS = 16
        assert HARTIPStatus.ERROR_SESSION_ALREADY_EXISTS == 16

    def test_insecure_session_exists(self) -> None:
        # CISAGOV: WARNING_INSECURE_SESSION_ALREADY_EXISTS = 30
        assert HARTIPStatus.WARNING_INSECURE_SESSION_EXISTS == 30


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
    """Verify HART response codes per Spec 307 / hartdefs.h / C# HARTMessage.cs."""

    def test_success(self) -> None:
        assert HARTResponseCode.SUCCESS == 0

    def test_undefined_command(self) -> None:
        assert HARTResponseCode.UNDEFINED_COMMAND == 1

    def test_access_restricted(self) -> None:
        # hartdefs.h: RC_ACC_RESTR = 16
        assert HARTResponseCode.ACCESS_RESTRICTED == 16

    def test_response_truncated(self) -> None:
        # hartdefs.h: RC_TRUNCATED = 30
        assert HARTResponseCode.RESPONSE_TRUNCATED == 30

    def test_device_busy(self) -> None:
        # hartdefs.h: RC_BUSY = 32, C#: RSP_DEVICE_BUSY = 32
        assert HARTResponseCode.DEVICE_BUSY == 32

    def test_dr_initiated(self) -> None:
        # hartdefs.h: RC_DR_INIT = 33, C#: RSP_DR_INITIATE = 33
        assert HARTResponseCode.DR_INITIATED == 33

    def test_delayed_response_codes(self) -> None:
        assert HARTResponseCode.DR_RUNNING == 34
        assert HARTResponseCode.DR_DEAD == 35
        assert HARTResponseCode.DR_CONFLICT == 36

    def test_cmd_not_implemented(self) -> None:
        # hartdefs.h: RC_NOT_IMPLEM = 64, C#: RSP_CMD_NOT_IMPLEMENTED = 64
        assert HARTResponseCode.CMD_NOT_IMPLEMENTED == 64


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
