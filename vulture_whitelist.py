"""Vulture whitelist: symbols used dynamically (dict lookup, re-export, etc.)."""

# -- parse_cmd* functions registered in COMMAND_REGISTRY dict --

# -- Friendly-name aliases (re-exports from __init__.py) --

# -- Dataclass fields accessed by users, not always by library code --
from hartip.device import DeviceInfo, DeviceVariable, Variable

DeviceInfo.manufacturer_id
DeviceInfo.manufacturer_name
DeviceInfo.device_type
DeviceInfo.expanded_device_type
DeviceInfo.device_id
DeviceInfo.unique_address
DeviceInfo.hart_revision
DeviceInfo.software_revision
DeviceInfo.device_revision
DeviceInfo.hardware_revision
DeviceInfo.physical_signaling
DeviceInfo.flags
DeviceInfo.num_preambles
DeviceInfo.num_response_preambles
DeviceInfo.max_device_vars
DeviceInfo.config_change_counter
DeviceInfo.extended_field_device_status
DeviceInfo.manufacturer_id_16bit
DeviceInfo.private_label
DeviceInfo.device_profile
DeviceInfo.tag
DeviceInfo.descriptor
DeviceInfo.date
DeviceInfo.long_tag
DeviceInfo.write_protected
DeviceInfo.config_changed
DeviceInfo.physical_signaling_name
DeviceInfo.flags_decoded
DeviceInfo.extended_device_status_decoded

Variable.value
Variable.unit_code
Variable.unit_name
Variable.label

DeviceVariable.slot
DeviceVariable.device_var_code
DeviceVariable.classification
DeviceVariable.unit_code
DeviceVariable.unit_name
DeviceVariable.value
DeviceVariable.status
DeviceVariable.classification_name
DeviceVariable.status_decoded

# -- Enum members used by callers, not always internally --

# -- Client convenience methods --
from hartip.client import HARTIPClient

HARTIPClient.read_unique_id
HARTIPClient.read_primary_variable
HARTIPClient.read_current_and_percent
HARTIPClient.read_dynamic_variables
HARTIPClient.read_device_vars_status
HARTIPClient.write_poll_address
HARTIPClient.read_loop_config
HARTIPClient.read_dynamic_var_classifications
HARTIPClient.read_message
HARTIPClient.read_tag_descriptor_date
HARTIPClient.read_pv_info
HARTIPClient.read_output_info
HARTIPClient.read_final_assembly
HARTIPClient.write_message
HARTIPClient.write_tag_descriptor_date
HARTIPClient.write_final_assembly
HARTIPClient.read_long_tag
HARTIPClient.read_additional_status
HARTIPClient.perform_self_test
HARTIPClient.lock_device
HARTIPClient.unlock_device
HARTIPClient.read_lock_state
HARTIPClient.send_direct_pdu
HARTIPClient.read_audit_log
HARTIPClient.psk_identity
HARTIPClient.psk_key
HARTIPClient.connected
HARTIPClient.session_active
HARTIPClient.default_address
HARTIPClient.default_unique_addr
HARTIPClient.server_version

# -- Standalone utility functions --
from hartip.client import probe_server_version

probe_server_version

# -- HARTIPResponse properties --
from hartip.client import HARTIPResponse

HARTIPResponse.command_number
HARTIPResponse.command_name
HARTIPResponse.parsed
HARTIPResponse.success
HARTIPResponse.error_message
HARTIPResponse.error_code
HARTIPResponse.raise_for_error

# -- v2 types --
from hartip.v2 import AuditLogResponse, DirectPDU, DirectPDUCommand, SessionLogRecord

DirectPDUCommand.is_response
DirectPDUCommand.encode_response
DirectPDU.device_status
DirectPDU.extended_status
SessionLogRecord.status_flags
SessionLogRecord.writes_occurred
SessionLogRecord.insecure
AuditLogResponse.server_status_flags

# -- Exception attributes --
from hartip.exceptions import (
    HARTChecksumError,
    HARTCommunicationError,
    HARTIPStatusError,
    HARTIPTLSError,
    HARTResponseError,
)

HARTIPTLSError.ssl_error
HARTIPStatusError.status
HARTChecksumError.expected
HARTChecksumError.actual
HARTResponseError.code
HARTResponseError.command
HARTCommunicationError.flags

# -- Constants re-exported via __init__ --

# -- Protocol re-exports --
from hartip.protocol import (
    PduContainer,
)

PduContainer.preamble_count
PduContainer.expansion_bytes

# -- ASCII helpers --

# -- Lookup tables and bitfield decoders --
from hartip.lookups import (
    ALARM_SELECTION_CODES,
    CLASSIFICATION_CODES,
    DEVICE_FAMILY_CODES,
    HART_TICKS_PER_SECOND,
    OPERATING_MODE_CODES,
    TRANSFER_FUNCTION_CODES,
    WRITE_PROTECT_CODES,
    decode_cmd0_flags,
    decode_device_status,
    decode_device_variable_status,
    decode_extended_device_status,
    decode_standardized_status_0,
    decode_standardized_status_1,
    decode_standardized_status_2,
    decode_standardized_status_3,
    get_alarm_selection_name,
    get_classification_name,
    get_device_family_name,
    get_operating_mode_name,
    get_transfer_function_name,
    get_write_protect_name,
    hart_ticks_to_seconds,
    hart_ticks_to_timedelta,
)

ALARM_SELECTION_CODES
CLASSIFICATION_CODES
DEVICE_FAMILY_CODES
HART_TICKS_PER_SECOND
OPERATING_MODE_CODES
TRANSFER_FUNCTION_CODES
WRITE_PROTECT_CODES
decode_cmd0_flags
decode_device_status
decode_device_variable_status
decode_extended_device_status
decode_standardized_status_0
decode_standardized_status_1
decode_standardized_status_2
decode_standardized_status_3
get_alarm_selection_name
get_classification_name
get_device_family_name
get_operating_mode_name
get_transfer_function_name
get_write_protect_name
hart_ticks_to_seconds
hart_ticks_to_timedelta

# -- High-level Device class --
from hartip.high_level import Device

Device.client
Device.info
Device.tag
Device.descriptor
Device.date
Device.long_tag
Device.manufacturer_name
Device.manufacturer_id
Device.device_type
Device.device_id
Device.unique_address
Device.hart_revision
Device.software_revision
Device.hardware_revision
Device.primary_variable
Device.loop_current
Device.percent_range
Device.dynamic_variables
Device.device_variables
Device.status
Device.additional_status
Device.message

# -- TypedDict response types --
from hartip.types import (
    Cmd2Response,
    Cmd3Response,
    Cmd8Response,
    Cmd9Response,
    Cmd13Response,
    Cmd15Response,
    Cmd48Response,
    Cmd54Response,
)

Cmd2Response
Cmd3Response
Cmd8Response
Cmd9Response
Cmd13Response
Cmd15Response
Cmd48Response
Cmd54Response

# -- v2 builders/parsers --
