"""Typed response dictionaries for HART command parsers.

These :class:`~typing.TypedDict` definitions describe the ``dict`` values
returned by the ``parse_cmdNN`` family of functions and the status-byte
decoders in :mod:`hartip.lookups`.  At runtime the values are plain dicts.

A parser that receives a payload too short for its command returns an
empty dict, typed as :class:`EmptyResponse`.  Keys that depend on the
payload length are declared in a ``total=False`` subclass and may be
absent.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, NoReturn, Optional, TypeAlias, TypedDict

if TYPE_CHECKING:
    from .device import DeviceVariable, Variable


EmptyResponse: TypeAlias = Dict[str, NoReturn]
"""Returned by a parser when the payload is too short to decode: ``{}``.

The value type is ``NoReturn`` because looking up any key raises
``KeyError``.  Unlike an empty ``TypedDict`` it does not absorb the
``CmdNResponse`` types in ``CmdNResponse | EmptyResponse``, so indexing
such a result gives the field's own type.  Test ``if result:`` or
``"key" in result`` before indexing.
"""


# -- Status byte decoders (hartip.lookups) ----------------------------------


class DeviceVariableStatus(TypedDict):
    """Return type of :func:`~hartip.lookups.decode_device_variable_status`."""

    process_data_status: int
    process_data_status_name: str
    limit_status: int
    limit_status_name: str
    more_device_variable_status_available: bool
    device_family_specific_status: int


class StandardizedStatus1(TypedDict):
    """Return type of :func:`~hartip.lookups.decode_standardized_status_1`."""

    undefined_bits: int
    reserved: bool
    battery_or_power_supply_needs_maintenance: bool
    event_notification_overflow: bool
    discrete_variable_simulation_active: bool
    status_simulation_active: bool


class StandardizedStatus2(TypedDict):
    """Return type of :func:`~hartip.lookups.decode_standardized_status_2`."""

    undefined_bits: int
    stale_data_notice: bool
    sub_device_with_duplicate_id: bool
    sub_device_mismatch: bool
    duplicate_master_detected: bool
    sub_device_list_changed: bool


class StandardizedStatus3(TypedDict):
    """Return type of :func:`~hartip.lookups.decode_standardized_status_3`."""

    undefined_bits: int
    radio_failure: bool
    block_transfer_pending: bool
    bandwidth_allocation_pending: bool
    reserved: bool
    capacity_denied: bool


# -- Universal commands -----------------------------------------------------


class Cmd2Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd2`."""

    current_mA: float
    percent_range: float


class Cmd3Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd3`."""

    loop_current: float
    variables: List[Variable]


class Cmd7Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd7` (and Command 6)."""

    polling_address: int
    loop_current_mode: int


class Cmd8Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd8`."""

    pv_classification: int
    pv_classification_name: str
    sv_classification: int
    sv_classification_name: str
    tv_classification: int
    tv_classification_name: str
    qv_classification: int
    qv_classification_name: str


class Cmd9Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd9`."""

    extended_device_status: int
    extended_device_status_decoded: dict[str, bool]
    variables: List[DeviceVariable]
    timestamp: Optional[bytes]
    timestamp_seconds: Optional[float]


class Cmd13Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd13` (and Command 18)."""

    tag: str
    descriptor: str
    date: str


class Cmd14Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd14`."""

    transducer_serial_number: int
    unit_code: int
    unit_name: str
    upper_transducer_limit: float
    lower_transducer_limit: float
    minimum_span: float


class Cmd15Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd15`."""

    alarm_selection_code: int
    alarm_selection_name: str
    transfer_function_code: int
    transfer_function_name: str
    range_units_code: int
    range_unit_name: str
    upper_range_value: float
    lower_range_value: float
    damping_value: float
    write_protect_code: int
    write_protect_name: str
    analog_channel_flags: int


class Cmd16Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd16` (and Command 19)."""

    final_assembly_number: int


class _Cmd48Base(TypedDict):
    device_specific_status: bytes


class Cmd48Response(_Cmd48Base, total=False):
    """Return type of :func:`~hartip.device.parse_cmd48`.

    Only ``device_specific_status`` is always present; the other keys
    depend on the payload length.
    """

    extended_device_status: int
    extended_device_status_decoded: dict[str, bool]
    operating_mode: int
    operating_mode_name: str
    standardized_status_0: int
    standardized_status_0_decoded: dict[str, bool]
    standardized_status_1: int
    standardized_status_1_decoded: StandardizedStatus1
    analog_channel_saturated: int
    standardized_status_2: int
    standardized_status_2_decoded: StandardizedStatus2
    standardized_status_3: int
    standardized_status_3_decoded: StandardizedStatus3
    analog_channel_fixed: int
    additional_device_specific_status: bytes


# -- Common-practice commands -----------------------------------------------


class Cmd33Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd33`."""

    variables: List[Variable]


class Cmd35Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd35`."""

    range_value_units: int
    range_unit_name: str
    upper_range_value: float
    lower_range_value: float


class Cmd38Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd38`."""

    configuration_change_counter: int


class Cmd44Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd44`."""

    pv_units_code: int
    pv_unit_name: str


class Cmd52Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd52`."""

    device_variable_code: int


class Cmd53Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd53`."""

    device_variable_code: int
    units_code: int
    unit_name: str


class _Cmd54Base(TypedDict):
    device_variable_code: int
    sensor_serial_number: int
    units_code: int
    unit_name: str


class Cmd54Response(_Cmd54Base, total=False):
    """Return type of :func:`~hartip.device.parse_cmd54`.

    The first four keys are always present; the rest depend on the
    payload length.
    """

    upper_sensor_limit: float
    lower_sensor_limit: float
    damping_value: float
    minimum_span: float
    classification: int
    classification_name: str
    device_family: int
    device_family_name: str
    acquisition_period: int
    acquisition_period_seconds: float
    properties: int


class Cmd71Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd71`."""

    lock_code: int


class Cmd76Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd76`."""

    lock_status: int
    device_locked: bool
    lock_permanent: bool
    lock_primary: bool
    configuration_locked: bool
    lock_gateway: bool


class Cmd79Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd79` and ``parse_cmd534``."""

    device_variable_code: int
    write_dv_command_code: int
    simulation_units_code: int
    simulation_unit_name: str
    simulation_value: float
    device_family: int
    device_family_name: str


class Cmd90Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd90`."""

    device_date_day: int
    device_date_month: int
    device_date_year: int
    device_timestamp: int
    device_timestamp_seconds: float
    last_received_date_day: int
    last_received_date_month: int
    last_received_date_year: int
    last_received_timestamp: int
    last_received_timestamp_seconds: float
    rtc_flags: int


class Cmd95Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd95`."""

    stx_count: int
    ack_count: int
    nak_count: int


class Cmd103Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd103`."""

    burst_message_number: int
    burst_comm_period: int
    burst_comm_period_seconds: float
    max_burst_comm_period: int
    max_burst_comm_period_seconds: float


class Cmd104Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd104`."""

    burst_message_number: int
    trigger_mode: int
    trigger_classification: int
    trigger_classification_name: str
    trigger_units_code: int
    trigger_unit_name: str
    trigger_value: float


class _Cmd105Base(TypedDict):
    burst_mode_control: int
    command_number_legacy: int


class Cmd105Response(_Cmd105Base, total=False):
    """Return type of :func:`~hartip.device.parse_cmd105`.

    The first two keys are always present; the rest depend on the
    payload length.
    """

    device_variable_index_list: List[int]
    burst_message_number: int
    max_burst_messages: int
    command_number: int
    burst_comm_period: int
    burst_comm_period_seconds: float
    max_burst_comm_period: int
    max_burst_comm_period_seconds: float
    trigger_mode: int
    trigger_classification: int
    trigger_classification_name: str
    trigger_units_code: int
    trigger_unit_name: str
    trigger_value: float


class Cmd107Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd107`."""

    device_variable_index_list: List[int]
    burst_message_number: int


class _Cmd108Base(TypedDict):
    command_number: int


class Cmd108Response(_Cmd108Base, total=False):
    """Return type of :func:`~hartip.device.parse_cmd108`.

    ``burst_message_number`` is absent in the 1-byte legacy reply.
    """

    burst_message_number: int


class _Cmd109Base(TypedDict):
    burst_mode_control: int


class Cmd109Response(_Cmd109Base, total=False):
    """Return type of :func:`~hartip.device.parse_cmd109`.

    ``burst_message_number`` is absent in the 1-byte legacy reply.
    """

    burst_message_number: int


# -- Device-specific commands -----------------------------------------------


class Cmd512Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd512` (and Command 513)."""

    country_code: int
    si_units_code: int


Cmd534Response = Cmd79Response
"""Return type of :func:`~hartip.device.parse_cmd534` (same layout as Command 79)."""
