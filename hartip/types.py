"""Typed response dictionaries for HART command parsers.

These :class:`~typing.TypedDict` definitions provide autocomplete and static
type checking for the ``dict`` values returned by the ``parse_cmdNN`` family
of functions.  The runtime return values are unchanged -- these are purely
for developer ergonomics.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional, TypedDict

if TYPE_CHECKING:
    from .device import DeviceVariable, Variable


# -- Command 2: Read Loop Current and Percent of Range ----------------------


class Cmd2Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd2`."""

    current_mA: float
    percent_range: float


# -- Command 3: Read Dynamic Variables --------------------------------------


class Cmd3Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd3`."""

    loop_current: float
    variables: List[Variable]


# -- Command 8: Read Dynamic Variable Classifications -----------------------


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


# -- Command 9: Read Device Variables with Status ---------------------------


class Cmd9Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd9`."""

    extended_device_status: int
    extended_device_status_decoded: dict
    variables: List[DeviceVariable]
    timestamp: Optional[bytes]
    timestamp_seconds: Optional[float]


# -- Command 13: Read Tag, Descriptor, Date ---------------------------------


class Cmd13Response(TypedDict):
    """Return type of :func:`~hartip.device.parse_cmd13`."""

    tag: str
    descriptor: str
    date: str


# -- Command 15: Read Output Information ------------------------------------


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


# -- Command 48: Read Additional Device Status (partial) --------------------


class Cmd48Response(TypedDict, total=False):
    """Return type of :func:`~hartip.device.parse_cmd48`.

    Many fields are optional because they depend on payload length.
    ``total=False`` means all keys are optional.
    """

    device_specific_status: bytes
    extended_device_status: int
    extended_device_status_decoded: dict
    operating_mode: int
    operating_mode_name: str
    standardized_status_0: int
    standardized_status_0_decoded: dict
    standardized_status_1: int
    standardized_status_1_decoded: dict
    analog_channel_saturated: int
    standardized_status_2: int
    standardized_status_2_decoded: dict
    standardized_status_3: int
    standardized_status_3_decoded: dict
    analog_channel_fixed: int
    additional_device_specific_status: bytes


# -- Command 54: Read Device Variable Information (partial) -----------------


class Cmd54Response(TypedDict, total=False):
    """Return type of :func:`~hartip.device.parse_cmd54`.

    Many fields are optional because they depend on payload length.
    """

    device_variable_code: int
    sensor_serial_number: int
    units_code: int
    unit_name: str
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
