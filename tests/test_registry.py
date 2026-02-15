"""Tests for the command registry, auto-parse, and friendly-name aliases."""

import struct
from types import SimpleNamespace

import pytest

from hartip.client import HARTIPResponse
from hartip.device import (
    COMMAND_REGISTRY,
    DeviceInfo,
    Variable,
    get_command_name,
    get_parser,
    parse_additional_device_status,
    parse_burst_mode_config,
    parse_cmd0,
    parse_cmd1,
    parse_cmd2,
    parse_cmd3,
    parse_cmd7,
    parse_cmd8,
    parse_cmd9,
    parse_cmd12,
    parse_cmd13,
    parse_cmd14,
    parse_cmd15,
    parse_cmd16,
    parse_cmd20,
    parse_cmd33,
    parse_cmd38,
    parse_cmd48,
    parse_cmd54,
    parse_cmd105,
    parse_cmd512,
    parse_cmd534,
    parse_command,
    parse_country_code,
    parse_current_and_percent,
    parse_device_variable_info,
    parse_device_variable_simulation_status,
    parse_device_variables,
    parse_device_variables_with_status,
    parse_dynamic_variable_classifications,
    parse_dynamic_variables,
    parse_final_assembly_number,
    parse_long_tag,
    parse_loop_configuration,
    parse_message,
    parse_output_info,
    parse_polling_address,
    parse_primary_variable,
    parse_pv_transducer_info,
    parse_reset_config_flag,
    parse_tag_descriptor_date,
    # Friendly-name aliases
    parse_unique_id,
    parse_unique_id_by_tag,
)

# ---------------------------------------------------------------------------
# Helpers: build realistic payloads for testing
# ---------------------------------------------------------------------------


def _cmd0_payload() -> bytes:
    """Build a minimal 12-byte Command 0 response payload."""
    return bytes(
        [
            0xFE,  # expansion code
            0x26,  # manufacturer_id
            0x4E,  # device_type
            0x05,  # preambles
            0x07,  # HART rev 7
            0x01,  # device_rev
            0x04,  # software_rev
            0x08,  # hardware_rev | physical_signaling
            0x0E,  # flags
            0x00,
            0x00,
            0xF0,  # device_id
        ]
    )


def _cmd1_payload() -> bytes:
    """Build a 5-byte Command 1 payload: unit_code(1) + float(4)."""
    return bytes([0x07]) + struct.pack(">f", 25.5)


def _cmd3_payload() -> bytes:
    """Build a Command 3 payload: current(4) + 1 variable (unit+float)."""
    current = struct.pack(">f", 12.0)
    var = bytes([0x07]) + struct.pack(">f", 25.5)
    return current + var


def _cmd48_payload() -> bytes:
    """Build a 9-byte Command 48 payload."""
    return bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02])


def _make_response(command: int, payload: bytes = b"") -> HARTIPResponse:
    """Create an HARTIPResponse with a given command number and payload."""
    pdu = SimpleNamespace(command=command)
    return HARTIPResponse(header=None, pdu=pdu, payload=payload)


# ---------------------------------------------------------------------------
# COMMAND_REGISTRY
# ---------------------------------------------------------------------------


class TestCommandRegistry:
    """Tests for the COMMAND_REGISTRY dict."""

    def test_registry_is_dict(self) -> None:
        assert isinstance(COMMAND_REGISTRY, dict)

    def test_registry_has_universal_commands(self) -> None:
        for cmd in (0, 1, 2, 3, 7, 8, 9, 12, 13, 14, 15, 16, 20, 48):
            assert cmd in COMMAND_REGISTRY, f"Command {cmd} missing"

    def test_registry_has_common_practice_commands(self) -> None:
        for cmd in (33, 35, 38, 44, 52, 53, 54, 79, 90, 95):
            assert cmd in COMMAND_REGISTRY, f"Command {cmd} missing"

    def test_registry_has_burst_commands(self) -> None:
        for cmd in (103, 104, 105, 107, 108, 109):
            assert cmd in COMMAND_REGISTRY, f"Command {cmd} missing"

    def test_registry_has_device_specific(self) -> None:
        for cmd in (512, 513, 534):
            assert cmd in COMMAND_REGISTRY, f"Command {cmd} missing"

    def test_registry_has_alias_commands(self) -> None:
        """Commands that share parsers (6->7, 11->0, 17->12, etc.)."""
        for cmd in (6, 11, 17, 18, 19, 21, 22):
            assert cmd in COMMAND_REGISTRY, f"Alias command {cmd} missing"

    def test_registry_entries_are_tuples(self) -> None:
        for cmd, entry in COMMAND_REGISTRY.items():
            assert isinstance(entry, tuple), f"Command {cmd}: not a tuple"
            assert len(entry) == 2, f"Command {cmd}: tuple length != 2"
            assert callable(entry[0]), f"Command {cmd}: parser not callable"
            assert isinstance(entry[1], str), f"Command {cmd}: name not str"

    def test_registry_count(self) -> None:
        # 40 registered commands
        assert len(COMMAND_REGISTRY) == 40


# ---------------------------------------------------------------------------
# get_parser / get_command_name / parse_command
# ---------------------------------------------------------------------------


class TestGetParser:
    def test_known_command(self) -> None:
        assert get_parser(0) is parse_cmd0
        assert get_parser(1) is parse_cmd1
        assert get_parser(48) is parse_cmd48

    def test_unknown_command(self) -> None:
        assert get_parser(999) is None
        assert get_parser(-1) is None

    def test_alias_commands(self) -> None:
        """Command 6 and 7 share the same parser."""
        assert get_parser(6) is parse_cmd7
        assert get_parser(11) is parse_cmd0


class TestGetCommandName:
    def test_known_commands(self) -> None:
        assert get_command_name(0) == "read_unique_id"
        assert get_command_name(1) == "read_primary_variable"
        assert get_command_name(48) == "read_additional_device_status"
        assert get_command_name(54) == "read_device_variable_info"
        assert get_command_name(105) == "read_burst_mode_config"

    def test_unknown_command(self) -> None:
        assert get_command_name(999) == "unknown_cmd_999"
        assert get_command_name(-1) == "unknown_cmd_-1"


class TestParseCommand:
    def test_cmd0(self) -> None:
        result = parse_command(0, _cmd0_payload())
        assert isinstance(result, DeviceInfo)
        assert result.manufacturer_id == 0x26
        assert result.hart_revision == 7

    def test_cmd1(self) -> None:
        result = parse_command(1, _cmd1_payload())
        assert isinstance(result, Variable)
        assert result.unit_code == 0x07
        assert abs(result.value - 25.5) < 0.01

    def test_cmd48(self) -> None:
        result = parse_command(48, _cmd48_payload())
        assert isinstance(result, dict)
        assert "device_specific_status" in result

    def test_unknown_command(self) -> None:
        assert parse_command(999, b"\x01\x02") is None

    def test_empty_payload(self) -> None:
        # parse_cmd0 with empty payload returns empty DeviceInfo
        result = parse_command(0, b"")
        assert isinstance(result, DeviceInfo)
        assert result.manufacturer_id == 0


# ---------------------------------------------------------------------------
# Friendly-name aliases
# ---------------------------------------------------------------------------


class TestFriendlyNames:
    """Verify every friendly name alias is the same function as the cmdNN version."""

    def test_parse_unique_id(self) -> None:
        assert parse_unique_id is parse_cmd0

    def test_parse_primary_variable(self) -> None:
        assert parse_primary_variable is parse_cmd1

    def test_parse_current_and_percent(self) -> None:
        assert parse_current_and_percent is parse_cmd2

    def test_parse_dynamic_variables(self) -> None:
        assert parse_dynamic_variables is parse_cmd3

    def test_parse_polling_address(self) -> None:
        assert parse_polling_address is parse_cmd7  # cmd6 is cmd7 alias

    def test_parse_loop_configuration(self) -> None:
        assert parse_loop_configuration is parse_cmd7

    def test_parse_dynamic_variable_classifications(self) -> None:
        assert parse_dynamic_variable_classifications is parse_cmd8

    def test_parse_device_variables_with_status(self) -> None:
        assert parse_device_variables_with_status is parse_cmd9

    def test_parse_unique_id_by_tag(self) -> None:
        assert parse_unique_id_by_tag is parse_cmd0  # cmd11 is cmd0 alias

    def test_parse_message(self) -> None:
        assert parse_message is parse_cmd12

    def test_parse_tag_descriptor_date(self) -> None:
        assert parse_tag_descriptor_date is parse_cmd13

    def test_parse_pv_transducer_info(self) -> None:
        assert parse_pv_transducer_info is parse_cmd14

    def test_parse_output_info(self) -> None:
        assert parse_output_info is parse_cmd15

    def test_parse_final_assembly_number(self) -> None:
        assert parse_final_assembly_number is parse_cmd16

    def test_parse_long_tag(self) -> None:
        assert parse_long_tag is parse_cmd20

    def test_parse_device_variables(self) -> None:
        assert parse_device_variables is parse_cmd33

    def test_parse_reset_config_flag(self) -> None:
        assert parse_reset_config_flag is parse_cmd38

    def test_parse_additional_device_status(self) -> None:
        assert parse_additional_device_status is parse_cmd48

    def test_parse_device_variable_info(self) -> None:
        assert parse_device_variable_info is parse_cmd54

    def test_parse_burst_mode_config(self) -> None:
        assert parse_burst_mode_config is parse_cmd105

    def test_parse_country_code(self) -> None:
        assert parse_country_code is parse_cmd512

    def test_parse_device_variable_simulation_status(self) -> None:
        assert parse_device_variable_simulation_status is parse_cmd534

    def test_friendly_names_callable(self) -> None:
        """All friendly names produce the same result as parse_cmdNN."""
        payload = _cmd0_payload()
        r1 = parse_cmd0(payload)
        r2 = parse_unique_id(payload)
        assert r1.manufacturer_id == r2.manufacturer_id
        assert r1.device_id == r2.device_id


# ---------------------------------------------------------------------------
# HARTIPResponse.parsed (auto-parse)
# ---------------------------------------------------------------------------


class TestAutoParseResponse:
    """Tests for HARTIPResponse.parsed property."""

    def test_auto_parse_cmd0(self) -> None:
        resp = _make_response(0, _cmd0_payload())
        info = resp.parsed
        assert isinstance(info, DeviceInfo)
        assert info.manufacturer_id == 0x26
        assert info.hart_revision == 7

    def test_auto_parse_cmd1(self) -> None:
        resp = _make_response(1, _cmd1_payload())
        var = resp.parsed
        assert isinstance(var, Variable)
        assert abs(var.value - 25.5) < 0.01

    def test_auto_parse_cmd3(self) -> None:
        resp = _make_response(3, _cmd3_payload())
        data = resp.parsed
        assert isinstance(data, dict)
        assert "loop_current" in data
        assert "variables" in data

    def test_auto_parse_cmd48(self) -> None:
        resp = _make_response(48, _cmd48_payload())
        data = resp.parsed
        assert isinstance(data, dict)
        assert "device_specific_status" in data

    def test_auto_parse_caching(self) -> None:
        """Parsed result should be cached (same object on second access)."""
        resp = _make_response(0, _cmd0_payload())
        first = resp.parsed
        second = resp.parsed
        assert first is second

    def test_auto_parse_unknown_command(self) -> None:
        resp = _make_response(999, b"\x01\x02\x03")
        assert resp.parsed is None

    def test_auto_parse_no_pdu(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None)
        assert resp.parsed is None

    def test_auto_parse_empty_payload(self) -> None:
        resp = _make_response(0, b"")
        # Empty payload => parse_cmd0 returns default DeviceInfo, but
        # auto-parse returns None because payload is empty (falsy).
        assert resp.parsed is None

    def test_auto_parse_none_cached_for_unknown(self) -> None:
        """Verify None result is also cached (not re-computed)."""
        resp = _make_response(999, b"\x01\x02")
        assert resp.parsed is None
        # Access again -- should not fail
        assert resp.parsed is None


# ---------------------------------------------------------------------------
# HARTIPResponse.command_number / command_name
# ---------------------------------------------------------------------------


class TestResponseCommandProperties:
    def test_command_number(self) -> None:
        resp = _make_response(48, b"\x00" * 6)
        assert resp.command_number == 48

    def test_command_number_no_pdu(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None)
        assert resp.command_number is None

    def test_command_name_known(self) -> None:
        resp = _make_response(0, _cmd0_payload())
        assert resp.command_name == "read_unique_id"

    def test_command_name_cmd48(self) -> None:
        resp = _make_response(48, b"\x00" * 6)
        assert resp.command_name == "read_additional_device_status"

    def test_command_name_unknown(self) -> None:
        resp = _make_response(999, b"\x01")
        assert resp.command_name == "unknown_cmd_999"

    def test_command_name_no_pdu(self) -> None:
        resp = HARTIPResponse(header=None, pdu=None)
        assert resp.command_name == "unknown"


# ---------------------------------------------------------------------------
# Top-level imports from hartip package
# ---------------------------------------------------------------------------


class TestTopLevelImports:
    """Verify the new symbols are importable from the top-level package."""

    def test_registry_import(self) -> None:
        from hartip import COMMAND_REGISTRY

        assert isinstance(COMMAND_REGISTRY, dict)

    def test_get_parser_import(self) -> None:
        from hartip import get_parser

        assert callable(get_parser)

    def test_get_command_name_import(self) -> None:
        from hartip import get_command_name

        assert callable(get_command_name)

    def test_parse_command_import(self) -> None:
        from hartip import parse_command

        assert callable(parse_command)

    def test_friendly_name_imports(self) -> None:
        from hartip import (
            parse_additional_device_status,
            parse_burst_mode_config,
            parse_device_variable_info,
            parse_primary_variable,
            parse_unique_id,
        )

        assert callable(parse_unique_id)
        assert callable(parse_primary_variable)
        assert callable(parse_additional_device_status)
        assert callable(parse_device_variable_info)
        assert callable(parse_burst_mode_config)

    def test_all_friendly_names_in_all(self) -> None:
        import hartip

        expected = [
            "parse_unique_id",
            "parse_primary_variable",
            "parse_current_and_percent",
            "parse_dynamic_variables",
            "parse_additional_device_status",
            "parse_device_variable_info",
            "parse_burst_mode_config",
            "parse_country_code",
            "COMMAND_REGISTRY",
            "get_parser",
            "get_command_name",
            "parse_command",
        ]
        for name in expected:
            assert name in hartip.__all__, f"{name} not in __all__"

    def test_backward_compat_parse_cmd_in_all(self) -> None:
        """Old parse_cmdNN names are still in __all__."""
        import hartip

        for name in ("parse_cmd0", "parse_cmd1", "parse_cmd48", "parse_cmd534"):
            assert name in hartip.__all__, f"{name} not in __all__"


# ---------------------------------------------------------------------------
# Registry consistency: every parser in the registry is actually callable
# and maps to the correct function
# ---------------------------------------------------------------------------


class TestRegistryConsistency:
    def test_every_registry_parser_is_importable(self) -> None:
        """Every parser function in the registry should be accessible."""
        for cmd, (parser, name) in COMMAND_REGISTRY.items():
            assert callable(parser), f"cmd {cmd}: parser not callable"
            assert len(name) > 0, f"cmd {cmd}: empty friendly name"

    def test_friendly_name_uniqueness(self) -> None:
        """No two commands should share the same friendly name."""
        names = [entry[1] for entry in COMMAND_REGISTRY.values()]
        assert len(names) == len(set(names)), "Duplicate friendly names found"

    @pytest.mark.parametrize(
        "cmd,expected_name",
        [
            (0, "read_unique_id"),
            (1, "read_primary_variable"),
            (2, "read_current_and_percent"),
            (3, "read_dynamic_variables"),
            (6, "write_polling_address"),
            (7, "read_loop_configuration"),
            (8, "read_dynamic_variable_classifications"),
            (9, "read_device_variables_with_status"),
            (11, "read_unique_id_by_tag"),
            (12, "read_message"),
            (13, "read_tag_descriptor_date"),
            (14, "read_pv_transducer_info"),
            (15, "read_output_info"),
            (16, "read_final_assembly_number"),
            (20, "read_long_tag"),
            (33, "read_device_variables"),
            (48, "read_additional_device_status"),
            (54, "read_device_variable_info"),
            (105, "read_burst_mode_config"),
            (512, "read_country_code"),
            (534, "read_device_variable_simulation_status"),
        ],
    )
    def test_command_name_mapping(self, cmd: int, expected_name: str) -> None:
        assert get_command_name(cmd) == expected_name
