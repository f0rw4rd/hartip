"""
Convenience wrappers for common HART commands.

:class:`CommandsMixin` builds the request data for each command and
sends it through :meth:`send_command`, which :class:`HARTIPClient`
implements.  Address arguments default to :data:`UNSET`, meaning the
client's ``default_address`` / ``default_unique_addr``.
"""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import TYPE_CHECKING, Final

from .ascii import pack_ascii
from .constants import HARTCommand
from .device import parse_cmd0

if TYPE_CHECKING:
    from .response import HARTIPResponse


class Unset(enum.Enum):
    """Type of :data:`UNSET`."""

    UNSET = enum.auto()


UNSET: Final = Unset.UNSET
"""Address default meaning "use the client default"; ``None`` stays a real value."""


class CommandsMixin(ABC):
    """HART command wrappers on top of :meth:`send_command`."""

    default_address: int
    default_unique_addr: bytes | None

    @abstractmethod
    def send_command(
        self,
        command: int,
        address: int = 0,
        data: bytes = b"",
        use_long_frame: bool = False,
        unique_addr: bytes | None = None,
    ) -> HARTIPResponse:
        """Send a HART command and receive the response."""

    def _resolve_addr(
        self,
        address: int | Unset,
        unique_addr: bytes | Unset | None,
    ) -> tuple[int, bytes | None]:
        """Resolve address/unique_addr from explicit args or instance defaults.

        :data:`UNSET` (the default in the wrappers) selects
        ``default_address`` / ``default_unique_addr``.  An explicit value,
        including ``None``, always takes precedence.
        """
        effective_address = self.default_address if isinstance(address, Unset) else address
        effective_unique = (
            self.default_unique_addr if isinstance(unique_addr, Unset) else unique_addr
        )
        return effective_address, effective_unique

    def _send(
        self,
        command: int,
        address: int | Unset,
        unique_addr: bytes | Unset | None,
        data: bytes = b"",
    ) -> HARTIPResponse:
        addr, uniq = self._resolve_addr(address, unique_addr)
        return self.send_command(command, addr, data=data, unique_addr=uniq)

    def read_unique_id(
        self, address: int | Unset = UNSET, *, unique_addr: bytes | Unset | None = UNSET
    ) -> HARTIPResponse:
        """Command 0: Read Unique Identifier.

        On success, auto-populates :attr:`default_unique_addr` from the
        parsed response so subsequent calls can omit the address.
        """
        resp = self._send(HARTCommand.READ_UNIQUE_ID, address, unique_addr)
        if resp.success and resp.payload:
            info = parse_cmd0(resp.payload)
            if info.unique_address:
                self.default_unique_addr = info.unique_address
        return resp

    def read_primary_variable(
        self, address: int | Unset = UNSET, *, unique_addr: bytes | Unset | None = UNSET
    ) -> HARTIPResponse:
        """Command 1: Read Primary Variable."""
        return self._send(HARTCommand.READ_PRIMARY_VARIABLE, address, unique_addr)

    def read_current_and_percent(
        self, address: int | Unset = UNSET, *, unique_addr: bytes | Unset | None = UNSET
    ) -> HARTIPResponse:
        """Command 2: Read Loop Current and Percent of Range."""
        return self._send(HARTCommand.READ_CURRENT_AND_PERCENT, address, unique_addr)

    def read_dynamic_variables(
        self, address: int | Unset = UNSET, *, unique_addr: bytes | Unset | None = UNSET
    ) -> HARTIPResponse:
        """Command 3: Read Dynamic Variables."""
        return self._send(HARTCommand.READ_DYNAMIC_VARS, address, unique_addr)

    def read_device_vars_status(
        self,
        address: int | Unset = UNSET,
        *,
        device_var_codes: Sequence[int] = (0, 1, 2, 3),
        unique_addr: bytes | Unset | None = UNSET,
    ) -> HARTIPResponse:
        """Command 9: Read Device Variables with Status.

        Args:
            address: Polling address (0-63) for short frame.
            device_var_codes: Device variable codes to read (1-8 codes).
                Defaults to ``(0, 1, 2, 3)`` for PV, SV, TV, QV.
                The HART spec requires at least 1 code in the request.
            unique_addr: Explicit 5-byte unique address for long frame.

        Returns:
            Parsed :class:`HARTIPResponse`.
        """
        data = bytes(device_var_codes[:8])
        return self._send(HARTCommand.READ_DEVICE_VARS_STATUS, address, unique_addr, data)

    def write_poll_address(
        self,
        poll_address: int,
        loop_current_mode: int = 0,
        address: int | Unset = UNSET,
        *,
        unique_addr: bytes | Unset | None = UNSET,
    ) -> HARTIPResponse:
        """Command 6: Write Polling Address.

        Args:
            poll_address: New polling address (0-63).
            loop_current_mode: 0=enabled, 1=disabled.
            address: Polling address for the request frame.
            unique_addr: Explicit 5-byte unique address for long frame.
        """
        data = bytes([poll_address & 0x3F, loop_current_mode & 0x01])
        return self._send(HARTCommand.WRITE_POLL_ADDRESS, address, unique_addr, data)

    def read_loop_config(
        self, address: int | Unset = UNSET, *, unique_addr: bytes | Unset | None = UNSET
    ) -> HARTIPResponse:
        """Command 7: Read Loop Configuration."""
        return self._send(HARTCommand.READ_LOOP_CONFIG, address, unique_addr)

    def read_dynamic_var_classifications(
        self, address: int | Unset = UNSET, *, unique_addr: bytes | Unset | None = UNSET
    ) -> HARTIPResponse:
        """Command 8: Read Dynamic Variable Classifications."""
        return self._send(HARTCommand.READ_DYNAMIC_VAR_CLASSIFICATION, address, unique_addr)

    def read_message(
        self, address: int | Unset = UNSET, *, unique_addr: bytes | Unset | None = UNSET
    ) -> HARTIPResponse:
        """Command 12: Read Message (24-byte packed ASCII)."""
        return self._send(HARTCommand.READ_MESSAGE, address, unique_addr)

    def read_tag_descriptor_date(
        self, address: int | Unset = UNSET, *, unique_addr: bytes | Unset | None = UNSET
    ) -> HARTIPResponse:
        """Command 13: Read Tag, Descriptor, Date."""
        return self._send(HARTCommand.READ_TAG_DESCRIPTOR_DATE, address, unique_addr)

    def read_pv_info(
        self, address: int | Unset = UNSET, *, unique_addr: bytes | Unset | None = UNSET
    ) -> HARTIPResponse:
        """Command 14: Read Primary Variable Transducer Information."""
        return self._send(HARTCommand.READ_PRIMARY_VAR_INFO, address, unique_addr)

    def read_output_info(
        self, address: int | Unset = UNSET, *, unique_addr: bytes | Unset | None = UNSET
    ) -> HARTIPResponse:
        """Command 15: Read Output Information."""
        return self._send(HARTCommand.READ_OUTPUT_INFO, address, unique_addr)

    def read_final_assembly(
        self, address: int | Unset = UNSET, *, unique_addr: bytes | Unset | None = UNSET
    ) -> HARTIPResponse:
        """Command 16: Read Final Assembly Number."""
        return self._send(HARTCommand.READ_FINAL_ASSEMBLY, address, unique_addr)

    def write_message(
        self,
        message: str,
        address: int | Unset = UNSET,
        *,
        unique_addr: bytes | Unset | None = UNSET,
    ) -> HARTIPResponse:
        """Command 17: Write Message.

        Args:
            message: Message string (up to 32 characters, packed to 24 bytes).
            address: Polling address for the request frame.
            unique_addr: Explicit 5-byte unique address for long frame.
        """
        packed = pack_ascii(message.ljust(32)[:32])[:24]
        return self._send(HARTCommand.WRITE_MESSAGE, address, unique_addr, packed)

    def write_tag_descriptor_date(
        self,
        tag: str,
        descriptor: str,
        day: int,
        month: int,
        year: int,
        address: int | Unset = UNSET,
        *,
        unique_addr: bytes | Unset | None = UNSET,
    ) -> HARTIPResponse:
        """Command 18: Write Tag, Descriptor, Date.

        Args:
            tag: Tag string (up to 8 characters, packed to 6 bytes).
            descriptor: Descriptor string (up to 16 characters, packed to 12 bytes).
            day: Day of month (1-31).
            month: Month (1-12).
            year: Year offset from 1900 (e.g. 124 for 2024).
            address: Polling address for the request frame.
            unique_addr: Explicit 5-byte unique address for long frame.
        """
        tag_packed = pack_ascii(tag.ljust(8)[:8])[:6]
        desc_packed = pack_ascii(descriptor.ljust(16)[:16])[:12]
        data = tag_packed + desc_packed + bytes([day, month, year])
        return self._send(HARTCommand.WRITE_TAG_DESCRIPTOR_DATE, address, unique_addr, data)

    def write_final_assembly(
        self,
        assembly_number: int,
        address: int | Unset = UNSET,
        *,
        unique_addr: bytes | Unset | None = UNSET,
    ) -> HARTIPResponse:
        """Command 19: Write Final Assembly Number.

        Args:
            assembly_number: Final assembly number (0-16777215, Unsigned-24).
            address: Polling address for the request frame.
            unique_addr: Explicit 5-byte unique address for long frame.
        """
        data = assembly_number.to_bytes(3, "big")
        return self._send(HARTCommand.WRITE_FINAL_ASSEMBLY, address, unique_addr, data)

    def read_long_tag(
        self, address: int | Unset = UNSET, *, unique_addr: bytes | Unset | None = UNSET
    ) -> HARTIPResponse:
        """Command 20: Read Long Tag (HART 6+)."""
        return self._send(HARTCommand.READ_LONG_TAG, address, unique_addr)

    def read_additional_status(
        self, address: int | Unset = UNSET, *, unique_addr: bytes | Unset | None = UNSET
    ) -> HARTIPResponse:
        """Command 48: Read Additional Transmitter Status."""
        return self._send(HARTCommand.READ_ADDITIONAL_STATUS, address, unique_addr)

    def perform_self_test(
        self, address: int | Unset = UNSET, *, unique_addr: bytes | Unset | None = UNSET
    ) -> HARTIPResponse:
        """Command 41: Perform Device Self-Test."""
        return self._send(HARTCommand.PERFORM_SELF_TEST, address, unique_addr)

    def lock_device(
        self,
        lock_code: int = 1,
        address: int | Unset = UNSET,
        *,
        unique_addr: bytes | Unset | None = UNSET,
    ) -> HARTIPResponse:
        """Command 71: Lock Device.

        Args:
            lock_code: Lock code (0=Unlock, 1=Lock Temporary,
                2=Lock Permanent, 3=Lock All).
            address: Polling address for the request frame.
            unique_addr: Explicit 5-byte unique address for long frame.
        """
        data = bytes([lock_code & 0xFF])
        return self._send(HARTCommand.LOCK_DEVICE, address, unique_addr, data)

    def unlock_device(
        self,
        address: int | Unset = UNSET,
        *,
        unique_addr: bytes | Unset | None = UNSET,
    ) -> HARTIPResponse:
        """Command 71: Unlock Device (convenience for lock_device with code 0).

        Args:
            address: Polling address for the request frame.
            unique_addr: Explicit 5-byte unique address for long frame.
        """
        return self.lock_device(lock_code=0, address=address, unique_addr=unique_addr)

    def read_lock_state(
        self, address: int | Unset = UNSET, *, unique_addr: bytes | Unset | None = UNSET
    ) -> HARTIPResponse:
        """Command 76: Read Lock Device State."""
        return self._send(HARTCommand.READ_LOCK_DEVICE_STATE, address, unique_addr)
