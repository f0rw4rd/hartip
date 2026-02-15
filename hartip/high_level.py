"""High-level ``Device`` wrapper for simplified HART-IP interaction.

Provides a clean, property-based API that hides the low-level HART command
framing.  Identity information (Command 0/13/20) is read once during
construction and cached.  Process values (Commands 1/2/3/9/48) are read
fresh on each access to avoid serving stale data.

Example::

    from hartip import Device

    with Device("192.168.1.100") as dev:
        print(dev.tag, dev.manufacturer_name)
        print(dev.primary_variable)        # Variable(value=25.3, ...)
        print(dev.loop_current)            # 12.5
        print(dev.device_variables([0,1])) # [DeviceVariable(...), ...]
"""

from __future__ import annotations

import logging
from typing import Any, Optional, Sequence

from .client import HARTIPClient
from .device import DeviceInfo, DeviceVariable, Variable

logger = logging.getLogger(__name__)


class Device:
    """Friendly, high-level wrapper around :class:`HARTIPClient`.

    On construction (or on :meth:`open`), the device connects and reads
    identity information via Commands 0, 13, and 20.  Cached identity
    properties are available immediately; live process-value properties
    make a network call on each access.

    Args:
        host: Device hostname or IP address.
        port: HART-IP port (default 5094).
        auto_read_tags: If ``True`` (default), Command 13 and 20 are
            issued during :meth:`open` to populate :attr:`tag`,
            :attr:`descriptor`, :attr:`date`, and :attr:`long_tag`.
        **kwargs: Forwarded to :class:`HARTIPClient` (e.g. ``protocol``,
            ``version``, ``timeout``, ``tls``, ``starttls``,
            ``psk_identity``, ``psk_key``, ``ssl_context``,
            ``auto_keepalive``).
    """

    def __init__(
        self,
        host: str,
        port: int = 5094,
        *,
        auto_read_tags: bool = True,
        **kwargs: Any,
    ) -> None:
        self._client = HARTIPClient(host, port=port, **kwargs)
        self._info: DeviceInfo = DeviceInfo()
        self._auto_read_tags = auto_read_tags
        self.open()

    # -- lifecycle -----------------------------------------------------------

    def open(self) -> None:
        """Connect to the device and read identity information.

        Called automatically by ``__init__``.  Safe to call again after
        :meth:`close` to reconnect.
        """
        self._client.connect()

        # Command 0 -- read unique ID (also sets default_unique_addr)
        resp = self._client.read_unique_id()
        if resp.success and resp.parsed is not None:
            self._info = resp.parsed
        else:
            logger.warning("Command 0 did not return valid identity")

        if self._auto_read_tags:
            self._read_tags()

    def _read_tags(self) -> None:
        """Issue Commands 13 and 20 to populate tag / long_tag fields."""
        # Command 13 -- tag, descriptor, date
        try:
            resp13 = self._client.read_tag_descriptor_date()
            if resp13.success and resp13.parsed:
                data = resp13.parsed
                self._info.tag = data.get("tag", "")
                self._info.descriptor = data.get("descriptor", "")
                self._info.date = data.get("date", "")
        except Exception:
            logger.debug("Command 13 failed, tag/descriptor unavailable", exc_info=True)

        # Command 20 -- long tag (HART 6+)
        try:
            resp20 = self._client.read_long_tag()
            if resp20.success and resp20.parsed is not None:
                self._info.long_tag = resp20.parsed
        except Exception:
            logger.debug("Command 20 failed, long_tag unavailable", exc_info=True)

    def close(self) -> None:
        """Close the underlying client connection."""
        self._client.close()

    def __enter__(self) -> Device:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        tag = self._info.tag or self._info.long_tag or "?"
        return (
            f"Device({self._client.host!r}, tag={tag!r}, "
            f"manufacturer={self._info.manufacturer_name!r})"
        )

    # -- underlying client ---------------------------------------------------

    @property
    def client(self) -> HARTIPClient:
        """The underlying :class:`HARTIPClient` for advanced usage."""
        return self._client

    # -- cached identity properties (from Commands 0/13/20) ------------------

    @property
    def info(self) -> DeviceInfo:
        """Full :class:`DeviceInfo` dataclass (cached from Command 0/13/20)."""
        return self._info

    @property
    def tag(self) -> str:
        """Short tag (Command 13, 8 characters)."""
        return self._info.tag

    @property
    def descriptor(self) -> str:
        """Descriptor string (Command 13, 16 characters)."""
        return self._info.descriptor

    @property
    def date(self) -> str:
        """Date string from Command 13 (YYYY-MM-DD format)."""
        return self._info.date

    @property
    def long_tag(self) -> str:
        """Long tag (Command 20, 32 characters, HART 6+)."""
        return self._info.long_tag

    @property
    def manufacturer_name(self) -> str:
        """Manufacturer name (e.g. 'Emerson', 'ABB')."""
        return self._info.manufacturer_name

    @property
    def manufacturer_id(self) -> int:
        """8-bit manufacturer ID from Command 0."""
        return self._info.manufacturer_id

    @property
    def device_type(self) -> int:
        """Device type code from Command 0."""
        return self._info.device_type

    @property
    def device_id(self) -> int:
        """24-bit device ID from Command 0."""
        return self._info.device_id

    @property
    def unique_address(self) -> bytes:
        """5-byte unique address for long-frame addressing."""
        return self._info.unique_address

    @property
    def hart_revision(self) -> int:
        """HART universal command revision level."""
        return self._info.hart_revision

    @property
    def software_revision(self) -> int:
        """Device software revision."""
        return self._info.software_revision

    @property
    def hardware_revision(self) -> int:
        """Device hardware revision."""
        return self._info.hardware_revision

    # -- live process-value properties (network call on each access) ---------

    @property
    def primary_variable(self) -> Optional[Variable]:
        """Read the primary variable (Command 1).

        Returns a :class:`Variable` with ``value``, ``unit_code``, and
        ``unit_name``, or ``None`` on failure.
        """
        resp = self._client.read_primary_variable()
        if resp.success:
            return resp.parsed
        return None

    @property
    def loop_current(self) -> Optional[float]:
        """Read loop current in mA (Command 2)."""
        resp = self._client.read_current_and_percent()
        if resp.success and resp.parsed:
            return resp.parsed.get("current_mA")
        return None

    @property
    def percent_range(self) -> Optional[float]:
        """Read percent of range (Command 2)."""
        resp = self._client.read_current_and_percent()
        if resp.success and resp.parsed:
            return resp.parsed.get("percent_range")
        return None

    @property
    def dynamic_variables(self) -> list[Variable]:
        """Read dynamic variables (Command 3).

        Returns a list of :class:`Variable` objects (PV, SV, TV, QV).
        Returns an empty list on failure.
        """
        resp = self._client.read_dynamic_variables()
        if resp.success and resp.parsed:
            return resp.parsed.get("variables", [])
        return []

    def device_variables(
        self,
        var_codes: Sequence[int] = (0, 1, 2, 3),
    ) -> list[DeviceVariable]:
        """Read device variables with status (Command 9).

        Args:
            var_codes: Device variable codes to request (default PV/SV/TV/QV).

        Returns:
            List of :class:`DeviceVariable` objects, or empty list on failure.
        """
        resp = self._client.read_device_vars_status(device_var_codes=var_codes)
        if resp.success and resp.parsed:
            return resp.parsed.get("variables", [])
        return []

    @property
    def status(self) -> dict:
        """Read additional device status (Command 48).

        Returns the full parsed dict from Command 48, or an empty dict
        on failure.
        """
        resp = self._client.read_additional_status()
        if resp.success and resp.parsed:
            return resp.parsed
        return {}

    @property
    def additional_status(self) -> dict:
        """Alias for :attr:`status` (Command 48)."""
        return self.status

    @property
    def message(self) -> str:
        """Read the device message (Command 12).

        Returns the 32-character message string, or empty string on failure.
        """
        resp = self._client.read_message()
        if resp.success and resp.parsed is not None:
            return resp.parsed
        return ""
