"""
HART-IP reply decoding.

:class:`HARTIPResponse` is what :meth:`HARTIPClient.send_command` returns.
:func:`decode_response` builds one from raw bytes: it checks the HART-IP
status and the PDU checksum and splits the PDU data into response code,
device status and payload.  :func:`check_pdu_reply` and
:func:`unwrap_extended` validate a reply against the command that was
sent.
"""

from __future__ import annotations

from collections.abc import Collection
from typing import Any

from .constants import COMM_ERROR_MASK, HARTIP_HEADER_SIZE, HARTIPStatus, HARTResponseCode
from .exceptions import (
    HARTChecksumError,
    HARTCommunicationError,
    HARTFrameError,
    HARTIPStatusError,
    HARTResponseError,
)
from .protocol import MessageHeader, PduContainer, parse_response, xor_checksum

_UNPARSED = object()


class HARTIPResponse:
    """Parsed HART-IP response.

    Attributes:
        header: Parsed HART-IP transport header.
        pdu: Parsed HART PDU frame, or ``None`` for header-only messages.
        response_code: HART response code (first data byte). When
            :attr:`comm_error` is ``True``, this is the raw communication
            error flags byte (MSB set).
        device_status: HART device status byte (second data byte).
        payload: Remaining command data after response_code and device_status.
        comm_error: ``True`` if bit 7 of the response code byte was set,
            indicating a communication error summary rather than a command
            response code.
        expanded_command: For a command above 253 sent through Command 31,
            the expanded command number; ``None`` otherwise.  When set,
            :attr:`command_number` reports it, :attr:`payload` no longer
            starts with the 2-byte expanded number, and ``pdu.command`` is
            still 31.
    """

    __slots__ = (
        "_parsed_cache",
        "comm_error",
        "device_status",
        "expanded_command",
        "header",
        "payload",
        "pdu",
        "response_code",
    )

    def __init__(
        self,
        header: MessageHeader | None,
        pdu: PduContainer | None,
        response_code: int = 0,
        device_status: int = 0,
        payload: bytes = b"",
        comm_error: bool = False,
        expanded_command: int | None = None,
    ):
        self.header = header
        self.pdu = pdu
        self.response_code = response_code
        self.device_status = device_status
        self.payload = payload
        self.comm_error = comm_error
        self.expanded_command = expanded_command
        self._parsed_cache: object = _UNPARSED

    @property
    def command_number(self) -> int | None:
        """The HART command number, or ``None`` if unavailable.

        For an expanded command sent through Command 31 this is the
        expanded number (e.g. 534), not 31.
        """
        if self.expanded_command is not None:
            return self.expanded_command
        if self.pdu is not None:
            return self.pdu.command
        return None

    @property
    def command_name(self) -> str:
        """Human-readable command name from the registry.

        Returns ``"unknown_cmd_{n}"`` when not registered, or ``"unknown"``
        when the command number is unavailable.
        """
        from .device import get_command_name

        cmd = self.command_number
        if cmd is None:
            return "unknown"
        return get_command_name(cmd)

    @property
    def parsed(self) -> Any:
        """Auto-parsed payload using the command registry.

        The result is computed lazily on first access and cached.  Returns
        ``None`` when no parser is registered for the command or when the
        command number is unavailable.  Its type depends on the command,
        so it is ``Any``; call the ``parse_cmdNN`` function for a
        statically typed result.

        Examples::

            resp = client.read_unique_id()
            info = resp.parsed           # DeviceInfo dataclass
            print(info.manufacturer_name)

            resp = client.read_dynamic_variables()
            data = resp.parsed           # dict with 'loop_current' and 'variables'
        """
        if self._parsed_cache is _UNPARSED:
            from .device import parse_command

            cmd = self.command_number
            self._parsed_cache = (
                parse_command(cmd, self.payload) if cmd is not None and self.payload else None
            )
        return self._parsed_cache

    @property
    def success(self) -> bool:
        """True when the response code is 0 and no communication error occurred."""
        return self.response_code == HARTResponseCode.SUCCESS and not self.comm_error

    @property
    def error_message(self) -> str:
        """Human-readable error description."""
        if self.comm_error:
            return f"Communication error (flags=0x{self.response_code:02X})"
        try:
            return HARTResponseCode(self.response_code).name
        except ValueError:
            return f"Unknown error code: {self.response_code}"

    @property
    def error_code(self) -> HARTResponseCode | None:
        """The response code as an enum member, or ``None`` if not recognized.

        Returns ``None`` when :attr:`comm_error` is ``True`` (the byte is
        not a response code in that case).
        """
        if self.comm_error:
            return None
        try:
            return HARTResponseCode(self.response_code)
        except ValueError:
            return None

    def raise_for_error(self) -> None:
        """Raise an exception if the response indicates an error.

        Raises:
            HARTCommunicationError: If :attr:`comm_error` is ``True``.
            HARTResponseError: If :attr:`response_code` is non-zero.
        """
        if self.comm_error:
            raise HARTCommunicationError(self.response_code)
        if self.response_code != HARTResponseCode.SUCCESS:
            cmd = self.command_number or 0
            raise HARTResponseError(
                f"HART command {cmd} failed: {self.error_message}",
                code=self.response_code,
                command=cmd,
            )

    def __repr__(self) -> str:
        cmd = "?" if self.command_number is None else str(self.command_number)
        status = "ok" if self.success else self.error_message
        return (
            f"HARTIPResponse(cmd={cmd}, rc={self.response_code}, "
            f"status={status!r}, payload={len(self.payload)}B)"
        )


def status_name(status: int) -> str:
    """Name of a HART-IP header status, or ``"status N"`` if unknown."""
    try:
        return HARTIPStatus(status).name
    except ValueError:
        return f"status {status}"


def check_hartip_status(
    header: MessageHeader,
    accept: Collection[int] = (HARTIPStatus.SUCCESS,),
) -> None:
    """Raise :class:`HARTIPStatusError` unless the header status is in *accept*."""
    if header.status not in accept:
        raise HARTIPStatusError(f"HART-IP error: {status_name(header.status)}", header.status)


def decode_response(data: bytes) -> HARTIPResponse:
    """Decode one HART-IP message into a :class:`HARTIPResponse`.

    Raises:
        HARTFrameError: Malformed or truncated message.
        HARTIPStatusError: HART-IP header status is not SUCCESS.
        HARTChecksumError: PDU checksum mismatch.
    """
    message = parse_response(data)
    header = message["header"]
    check_hartip_status(header)
    pdu = message["pdu"]
    if pdu is None:
        return HARTIPResponse(header=header, pdu=None)

    # The XOR covers delimiter through the last data byte; preamble bytes
    # (0xFF) are excluded per the HART spec.
    pdu_bytes = data[HARTIP_HEADER_SIZE:]
    expected = xor_checksum(pdu_bytes[pdu.preamble_count : pdu.checksum_offset])
    if expected != pdu.checksum:
        raise HARTChecksumError(expected, pdu.checksum)

    # Reply data: response code, device status, then the command payload.
    # Bit 7 of the response code byte marks a communication error summary.
    response_code = pdu.data[0] if pdu.data else 0
    return HARTIPResponse(
        header=header,
        pdu=pdu,
        response_code=response_code,
        device_status=pdu.data[1] if len(pdu.data) >= 2 else 0,
        payload=pdu.data[2:],
        comm_error=bool(response_code & COMM_ERROR_MASK),
    )


def check_pdu_reply(resp: HARTIPResponse, wire_command: int) -> None:
    """Reject a pass-through reply that does not carry the requested command."""
    if resp.pdu is None:
        raise HARTFrameError(f"Reply to command {wire_command} carries no PDU")
    if resp.pdu.command != wire_command:
        raise HARTFrameError(f"Reply carries command {resp.pdu.command}, requested {wire_command}")


def unwrap_extended(resp: HARTIPResponse, requested: int | None) -> None:
    """Strip the expanded command number from a Command 31 reply.

    The reply data after response code and device status starts with
    the 2-byte expanded command number (Wireshark packet-hartip.c
    dissect_cmd31).  *requested* is the number that was sent, or
    ``None`` for unsolicited frames, which are accepted as they come.
    """
    if len(resp.payload) >= 2:
        expanded = int.from_bytes(resp.payload[:2], "big")
        if requested is not None and expanded != requested:
            raise HARTFrameError(
                f"Command 31 reply carries expanded command {expanded}, requested {requested}"
            )
        resp.payload = resp.payload[2:]
        resp.expanded_command = expanded
    elif requested is not None:
        if resp.success:
            raise HARTFrameError(
                f"Command 31 reply to {requested} lacks the expanded command number"
            )
        # Error replies may omit the data; report the command that was sent.
        resp.expanded_command = requested
