"""Exact local-control HTTP validation without path or header normalization."""

from __future__ import annotations

import re
from dataclasses import dataclass
from email.message import Message
from urllib.parse import urlsplit

from stateguard.control.contracts import ControlErrorCode

MAX_REQUEST_BODY_BYTES = 65_536
_CONTENT_LENGTH = re.compile(r"^(?:0|[1-9][0-9]*)$")
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


class TransportRejection(Exception):
    """A structurally classified HTTP request rejection."""

    def __init__(
        self,
        status: int,
        code: ControlErrorCode,
        *,
        allow: str | None = None,
    ) -> None:
        self.status = status
        self.code = code
        self.allow = allow
        super().__init__(code.value)


@dataclass(frozen=True)
class HostAuthority:
    hostname: str
    port: int


def validate_bind_address(host: str, port: int, *, allow_zero: bool = False) -> None:
    if host not in {"127.0.0.1", "::1"}:
        raise ValueError("invalid control API bind address")
    minimum = 0 if allow_zero else 1
    if isinstance(port, bool) or not minimum <= port <= 65_535:
        raise ValueError("invalid control API port")


def _parse_loopback_authority(value: str, listener_port: int) -> HostAuthority:
    if (
        not value
        or not value.isascii()
        or any(character.isspace() for character in value)
        or any(character in value for character in (",", "@", "/", "?", "#"))
    ):
        raise ValueError("invalid authority")
    parsed = urlsplit(f"//{value}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("invalid authority")
    hostname = parsed.hostname
    if hostname is None or hostname.casefold() not in _LOOPBACK_HOSTS:
        raise ValueError("invalid authority")
    normalized = hostname.casefold()
    if normalized == "::1" and not value.startswith("["):
        raise ValueError("invalid authority")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid authority") from exc
    effective_port = 80 if parsed_port is None else parsed_port
    if effective_port != listener_port or (parsed_port is None and listener_port != 80):
        raise ValueError("invalid authority")
    return HostAuthority(hostname=normalized, port=effective_port)


def validate_host(headers: Message[str, str], listener_port: int) -> HostAuthority:
    values = headers.get_all("Host", failobj=[])
    if len(values) != 1:
        raise TransportRejection(421, ControlErrorCode.HOST_NOT_ALLOWED)
    try:
        return _parse_loopback_authority(values[0], listener_port)
    except ValueError as exc:
        raise TransportRejection(421, ControlErrorCode.HOST_NOT_ALLOWED) from exc


def validate_origin(headers: Message[str, str], authority: HostAuthority) -> None:
    values = headers.get_all("Origin", failobj=[])
    if not values:
        return
    if len(values) != 1:
        raise TransportRejection(403, ControlErrorCode.ORIGIN_NOT_ALLOWED)
    value = values[0]
    try:
        if not value.isascii() or any(character.isspace() for character in value):
            raise ValueError("invalid origin")
        parsed = urlsplit(value)
        if (
            parsed.scheme.casefold() != "http"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("invalid origin")
        try:
            port = 80 if parsed.port is None else parsed.port
        except ValueError as exc:
            raise ValueError("invalid origin") from exc
        if parsed.hostname.casefold() != authority.hostname or port != authority.port:
            raise ValueError("invalid origin")
    except ValueError as exc:
        raise TransportRejection(403, ControlErrorCode.ORIGIN_NOT_ALLOWED) from exc


def validate_request_target(target: str) -> str:
    if (
        not target
        or not target.startswith("/")
        or not target.isascii()
        or any(ord(character) < 32 or ord(character) == 127 for character in target)
        or any(character in target for character in ("%", "\\", "?", "#"))
        or "//" in target
    ):
        raise TransportRejection(400, ControlErrorCode.INVALID_REQUEST)
    segments = target.split("/")[1:]
    if any(segment in {".", ".."} for segment in segments):
        raise TransportRejection(400, ControlErrorCode.INVALID_REQUEST)
    return target


def _reject_ambiguous_framing(headers: Message[str, str]) -> None:
    if headers.get_all("Transfer-Encoding", failobj=[]):
        raise TransportRejection(400, ControlErrorCode.INVALID_REQUEST)
    if headers.get_all("Expect", failobj=[]):
        raise TransportRejection(400, ControlErrorCode.INVALID_REQUEST)


def validate_get_framing(headers: Message[str, str]) -> None:
    _reject_ambiguous_framing(headers)
    lengths = headers.get_all("Content-Length", failobj=[])
    if len(lengths) > 1 or (lengths and lengths[0] != "0"):
        raise TransportRejection(400, ControlErrorCode.INVALID_REQUEST)


def validate_mutation_framing(headers: Message[str, str]) -> int:
    _reject_ambiguous_framing(headers)
    if headers.get_all("Content-Encoding", failobj=[]):
        raise TransportRejection(415, ControlErrorCode.UNSUPPORTED_MEDIA_TYPE)
    content_types = headers.get_all("Content-Type", failobj=[])
    if len(content_types) != 1:
        raise TransportRejection(415, ControlErrorCode.UNSUPPORTED_MEDIA_TYPE)
    parts = tuple(part.strip().casefold() for part in content_types[0].split(";"))
    if parts not in {("application/json",), ("application/json", "charset=utf-8")}:
        raise TransportRejection(415, ControlErrorCode.UNSUPPORTED_MEDIA_TYPE)
    lengths = headers.get_all("Content-Length", failobj=[])
    if len(lengths) != 1 or _CONTENT_LENGTH.fullmatch(lengths[0]) is None:
        raise TransportRejection(400, ControlErrorCode.INVALID_REQUEST)
    length = int(lengths[0])
    if length > MAX_REQUEST_BODY_BYTES:
        raise TransportRejection(413, ControlErrorCode.REQUEST_TOO_LARGE)
    if length == 0:
        raise TransportRejection(400, ControlErrorCode.INVALID_REQUEST)
    return length
