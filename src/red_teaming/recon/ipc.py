"""Bounded in-memory IPC for the RECON-002 egress broker and namespace helper.

IPC uses inherited ``AF_UNIX`` ``socketpair`` file descriptors created by the
launcher and passed to the sandboxed child with ``pass_fds``. No filesystem
socket is ever created (the project lives on a 9p mount) and no arbitrary
destination, path, or command can be expressed on the wire.

The protocol is deliberately tiny and bounded:

* every frame is a 4-byte big-endian length prefix followed by a payload whose
  length is capped by :data:`~red_teaming.recon.netpolicy.MAX_IPC_FRAME`;
* the control channel carries a JSON object with a fixed ``op`` value; the only
  connect operation names the literal ``crt.sh``/``443`` authority, which the
  broker revalidates against policy;
* the DNS channel carries a 1-byte transport tag plus a raw DNS message, and
  the response carries a tag, a status byte, and the raw DNS response;
* file descriptors are transferred only over the control channel with
  ``SCM_RIGHTS`` (never as a path).

On platforms without ``SCM_RIGHTS`` the fd-transfer helpers fail closed with
:class:`IpcUnsupported`; plain framing still works and is unit-testable.
"""

from __future__ import annotations

import array
import json
import socket
from typing import Any

from .netpolicy import MAX_IPC_FRAME, DNS_PROTO_TCP, DNS_PROTO_UDP

__all__ = [
    "CONNECT_OP",
    "DNS_PROTO_TCP",
    "DNS_PROTO_UDP",
    "IpcClosed",
    "IpcError",
    "IpcProtocolError",
    "IpcUnsupported",
    "STATUS_DENIED",
    "STATUS_ERROR",
    "STATUS_OK",
    "decode_connect_request",
    "decode_connect_response",
    "decode_dns_request",
    "decode_dns_response",
    "decode_status_event",
    "encode_connect_request",
    "encode_connect_response",
    "encode_dns_request",
    "encode_dns_response",
    "encode_status_event",
    "fd_passing_supported",
    "recv_frame",
    "recv_message_fd",
    "send_fd_message",
    "send_frame",
]

CONNECT_OP = "connect"

STATUS_OK = 0
STATUS_DENIED = 1
STATUS_ERROR = 2

_MAX_REASON = 128
_MAX_STATUS_FIELDS = 16
_MAX_STATUS_VALUE = 256

_FD_ANC_SIZE = array.array("i").itemsize


class IpcError(ValueError):
    """Base class for IPC failure."""


class IpcClosed(IpcError):
    """The peer closed cleanly (or the frame was truncated)."""


class IpcProtocolError(IpcError):
    """A malformed, oversized, or unexpected frame."""


class IpcUnsupported(IpcError):
    """The platform cannot express this IPC operation (e.g. no SCM_RIGHTS)."""


def fd_passing_supported() -> bool:
    """Return True when this interpreter can pass descriptors with SCM_RIGHTS."""

    return all(
        hasattr(socket, name)
        for name in ("SCM_RIGHTS", "CMSG_SPACE", "CMSG_LEN", "SOL_SOCKET")
    )


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------


def _check_size(size: object, max_frame: int) -> int:
    if isinstance(size, bool) or not isinstance(size, int):
        raise IpcProtocolError("frame length must be an integer")
    if size <= 0:
        raise IpcProtocolError("empty frames are not allowed")
    if size > max_frame:
        raise IpcProtocolError("frame exceeds the bounded maximum")
    return size


def send_frame(sock: Any, payload: bytes, *, max_frame: int = MAX_IPC_FRAME) -> None:
    """Send one length-prefixed frame, failing closed on an oversized payload."""

    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise IpcProtocolError("frame payload must be bytes")
    raw = bytes(payload)
    _check_size(len(raw), max_frame)
    sock.sendall(len(raw).to_bytes(4, "big") + raw)


def _recv_exact(sock: Any, count: int) -> bytes | None:
    buffer = bytearray()
    while len(buffer) < count:
        chunk = sock.recv(count - len(buffer))
        if not chunk:
            return None
        buffer.extend(chunk)
    return bytes(buffer)


def recv_frame(sock: Any, *, max_frame: int = MAX_IPC_FRAME) -> bytes | None:
    """Receive one frame; return ``None`` on clean EOF, else the payload."""

    header = _recv_exact(sock, 4)
    if header is None:
        return None
    size = _check_size(int.from_bytes(header, "big"), max_frame)
    payload = _recv_exact(sock, size)
    if payload is None:
        raise IpcClosed("truncated IPC frame")
    return payload


# ---------------------------------------------------------------------------
# Descriptor passing
# ---------------------------------------------------------------------------


def send_fd_message(
    sock: Any,
    payload: bytes,
    fd: int | None = None,
    *,
    max_frame: int = MAX_IPC_FRAME,
) -> None:
    """Send a length-prefixed frame, optionally transferring one descriptor."""

    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise IpcProtocolError("frame payload must be bytes")
    raw = bytes(payload)
    _check_size(len(raw), max_frame)
    frame = len(raw).to_bytes(4, "big") + raw
    if fd is None:
        sock.sendall(frame)
        return
    if not fd_passing_supported():
        raise IpcUnsupported("SCM_RIGHTS descriptor passing is unavailable")

    ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))]
    sent = sock.sendmsg([frame], ancillary)
    if sent != len(frame):
        raise IpcClosed("partial descriptor frame send")


def recv_message_fd(
    sock: Any, *, max_frame: int = MAX_IPC_FRAME
) -> tuple[bytes, int | None]:
    """Receive one frame plus (optionally) one descriptor, or raise on EOF."""

    if not fd_passing_supported() or not hasattr(sock, "recvmsg"):
        raise IpcUnsupported("SCM_RIGHTS descriptor passing is unavailable")

    buffer = bytearray()
    received_fd: int | None = None
    while len(buffer) < 4:
        chunk, ancillary, _flags, _addr = sock.recvmsg(
            65_536, socket.CMSG_SPACE(_FD_ANC_SIZE)
        )
        if received_fd is None:
            received_fd = _extract_fd(ancillary)
        if not chunk:
            raise IpcClosed("peer closed before the frame header")
        buffer.extend(chunk)

    size = _check_size(int.from_bytes(bytes(buffer[:4]), "big"), max_frame)
    payload = bytearray(buffer[4:4 + size])
    while len(payload) < size:
        chunk, ancillary, _flags, _addr = sock.recvmsg(
            65_536, socket.CMSG_SPACE(_FD_ANC_SIZE)
        )
        if received_fd is None:
            received_fd = _extract_fd(ancillary)
        if not chunk:
            raise IpcClosed("peer closed inside a frame")
        payload.extend(chunk)

    if len(buffer) > 4 + size:
        raise IpcProtocolError("unexpected pipelined bytes after a frame")
    if len(payload) > size:
        raise IpcProtocolError("unexpected bytes beyond the declared frame")
    return bytes(payload), received_fd


def _extract_fd(ancillary: object) -> int | None:
    found: int | None = None
    for level, kind, data in ancillary or ():  # type: ignore[misc]
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            continue
        values = array.array("i")
        values.frombytes(data[: len(data) - (len(data) % _FD_ANC_SIZE)])
        for value in values:
            if found is None:
                found = int(value)
            else:
                # Never accept more than one descriptor; close extras.
                try:
                    import os

                    os.close(int(value))
                except OSError:
                    pass
    return found


# ---------------------------------------------------------------------------
# Message codecs
# ---------------------------------------------------------------------------


def _encode_json(document: dict, *, max_frame: int) -> bytes:
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    _check_size(len(raw), max_frame)
    return raw


def _decode_json(payload: object, *, max_frame: int) -> dict:
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise IpcProtocolError("message payload must be bytes")
    raw = bytes(payload)
    _check_size(len(raw), max_frame)
    try:
        document = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IpcProtocolError("message is not valid JSON") from exc
    if not isinstance(document, dict):
        raise IpcProtocolError("message must be a JSON object")
    return document


def _bounded_text(value: object, *, field: str, limit: int = _MAX_REASON) -> str:
    if not isinstance(value, str) or not value:
        raise IpcProtocolError(f"{field} must be a non-empty string")
    if len(value) > limit:
        raise IpcProtocolError(f"{field} exceeds its bound")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise IpcProtocolError(f"{field} contains control characters")
    return value


def _bounded_optional_text(value: str, *, field: str, limit: int) -> str:
    if len(value) > limit:
        raise IpcProtocolError(f"{field} exceeds its bound")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise IpcProtocolError(f"{field} contains control characters")
    return value


def encode_connect_request(host: str, port: int) -> bytes:
    """Encode a connect request naming a literal host and port."""

    if not isinstance(host, str) or not host:
        raise IpcProtocolError("connect host must be a non-empty string")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise IpcProtocolError("connect port must be an in-range integer")
    return _encode_json({"op": CONNECT_OP, "host": host, "port": port}, max_frame=MAX_IPC_FRAME)


def decode_connect_request(payload: object) -> tuple[str, int]:
    """Decode a connect request; structural validation only.

    Policy validation of the literal host/port happens in the broker before any
    socket is opened.
    """

    document = _decode_json(payload, max_frame=MAX_IPC_FRAME)
    if document.get("op") != CONNECT_OP:
        raise IpcProtocolError("unsupported connect request op")
    if set(document) != {"op", "host", "port"}:
        raise IpcProtocolError("unexpected connect request fields")
    host = document.get("host")
    port = document.get("port")
    if not isinstance(host, str) or not host:
        raise IpcProtocolError("connect host must be a non-empty string")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise IpcProtocolError("connect port must be an in-range integer")
    return host, port


def encode_connect_response(ok: bool, reason: str | None = None) -> bytes:
    """Encode a connect response (the descriptor, if any, travels ancestrally)."""

    if not isinstance(ok, bool):
        raise IpcProtocolError("connect response ok must be a boolean")
    document: dict = {"ok": ok}
    if reason is not None:
        document["reason"] = _bounded_text(reason, field="reason")
    return _encode_json(document, max_frame=MAX_IPC_FRAME)


def decode_connect_response(payload: object) -> tuple[bool, str | None]:
    """Decode a connect response, returning ``(ok, reason)``."""

    document = _decode_json(payload, max_frame=MAX_IPC_FRAME)
    ok = document.get("ok")
    if not isinstance(ok, bool):
        raise IpcProtocolError("connect response ok must be a boolean")
    allowed = {"ok"} if ok else {"ok", "reason"}
    if not set(document) <= allowed:
        raise IpcProtocolError("unexpected connect response fields")
    reason = document.get("reason")
    if reason is not None:
        reason = _bounded_text(reason, field="reason")
    return ok, reason


def _check_dns_transport(protocol: object) -> int:
    if isinstance(protocol, bool) or protocol not in (DNS_PROTO_UDP, DNS_PROTO_TCP):
        raise IpcProtocolError("unknown DNS transport tag")
    return int(protocol)  # type: ignore[arg-type]


def encode_dns_request(protocol: int, query: bytes) -> bytes:
    """Encode a DNS relay request as ``tag || raw-query``."""

    tag = _check_dns_transport(protocol)
    if not isinstance(query, (bytes, bytearray, memoryview)):
        raise IpcProtocolError("DNS query must be bytes")
    raw = bytes(query)
    return bytes([tag]) + raw


def decode_dns_request(payload: object) -> tuple[int, bytes]:
    """Decode a DNS relay request, returning ``(protocol, raw_query)``."""

    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise IpcProtocolError("DNS request payload must be bytes")
    raw = bytes(payload)
    if len(raw) < 2:
        raise IpcProtocolError("DNS request frame is too short")
    tag = _check_dns_transport(raw[0])
    return tag, raw[1:]


def encode_dns_response(protocol: int, status: int, response: bytes = b"") -> bytes:
    """Encode a DNS relay response as ``tag || status || raw-response``."""

    tag = _check_dns_transport(protocol)
    if isinstance(status, bool) or status not in (STATUS_OK, STATUS_DENIED, STATUS_ERROR):
        raise IpcProtocolError("unknown DNS status")
    if not isinstance(response, (bytes, bytearray, memoryview)):
        raise IpcProtocolError("DNS response must be bytes")
    return bytes([tag, status]) + bytes(response)


def decode_dns_response(payload: object) -> tuple[int, int, bytes]:
    """Decode a DNS relay response, returning ``(protocol, status, response)``."""

    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise IpcProtocolError("DNS response payload must be bytes")
    raw = bytes(payload)
    if len(raw) < 2:
        raise IpcProtocolError("DNS response frame is too short")
    tag = _check_dns_transport(raw[0])
    status = raw[1]
    if status not in (STATUS_OK, STATUS_DENIED, STATUS_ERROR):
        raise IpcProtocolError("unknown DNS status")
    return tag, status, raw[2:]


def encode_status_event(event: dict) -> bytes:
    """Encode a bounded status event for the launcher (self-test/evidence)."""

    if not isinstance(event, dict):
        raise IpcProtocolError("status event must be a mapping")
    document: dict = {}
    for key, value in event.items():
        if not isinstance(key, str) or not key:
            raise IpcProtocolError("status event keys must be non-empty strings")
        if value is None or isinstance(value, (bool, int, float)):
            document[key] = value
        elif isinstance(value, str):
            document[key] = _bounded_optional_text(
                value, field="status value", limit=_MAX_STATUS_VALUE
            )
        elif isinstance(value, (list, tuple)):
            document[key] = [
                _bounded_optional_text(
                    item, field="status list item", limit=_MAX_STATUS_VALUE
                )
                if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            raise IpcProtocolError("unsupported status event value")
    return _encode_json(document, max_frame=MAX_IPC_FRAME)


def decode_status_event(payload: object) -> dict:
    """Decode a bounded status event produced by the sandboxed helper."""

    document = _decode_json(payload, max_frame=MAX_IPC_FRAME)
    if len(document) > _MAX_STATUS_FIELDS:
        raise IpcProtocolError("status event has too many fields")
    for key, value in document.items():
        if not isinstance(key, str) or not key:
            raise IpcProtocolError("status event keys must be non-empty strings")
        if isinstance(value, str) and len(value) > _MAX_STATUS_VALUE:
            raise IpcProtocolError("status event value exceeds its bound")
    return document
