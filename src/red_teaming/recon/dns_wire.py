"""Minimal, bounded DNS wire codec for the RECON-002 broker and relay.

This module implements only what the egress layer needs:

* build a single-question query for A/AAAA/CNAME;
* parse and strictly validate a query (opcode 0, exactly one IN question);
* parse and strictly validate a response against the expected transaction id,
  question name, and question type, extracting A/AAAA/CNAME records;
* build a canned response for offline fakes/tests.

There is deliberately **no** dependency on the system resolver and no socket
use. Every parser is bounded (message size, label count, pointer jumps, answer
count) so a hostile or malformed datagram fails closed instead of looping or
allocating unbounded memory. Nothing here performs I/O at import time.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .netpolicy import (
    DNS_TYPE_A,
    DNS_TYPE_AAAA,
    DNS_TYPE_CNAME,
    MAX_DNS_MESSAGE,
    PolicyError,
    normalize_policy_name,
)

__all__ = [
    "DnsMessageError",
    "DnsQuery",
    "DnsRecord",
    "DnsResponse",
    "build_query",
    "build_response_for_query",
    "extract_addresses",
    "extract_cnames",
    "is_truncated",
    "parse_query",
    "parse_response",
]

_HEADER_LEN = 12
_MAX_LABELS = 64
_MAX_POINTER_JUMPS = 32
_MAX_ANSWER_RECORDS = 64

_FLAG_QR = 0x8000
_FLAG_OPCODE_MASK = 0x7800
_FLAG_TC = 0x0200
_FLAG_RCODE_MASK = 0x000F
_OPCODE_QUERY = 0
_CLASS_IN = 1


class DnsMessageError(ValueError):
    """A malformed, oversized, or mismatched DNS message (fail closed)."""


@dataclass(frozen=True)
class DnsQuery:
    """A parsed single-question DNS query."""

    transaction_id: int
    name: str
    qtype: int
    qclass: int
    opcode: int
    question_end: int


@dataclass(frozen=True)
class DnsRecord:
    """One parsed A/AAAA/CNAME answer record."""

    name: str
    rtype: int
    value: str


@dataclass(frozen=True)
class DnsResponse:
    """A validated DNS response with its parsed answer records."""

    transaction_id: int
    truncated: bool
    rcode: int
    question_name: str
    question_type: int
    answers: tuple[DnsRecord, ...]


def _require_bytes(data: object, *, max_len: int) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise DnsMessageError("DNS message must be bytes")
    raw = bytes(data)
    if len(raw) < _HEADER_LEN:
        raise DnsMessageError("DNS message is shorter than its header")
    if len(raw) > max_len:
        raise DnsMessageError("DNS message exceeds the bounded maximum")
    return raw


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read a (possibly compressed) DNS name; return ``(canonical, next)``."""

    labels: list[bytes] = []
    next_offset = offset
    jumped = False
    jumps = 0
    count = 0
    while True:
        if offset >= len(data):
            raise DnsMessageError("DNS name runs past the message end")
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DnsMessageError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if pointer >= len(data):
                raise DnsMessageError("DNS compression pointer out of range")
            if not jumped:
                next_offset = offset + 2
                jumped = True
            jumps += 1
            if jumps > _MAX_POINTER_JUMPS:
                raise DnsMessageError("too many DNS compression jumps")
            offset = pointer
            continue
        if length & 0xC0:
            raise DnsMessageError("reserved DNS label type")
        offset += 1
        if offset + length > len(data):
            raise DnsMessageError("truncated DNS label")
        labels.append(bytes(data[offset : offset + length]))
        offset += length
        count += 1
        if count > _MAX_LABELS:
            raise DnsMessageError("too many DNS labels")
    if not labels:
        raise DnsMessageError("empty DNS name")
    try:
        joined = b".".join(labels).decode("ascii")
    except UnicodeDecodeError as exc:
        raise DnsMessageError("non-ASCII DNS label") from exc
    try:
        canonical = normalize_policy_name(joined)
    except PolicyError as exc:
        raise DnsMessageError("invalid DNS name") from exc
    return canonical, next_offset


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        encoded = label.encode("ascii")
        if not 1 <= len(encoded) <= 63:
            raise DnsMessageError("invalid DNS label length")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def _canonical(name: object) -> str:
    """Canonicalize a DNS name, converting policy errors to wire errors."""

    try:
        return normalize_policy_name(name)
    except PolicyError as exc:
        raise DnsMessageError("invalid DNS name") from exc


def build_query(
    name: object, qtype: int, transaction_id: int, *, recursive: bool = True
) -> bytes:
    """Build a bounded single-question DNS query for *name* and *qtype*."""

    if qtype not in (DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_CNAME):
        raise DnsMessageError("unsupported DNS query type")
    if (
        isinstance(transaction_id, bool)
        or not isinstance(transaction_id, int)
        or not 0 <= transaction_id <= 0xFFFF
    ):
        raise DnsMessageError("transaction id must be a 16-bit integer")
    canonical = _canonical(name)

    header = bytearray()
    header += transaction_id.to_bytes(2, "big")
    header += (0x0100 if recursive else 0x0000).to_bytes(2, "big")
    header += (1).to_bytes(2, "big")
    header += b"\x00\x00\x00\x00\x00\x00"

    question = _encode_name(canonical)
    question += qtype.to_bytes(2, "big")
    question += _CLASS_IN.to_bytes(2, "big")

    message = bytes(header) + question
    if len(message) > MAX_DNS_MESSAGE:
        raise DnsMessageError("query exceeds the bounded maximum")
    return message


def _parse_question(data: bytes, offset: int) -> tuple[str, int, int, int]:
    name, offset = _read_name(data, offset)
    if offset + 4 > len(data):
        raise DnsMessageError("truncated DNS question")
    qtype = int.from_bytes(data[offset : offset + 2], "big")
    qclass = int.from_bytes(data[offset + 2 : offset + 4], "big")
    return name, qtype, qclass, offset + 4


def parse_query(data: object, *, max_len: int = MAX_DNS_MESSAGE) -> DnsQuery:
    """Parse and validate a single-question DNS query (fail closed)."""

    raw = _require_bytes(data, max_len=max_len)
    transaction_id = int.from_bytes(raw[0:2], "big")
    flags = int.from_bytes(raw[2:4], "big")
    if flags & _FLAG_QR:
        raise DnsMessageError("expected a query, not a response")
    opcode = (flags & _FLAG_OPCODE_MASK) >> 11
    if opcode != _OPCODE_QUERY:
        raise DnsMessageError("unsupported DNS opcode")
    qdcount = int.from_bytes(raw[4:6], "big")
    if qdcount != 1:
        raise DnsMessageError("DNS query must contain exactly one question")
    name, qtype, qclass, question_end = _parse_question(raw, _HEADER_LEN)
    if qclass != _CLASS_IN:
        raise DnsMessageError("only IN-class DNS questions are supported")
    return DnsQuery(
        transaction_id=transaction_id,
        name=name,
        qtype=qtype,
        qclass=qclass,
        opcode=opcode,
        question_end=question_end,
    )


def _parse_rdata(
    data: bytes, rtype: int, start: int, rdlength: int
) -> tuple[str | None, str | None]:
    """Return ``(value_text, canonical_name)`` for a supported record."""

    end = start + rdlength
    if end > len(data):
        raise DnsMessageError("DNS record data runs past the message end")
    if rtype == DNS_TYPE_A:
        if rdlength != 4:
            raise DnsMessageError("A record must be 4 bytes")
        return str(ipaddress.IPv4Address(data[start:end])), None
    if rtype == DNS_TYPE_AAAA:
        if rdlength != 16:
            raise DnsMessageError("AAAA record must be 16 bytes")
        return str(ipaddress.IPv6Address(data[start:end])), None
    if rtype == DNS_TYPE_CNAME:
        name, next_offset = _read_name(data, start)
        if next_offset > end:
            raise DnsMessageError("CNAME record data overruns its length")
        return name, name
    return None, None


def _parse_records(
    data: bytes, offset: int, count: int
) -> tuple[tuple[DnsRecord, ...], int]:
    if count > _MAX_ANSWER_RECORDS:
        raise DnsMessageError("too many DNS answer records")
    records: list[DnsRecord] = []
    for _ in range(count):
        owner, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            raise DnsMessageError("truncated DNS record header")
        rtype = int.from_bytes(data[offset : offset + 2], "big")
        rclass = int.from_bytes(data[offset + 2 : offset + 4], "big")
        # ttl = data[offset + 4 : offset + 8]
        rdlength = int.from_bytes(data[offset + 8 : offset + 10], "big")
        rdata_start = offset + 10
        value, canonical = _parse_rdata(data, rtype, rdata_start, rdlength)
        offset = rdata_start + rdlength
        if rclass == _CLASS_IN and value is not None:
            records.append(
                DnsRecord(name=canonical or owner, rtype=rtype, value=value)
            )
    return tuple(records), offset


def parse_response(
    data: object,
    *,
    expect_id: int,
    expect_name: object,
    expect_type: int,
    max_len: int = MAX_DNS_MESSAGE,
) -> DnsResponse:
    """Parse a response and require the expected transaction and question.

    Raises :class:`DnsMessageError` on any malformed, oversized, mismatched, or
    off-question response so the caller can fail closed before relaying it.
    """

    raw = _require_bytes(data, max_len=max_len)
    transaction_id = int.from_bytes(raw[0:2], "big")
    flags = int.from_bytes(raw[2:4], "big")
    if not flags & _FLAG_QR:
        raise DnsMessageError("expected a response, not a query")
    opcode = (flags & _FLAG_OPCODE_MASK) >> 11
    if opcode != _OPCODE_QUERY:
        raise DnsMessageError("unsupported DNS opcode")
    qdcount = int.from_bytes(raw[4:6], "big")
    if qdcount != 1:
        raise DnsMessageError("DNS response must contain exactly one question")
    ancount = int.from_bytes(raw[6:8], "big")

    name, qtype, qclass, offset = _parse_question(raw, _HEADER_LEN)
    if qclass != _CLASS_IN:
        raise DnsMessageError("only IN-class DNS questions are supported")

    if expect_id != transaction_id:
        raise DnsMessageError("DNS transaction id does not match")
    canonical_expect = _canonical(expect_name)
    if name != canonical_expect:
        raise DnsMessageError("DNS question name does not match")
    if qtype != expect_type:
        raise DnsMessageError("DNS question type does not match")

    answers, _ = _parse_records(raw, offset, ancount)
    return DnsResponse(
        transaction_id=transaction_id,
        truncated=bool(flags & _FLAG_TC),
        rcode=flags & _FLAG_RCODE_MASK,
        question_name=name,
        question_type=qtype,
        answers=answers,
    )


def is_truncated(data: object) -> bool:
    """Return True when a DNS message has the TC (truncated) flag set."""

    if not isinstance(data, (bytes, bytearray, memoryview)):
        return False
    raw = bytes(data)
    if len(raw) < 4:
        return False
    return bool(int.from_bytes(raw[2:4], "big") & _FLAG_TC)


def extract_addresses(response: DnsResponse) -> tuple[str, ...]:
    """Return the A/AAAA values from a validated response (deduplicated)."""

    values: dict[str, None] = {}
    for record in response.answers:
        if record.rtype in (DNS_TYPE_A, DNS_TYPE_AAAA):
            values[record.value] = None
    return tuple(values)


def extract_cnames(response: DnsResponse) -> tuple[str, ...]:
    """Return the CNAME targets from a validated response (deduplicated)."""

    values: dict[str, None] = {}
    for record in response.answers:
        if record.rtype == DNS_TYPE_CNAME:
            values[record.value] = None
    return tuple(values)


def build_response_for_query(
    query: object,
    answers: object = (),
    *,
    rcode: int = 0,
    truncated: bool = False,
    max_len: int = MAX_DNS_MESSAGE,
) -> bytes:
    """Build a canned DNS response for a query (offline fakes and self-test).

    *answers* is an iterable of ``(name, rtype, value)`` triples where value is
    an IP literal for A/AAAA or a DNS name for CNAME.
    """

    parsed = parse_query(query, max_len=max_len)
    records = tuple(answers or ())
    if len(records) > _MAX_ANSWER_RECORDS:
        raise DnsMessageError("too many canned answer records")
    if isinstance(rcode, bool) or not isinstance(rcode, int) or not 0 <= rcode <= 15:
        raise DnsMessageError("rcode must be a 4-bit integer")

    flags = _FLAG_QR | 0x0100  # QR, opcode 0, RD
    if truncated:
        flags |= _FLAG_TC
    flags |= rcode & _FLAG_RCODE_MASK

    out = bytearray()
    out += parsed.transaction_id.to_bytes(2, "big")
    out += flags.to_bytes(2, "big")
    out += (1).to_bytes(2, "big")
    out += len(records).to_bytes(2, "big")
    out += b"\x00\x00\x00\x00"

    out += _encode_name(parsed.name)
    out += parsed.qtype.to_bytes(2, "big")
    out += _CLASS_IN.to_bytes(2, "big")

    for name, rtype, value in records:
        if rtype not in (DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_CNAME):
            raise DnsMessageError("unsupported canned record type")
        canonical = _canonical(name)
        rdata = _encode_record_rdata(rtype, value)
        out += _encode_name(canonical)
        out += rtype.to_bytes(2, "big")
        out += _CLASS_IN.to_bytes(2, "big")
        out += (60).to_bytes(4, "big")
        out += len(rdata).to_bytes(2, "big")
        out += rdata

    if len(out) > max_len:
        raise DnsMessageError("canned response exceeds the bounded maximum")
    return bytes(out)


def _encode_record_rdata(rtype: int, value: object) -> bytes:
    if rtype == DNS_TYPE_A:
        return ipaddress.IPv4Address(value).packed  # type: ignore[arg-type]
    if rtype == DNS_TYPE_AAAA:
        return ipaddress.IPv6Address(value).packed  # type: ignore[arg-type]
    if rtype == DNS_TYPE_CNAME:
        return _encode_name(_canonical(value))
    raise DnsMessageError("unsupported canned record type")
