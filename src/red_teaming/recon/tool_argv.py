"""Exact, shared tool-command specification and argv validation.

The sandbox runner must never launch an arbitrary binary or argument list. This
module is the single source of truth for the *only* commands RECON-002 may run
against the pinned tools:

* the exact local **inspection** commands (``--version``/``-version`` and
  ``-h``/``--help``) used by validate-only; and
* the exact **live** argv for Subfinder, Amass, and dnsx.

The production adapters build argv from :func:`expected_live_argv` (via the
:class:`ToolCommandSpec`) and the runner independently re-validates whatever it
is asked to launch, so neither side can drift into an unintended invocation.

Pure data and pure validation: no I/O, no process, no socket.
"""

from __future__ import annotations

from dataclasses import dataclass

from .netpolicy import ROOT_DOMAIN, UPSTREAM_DNS_HOST, UPSTREAM_DNS_PORT

__all__ = [
    "AMASS_HELP_FLAG",
    "ArgvError",
    "INSPECTION",
    "LIVE",
    "ToolCommandSpec",
    "classify_argv",
    "expected_live_argv",
    "inspection_argvs",
    "is_inspection_argv",
    "is_live_argv",
    "required_markers_for",
]

INSPECTION = "inspection"
LIVE = "live"

#: The one exact local help flag permitted for the Amass ``enum`` flagset.
#: Pinned Amass 5.1.1 defines this long flag explicitly (its usage action prints
#: the ``enum`` flag list); it is used instead of the short/reserved ``-h``.
AMASS_HELP_FLAG = "-help"

#: Exact source allowed for the passive discovery tools.
CRTSH_SOURCE = "crtsh"

#: dnsx resolver string (host:port) as passed on the command line.
DNSX_RESOLVER = f"{UPSTREAM_DNS_HOST}:{UPSTREAM_DNS_PORT}"

_VERSION_FLAGS = ("-version", "--version")
_HELP_FLAGS = ("-h", "--help")


class ArgvError(ValueError):
    """The argv is not one of the exact permitted tool commands."""


@dataclass(frozen=True)
class ToolCommandSpec:
    """Immutable description of the exact permitted commands for one tool."""

    tool: str
    version: str
    binary: str
    root: str = ROOT_DOMAIN
    #: Amass domain option actually advertised by the pinned help (``-d`` or
    #: ``-domain``); ignored by the other tools.
    domain_option: str = "-d"
    #: Amass ``-oA`` output prefix (already contained in the run work directory).
    #: Pinned Amass 5.1.1 has no ``-json`` flag; it writes ``<prefix>.json``.
    output_prefix: str | None = None

    def __post_init__(self) -> None:
        for name, value in (("tool", self.tool), ("version", self.version), ("binary", self.binary)):
            if not isinstance(value, str) or not value:
                raise ArgvError(f"{name} must be a non-empty string")
        if self.root != ROOT_DOMAIN:
            raise ArgvError("only the fixed RECON-002 root domain is permitted")
        if self.tool == "amass":
            if self.domain_option not in ("-d", "-domain"):
                raise ArgvError("amass domain option must be -d or -domain")
            if not isinstance(self.output_prefix, str) or not self.output_prefix:
                raise ArgvError("amass requires a bounded output prefix")


def expected_live_argv(spec: ToolCommandSpec) -> tuple[str, ...]:
    """Return the one and only permitted live argv for *spec*."""

    if not isinstance(spec, ToolCommandSpec):
        raise ArgvError("spec must be a ToolCommandSpec")
    binary = spec.binary
    tool = spec.tool
    if tool == "subfinder":
        return (
            binary,
            "-d",
            spec.root,
            "-s",
            CRTSH_SOURCE,
            "-json",
            "-silent",
            "-rl",
            "1",
            "-duc",
        )
    if tool == "amass":
        return (
            binary,
            "enum",
            "-passive",
            spec.domain_option,
            spec.root,
            "-oA",
            spec.output_prefix or "",
            "-include",
            CRTSH_SOURCE,
        )
    if tool == "dnsx":
        return (
            binary,
            "-json",
            "-a",
            "-aaaa",
            "-cname",
            "-silent",
            "-r",
            DNSX_RESOLVER,
            "-rl",
            "5",
            "-t",
            "2",
            "-duc",
        )
    raise ArgvError(f"unsupported tool: {tool!r}")


def required_markers_for(spec: ToolCommandSpec) -> tuple[str, ...]:
    """Return every option token that must be advertised for the live argv.

    The markers are derived from the exact live argv itself, so a capability is
    only considered confirmed when the pinned help advertises every option the
    live command actually uses.
    """

    argv = expected_live_argv(spec)
    markers: list[str] = []
    for item in argv[1:]:
        if item.startswith("-") and item not in markers:
            markers.append(item)
    if spec.tool == "amass" and spec.domain_option not in markers:
        markers.append(spec.domain_option)
    return tuple(markers)


def inspection_argvs(spec: ToolCommandSpec) -> frozenset[tuple[str, ...]]:
    """Return the exact permitted local inspection argvs for *spec*."""

    if not isinstance(spec, ToolCommandSpec):
        raise ArgvError("spec must be a ToolCommandSpec")
    binary = spec.binary
    forms: list[tuple[str, ...]] = []
    if spec.tool == "amass":
        for flag in _VERSION_FLAGS:
            forms.append((binary, flag))
        # Only the exact long help form is permitted for the ``enum`` flagset;
        # the short ``-h`` form is intentionally not allowlisted.
        forms.append((binary, "enum", AMASS_HELP_FLAG))
    else:
        for flag in _VERSION_FLAGS:
            forms.append((binary, flag))
        for flag in _HELP_FLAGS:
            forms.append((binary, flag))
    return frozenset(forms)


def _as_tuple(argv: object) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)):
        raise ArgvError("argv must be a sequence of strings, not a string")
    try:
        items = tuple(argv)  # type: ignore[arg-type]
    except TypeError as exc:
        raise ArgvError("argv must be a sequence of strings") from exc
    if not items:
        raise ArgvError("argv must not be empty")
    for item in items:
        if not isinstance(item, str) or not item:
            raise ArgvError("argv entries must be non-empty strings")
    return items


def is_inspection_argv(spec: ToolCommandSpec, argv: object) -> bool:
    """Return True only for an exact permitted inspection command."""

    try:
        items = _as_tuple(argv)
    except ArgvError:
        return False
    return items in inspection_argvs(spec)


def is_live_argv(spec: ToolCommandSpec, argv: object) -> bool:
    """Return True only for the exact permitted live command."""

    try:
        items = _as_tuple(argv)
    except ArgvError:
        return False
    return items == expected_live_argv(spec)


def classify_argv(spec: ToolCommandSpec, argv: object) -> str:
    """Return ``"inspection"`` or ``"live"``; raise :class:`ArgvError` otherwise."""

    if not isinstance(spec, ToolCommandSpec):
        raise ArgvError("spec must be a ToolCommandSpec")
    items = _as_tuple(argv)
    if items[0] != spec.binary:
        raise ArgvError("argv does not name the pinned binary")
    if items in inspection_argvs(spec):
        return INSPECTION
    if items == expected_live_argv(spec):
        return LIVE
    raise ArgvError("argv is not an exact permitted command")
