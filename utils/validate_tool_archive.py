#!/usr/bin/env python3
"""Offline safety validation of recon tool archive members before extraction.

Domain-neutral helper for TOOLING-001. It uses only the Python standard library
and does **not** extract anything. It enumerates the members of a pinned release
archive and refuses any member that could escape the extraction root or that is
not a plain file or directory:

  * absolute paths (``/etc/passwd``);
  * path traversal (``../`` segments, including backslash forms);
  * Windows drive paths (``C:/...``) and UNC paths (``\\\\host\\share``);
  * NUL bytes / control characters in a member name;
  * symlinks and hardlinks;
  * device / FIFO / socket ("special") entries;
  * any member whose resolved destination escapes the extraction root.

The caller runs this before extracting with ``python3 -m zipfile`` or ``tar``.

Exit codes
----------
0   validation passed (a JSON summary is printed to stdout)
2   archive member violated the safety policy
3   archive could not be read, or a usage error occurred

``--self-test`` runs an in-memory, offline test suite and exits 0 on success and
1 on failure. It writes only to the system temporary directory.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import zipfile

_CONTROL_CHARS = frozenset(chr(c) for c in range(0x20)) | {chr(0x7F)}

# Archive member types that carry metadata only and never extract a file.
_METADATA_TAR_TYPES = frozenset(
    t
    for t in (
        getattr(tarfile, "XHDTYPE", None),
        getattr(tarfile, "XGLTYPE", None),
        getattr(tarfile, "GNUTYPE_LONGNAME", None),
        getattr(tarfile, "GNUTYPE_LONGLINK", None),
    )
    if t is not None
)

_SPECIAL_TAR_PREDICATES = ("ischr", "isblk", "isfifo")


class ArchiveViolation(Exception):
    """Raised when an archive member violates the extraction safety policy."""


def _looks_like_drive_path(name: str) -> bool:
    """True for a Windows drive path such as ``C:/evil`` or ``C:evil``."""
    return len(name) >= 2 and name[1] == ":" and name[0].isalpha()


def check_member_name(name: str, root: str) -> str:
    """Validate a single member name and return its resolved destination path.

    Raises :class:`ArchiveViolation` on any unsafe name.
    """
    if not isinstance(name, str):
        raise ArchiveViolation("non-string member name")
    if name == "":
        raise ArchiveViolation("empty member name")
    if "\x00" in name:
        raise ArchiveViolation("NUL byte in member name")
    for char in name:
        if char in _CONTROL_CHARS:
            raise ArchiveViolation(f"control character in member name: {name!r}")

    if name.startswith("\\\\") or name.startswith("//"):
        raise ArchiveViolation(f"UNC path is not permitted: {name!r}")

    normalized = name.replace("\\", "/")
    if normalized.startswith("/"):
        raise ArchiveViolation(f"absolute path is not permitted: {name!r}")
    if _looks_like_drive_path(normalized):
        raise ArchiveViolation(f"drive path is not permitted: {name!r}")

    parts = normalized.split("/")
    for part in parts:
        if part == "..":
            raise ArchiveViolation(f"path traversal is not permitted: {name!r}")

    # Defense in depth: resolve the destination and confirm containment.
    root_norm = os.path.normpath(root)
    relative_parts = [part for part in parts if part != ""]
    destination = os.path.normpath(os.path.join(root_norm, *relative_parts))
    try:
        common = os.path.commonpath([root_norm, destination])
    except ValueError as exc:  # e.g. different drives on Windows
        raise ArchiveViolation(
            f"cannot resolve member destination: {name!r}"
        ) from exc
    if common != root_norm:
        raise ArchiveViolation(f"member escapes extraction root: {name!r}")
    return destination


def _zip_unix_mode(info: zipfile.ZipInfo) -> int:
    return (info.external_attr >> 16) & 0xFFFF


def validate_zip(path: str, root: str) -> int:
    """Validate every member of a ``.zip`` archive. Returns the member count."""
    count = 0
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            check_member_name(info.filename, root)
            mode = _zip_unix_mode(info)
            if mode:
                if stat.S_ISLNK(mode):
                    raise ArchiveViolation(
                        f"symlink member is not permitted: {info.filename!r}"
                    )
                if (
                    stat.S_ISCHR(mode)
                    or stat.S_ISBLK(mode)
                    or stat.S_ISFIFO(mode)
                    or stat.S_ISSOCK(mode)
                ):
                    raise ArchiveViolation(
                        f"special member is not permitted: {info.filename!r}"
                    )
            count += 1
    return count


def validate_targz(path: str, root: str) -> int:
    """Validate every member of a ``.tar.gz`` archive. Returns the member count."""
    count = 0
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            if member.type in _METADATA_TAR_TYPES:
                continue
            check_member_name(member.name, root)
            if member.issym() or member.islnk():
                raise ArchiveViolation(
                    f"link member is not permitted: {member.name!r}"
                )
            if any(getattr(member, predicate)() for predicate in _SPECIAL_TAR_PREDICATES):
                raise ArchiveViolation(
                    f"special member is not permitted: {member.name!r}"
                )
            if not (member.isfile() or member.isdir()):
                raise ArchiveViolation(
                    f"special member is not permitted: {member.name!r}"
                )
            count += 1
    return count


# --- Offline self-test -------------------------------------------------------


def _expect_violation(label: str, func, *args) -> bool:
    try:
        func(*args)
    except ArchiveViolation:
        return True
    except Exception as exc:  # noqa: BLE001 - report unexpected failure
        print(f"  FAIL {label}: unexpected {type(exc).__name__}: {exc}")
        return False
    print(f"  FAIL {label}: expected ArchiveViolation, none raised")
    return False


def _expect_ok(label: str, func, *args) -> bool:
    try:
        func(*args)
    except Exception as exc:  # noqa: BLE001 - report unexpected failure
        print(f"  FAIL {label}: unexpected {type(exc).__name__}: {exc}")
        return False
    return True


def run_self_test() -> bool:
    """Run the offline archive-validation self-tests. Returns True on success."""
    ok = True
    with tempfile.TemporaryDirectory(prefix="tooling-archive-selftest-") as tmp:
        root = os.path.join(tmp, "root")
        os.makedirs(root, exist_ok=True)

        safe_zip = os.path.join(tmp, "safe.zip")
        with zipfile.ZipFile(safe_zip, "w") as zf:
            zf.writestr("dir/file.txt", "data")
        ok &= _expect_ok("safe-zip", validate_zip, safe_zip, root)

        traversal_zip = os.path.join(tmp, "traversal.zip")
        with zipfile.ZipFile(traversal_zip, "w") as zf:
            zf.writestr("../escape.txt", "data")
        ok &= _expect_violation("zip-traversal", validate_zip, traversal_zip, root)

        destination_escape_zip = os.path.join(tmp, "dest-escape.zip")
        with zipfile.ZipFile(destination_escape_zip, "w") as zf:
            zf.writestr("sub/../../escape.txt", "data")
        ok &= _expect_violation(
            "zip-destination-escape", validate_zip, destination_escape_zip, root
        )

        absolute_zip = os.path.join(tmp, "absolute.zip")
        with zipfile.ZipFile(absolute_zip, "w") as zf:
            zf.writestr("/etc/passwd", "data")
        ok &= _expect_violation("zip-absolute", validate_zip, absolute_zip, root)

        drive_zip = os.path.join(tmp, "drive.zip")
        with zipfile.ZipFile(drive_zip, "w") as zf:
            zf.writestr("C:/Windows/evil", "data")
        ok &= _expect_violation("zip-drive", validate_zip, drive_zip, root)

        unc_zip = os.path.join(tmp, "unc.zip")
        with zipfile.ZipFile(unc_zip, "w") as zf:
            zf.writestr("\\\\server\\share\\evil", "data")
        ok &= _expect_violation("zip-unc", validate_zip, unc_zip, root)

        ok &= _expect_violation(
            "member-name-nul", check_member_name, "bad\x00name", root
        )
        ok &= _expect_violation(
            "member-name-control", check_member_name, "bad\nname", root
        )

        symlink_zip = os.path.join(tmp, "symlink.zip")
        with zipfile.ZipFile(symlink_zip, "w") as zf:
            info = zipfile.ZipInfo("link")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "/etc/passwd")
        ok &= _expect_violation("zip-symlink", validate_zip, symlink_zip, root)

        fifo_zip = os.path.join(tmp, "fifo.zip")
        with zipfile.ZipFile(fifo_zip, "w") as zf:
            info = zipfile.ZipInfo("pipe")
            info.external_attr = (stat.S_IFIFO | 0o644) << 16
            zf.writestr(info, "")
        ok &= _expect_violation("zip-special", validate_zip, fifo_zip, root)

        safe_tar = os.path.join(tmp, "safe.tar.gz")
        with tarfile.open(safe_tar, "w:gz") as tf:
            info = tarfile.TarInfo("dir/file.txt")
            payload = b"data"
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
        ok &= _expect_ok("safe-targz", validate_targz, safe_tar, root)

        traversal_tar = os.path.join(tmp, "traversal.tar.gz")
        with tarfile.open(traversal_tar, "w:gz") as tf:
            info = tarfile.TarInfo("../escape.txt")
            payload = b"data"
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
        ok &= _expect_violation("targz-traversal", validate_targz, traversal_tar, root)

        symlink_tar = os.path.join(tmp, "symlink.tar.gz")
        with tarfile.open(symlink_tar, "w:gz") as tf:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tf.addfile(info)
        ok &= _expect_violation("targz-symlink", validate_targz, symlink_tar, root)

        hardlink_tar = os.path.join(tmp, "hardlink.tar.gz")
        with tarfile.open(hardlink_tar, "w:gz") as tf:
            info = tarfile.TarInfo("hardlink")
            info.type = tarfile.LNKTYPE
            info.linkname = "dir/file.txt"
            tf.addfile(info)
        ok &= _expect_violation("targz-hardlink", validate_targz, hardlink_tar, root)

        device_tar = os.path.join(tmp, "device.tar.gz")
        with tarfile.open(device_tar, "w:gz") as tf:
            info = tarfile.TarInfo("dev")
            info.type = tarfile.CHRTYPE
            info.devmajor = 1
            info.devminor = 3
            tf.addfile(info)
        ok &= _expect_violation("targz-special", validate_targz, device_tar, root)

    if ok:
        print("archive self-test: all checks passed")
    else:
        print("archive self-test: FAILURES detected")
    return ok


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="validate_tool_archive.py",
        description="Validate archive members before extraction (offline).",
    )
    parser.add_argument("--archive", help="path to the archive to validate")
    parser.add_argument(
        "--type", choices=("zip", "targz"), help="archive type (zip or targz)"
    )
    parser.add_argument(
        "--root", help="extraction root the members must stay inside"
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        dest="self_test",
        help="run the offline self-tests and exit",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return 0 if run_self_test() else 1

    if not args.archive or not args.type or not args.root:
        parser.error("--archive, --type and --root are required (or use --self-test)")

    try:
        if args.type == "zip":
            members = validate_zip(args.archive, args.root)
        else:
            members = validate_targz(args.archive, args.root)
    except ArchiveViolation as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError, zipfile.BadZipFile, tarfile.TarError, EOFError) as exc:
        print(f"error: cannot read archive: {exc}", file=sys.stderr)
        return 3

    print(
        json.dumps(
            {
                "ok": True,
                "type": args.type,
                "members": members,
                "archive": args.archive,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
