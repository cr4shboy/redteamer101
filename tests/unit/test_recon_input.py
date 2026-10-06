"""Unit tests for bounded recon scope input parsing."""

import tempfile
import unittest
from pathlib import Path

from red_teaming.projects.models import ValidationError
from red_teaming.recon.input import (
    MAX_INPUT_BYTES,
    InputError,
    parse_entries,
    read_entries,
    read_text,
)
from red_teaming.recon.scope import DomainScope


class ParseEntriesTests(unittest.TestCase):
    def test_ignores_blank_lines_and_comments(self):
        text = "# comment\n\nexample.com\n   \n# another\napi.example.org\n"
        self.assertEqual(parse_entries(text), ("example.com", "api.example.org"))

    def test_inline_hash_is_not_a_comment(self):
        self.assertEqual(parse_entries("example.com # note\n"), ("example.com # note",))

    def test_entry_whitespace_is_preserved(self):
        self.assertEqual(parse_entries(" example.com \n"), (" example.com ",))
        self.assertEqual(parse_entries("\texample.com\n"), ("\texample.com",))

    def test_whitespace_entries_are_rejected_by_scope(self):
        for text in (" example.com \n", "\texample.com\n", "example.com \n"):
            with self.subTest(text=text):
                with self.assertRaises(ValidationError):
                    DomainScope.parse(parse_entries(text))

    def test_indented_comment_is_ignored(self):
        self.assertEqual(parse_entries("   # comment\n\texample.com\n"), ("\texample.com",))

    def test_entry_count_is_bounded(self):
        text = "\n".join(f"h{i}.example.com" for i in range(5))
        self.assertEqual(parse_entries(text, max_entries=5), tuple(
            f"h{i}.example.com" for i in range(5)
        ))
        with self.assertRaises(InputError):
            parse_entries(text, max_entries=4)

    def test_non_string_is_rejected(self):
        with self.assertRaises(InputError):
            parse_entries(None)

    def test_scope_rejects_url_ip_wildcard(self):
        with self.assertRaises(ValidationError):
            DomainScope.parse(parse_entries("http://example.com\n"))
        with self.assertRaises(ValidationError):
            DomainScope.parse(parse_entries("192.0.2.1\n"))
        with self.assertRaises(ValidationError):
            DomainScope.parse(parse_entries("*.example.com\n"))


class ReadTextTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_rejects_relative_and_missing(self):
        with self.assertRaises(InputError):
            read_text("relative.txt")
        with self.assertRaises(InputError):
            read_text(self.root / "missing.txt")

    def test_bounds_bytes(self):
        path = self.root / "big.txt"
        path.write_text("x" * (MAX_INPUT_BYTES + 1), encoding="utf-8")
        with self.assertRaises(InputError):
            read_text(path)

    def test_rejects_invalid_utf8(self):
        path = self.root / "bad.txt"
        path.write_bytes(b"\xff\xfe\x00")
        with self.assertRaises(InputError):
            read_text(path)

    def test_strips_utf8_bom(self):
        path = self.root / "bom.txt"
        path.write_bytes("\ufeffexample.com\n".encode("utf-8"))
        self.assertEqual(read_entries(path), ("example.com",))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
