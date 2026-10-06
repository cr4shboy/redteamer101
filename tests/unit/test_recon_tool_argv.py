"""Offline tests for exact tool-command specs and argv validation."""

import unittest

from red_teaming.recon.tool_argv import (
    INSPECTION,
    LIVE,
    ArgvError,
    ToolCommandSpec,
    classify_argv,
    expected_live_argv,
    inspection_argvs,
    is_inspection_argv,
    is_live_argv,
    required_markers_for,
)

ROOT = "acme.example"
BIN = "/opt/.tools/wsl/subfinder/2.16.0/subfinder"


def subfinder_spec():
    return ToolCommandSpec(tool="subfinder", version="2.16.0", binary=BIN, root=ROOT)


def dnsx_spec():
    return ToolCommandSpec(tool="dnsx", version="1.3.1", binary=BIN, root=ROOT)


def amass_spec(domain_option="-d", output_prefix="/work/amass-enum"):
    return ToolCommandSpec(
        tool="amass",
        version="5.1.1",
        binary=BIN,
        root=ROOT,
        domain_option=domain_option,
        output_prefix=output_prefix,
    )


class SpecTests(unittest.TestCase):
    def test_exact_live_argv(self):
        self.assertEqual(
            expected_live_argv(subfinder_spec()),
            (BIN, "-d", ROOT, "-s", "crtsh", "-json", "-silent", "-rl", "1", "-duc"),
        )
        self.assertEqual(
            expected_live_argv(dnsx_spec()),
            (
                BIN,
                "-json",
                "-a",
                "-aaaa",
                "-cname",
                "-silent",
                "-r",
                "1.1.1.1:53",
                "-rl",
                "5",
                "-t",
                "2",
                "-duc",
            ),
        )
        self.assertEqual(
            expected_live_argv(amass_spec()),
            (
                BIN,
                "enum",
                "-passive",
                "-d",
                ROOT,
                "-oA",
                "/work/amass-enum",
                "-include",
                "crtsh",
            ),
        )

    def test_required_markers_cover_every_flag(self):
        for spec in (subfinder_spec(), dnsx_spec(), amass_spec()):
            markers = required_markers_for(spec)
            for item in expected_live_argv(spec)[1:]:
                if item.startswith("-"):
                    self.assertIn(item, markers)

    def test_rejects_other_root(self):
        with self.assertRaises(ArgvError):
            ToolCommandSpec(tool="dnsx", version="1.3.1", binary=BIN, root="example.com")

    def test_amass_requires_output_and_valid_domain_option(self):
        with self.assertRaises(ArgvError):
            ToolCommandSpec(tool="amass", version="5.1.1", binary=BIN, root=ROOT)
        with self.assertRaises(ArgvError):
            ToolCommandSpec(
                tool="amass",
                version="5.1.1",
                binary=BIN,
                root=ROOT,
                domain_option="-x",
                output_prefix="/w/a",
            )

    def test_unsupported_tool(self):
        with self.assertRaises(ArgvError):
            expected_live_argv(
                ToolCommandSpec(tool="nmap", version="1", binary=BIN, root=ROOT)
            )


class ClassifyTests(unittest.TestCase):
    def test_live_and_inspection(self):
        spec = subfinder_spec()
        self.assertEqual(classify_argv(spec, expected_live_argv(spec)), LIVE)
        for form in inspection_argvs(spec):
            self.assertEqual(classify_argv(spec, form), INSPECTION)

    def test_rejects_arbitrary_binary_and_args(self):
        spec = subfinder_spec()
        bad = [
            ("/bin/sh", "-c", "id"),
            (BIN, "-d", ROOT, "-all"),
            (BIN,),
            (BIN, "-d", "example.com", "-json", "-silent", "-s", "crtsh", "-rl", "1", "-duc"),
            (BIN, "-version", "extra"),
        ]
        for argv in bad:
            with self.subTest(argv=argv):
                self.assertFalse(is_live_argv(spec, argv))
                self.assertFalse(is_inspection_argv(spec, argv))
                with self.assertRaises(ArgvError):
                    classify_argv(spec, argv)

    def test_amass_inspection_uses_enum(self):
        spec = amass_spec()
        self.assertTrue(is_inspection_argv(spec, (BIN, "-version")))
        self.assertTrue(is_inspection_argv(spec, (BIN, "enum", "-help")))
        # The short/reserved ``-h`` form (and the bare top-level ``-h``) is not
        # an allowlisted Amass inspection command.
        self.assertFalse(is_inspection_argv(spec, (BIN, "enum", "-h")))
        self.assertFalse(is_inspection_argv(spec, (BIN, "-h")))
        self.assertFalse(is_inspection_argv(spec, (BIN, "enum", "--help")))

    def test_string_argv_rejected(self):
        with self.assertRaises(ArgvError):
            classify_argv(subfinder_spec(), "not-a-list")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
