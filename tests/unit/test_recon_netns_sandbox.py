"""Offline unit tests for the namespace sandbox launcher and route checks.

No namespace, process, or network is created on Windows; launch paths are
asserted to fail closed with ``SandboxUnsupported``. Route parsing is pure.
"""

import sys
import tempfile
import unittest
from pathlib import Path

from red_teaming.recon import netns_sandbox
from red_teaming.recon.netns_sandbox import (
    HELPER_MODULE,
    IP_PATH,
    PYTHON_PATH,
    UNSHARE_FLAGS,
    UNSHARE_PATH,
    SandboxConfig,
    SandboxError,
    SandboxUnsupported,
    build_helper_argv,
    build_helper_env,
    ensure_sandbox_supported,
    launch_helper,
    routes_are_isolated,
    sandbox_supported,
    unsafe_route_lines,
)


def _config(**overrides):
    values = dict(
        connect_fd=10,
        dns_fd=11,
        status_fd=12,
        http_port=18080,
        dns_port=53,
        mode="serve",
    )
    values.update(overrides)
    return SandboxConfig(**values)


class PlatformTests(unittest.TestCase):
    def test_supported_matches_platform(self):
        self.assertEqual(sandbox_supported(), sys.platform.startswith("linux"))

    def test_ensure_supported_fails_closed_off_linux(self):
        if sandbox_supported():
            self.assertIsNone(ensure_sandbox_supported())
        else:
            with self.assertRaises(SandboxUnsupported):
                ensure_sandbox_supported()

    def test_launch_fails_closed_off_linux(self):
        if sandbox_supported():
            self.skipTest("Linux host")
        with self.assertRaises(SandboxUnsupported):
            launch_helper(_config(src_path=str(Path(tempfile.gettempdir()))))


@unittest.skipUnless(sandbox_supported(), "Linux/WSL only")
class LaunchTests(unittest.TestCase):
    def test_launch_passes_exact_fds_and_is_shell_free(self):
        captured = {}

        def fake_popen(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return object()

        config = _config(src_path="/tmp")
        launch_helper(config, popen=fake_popen, base_env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(
            captured["kwargs"]["pass_fds"],
            (config.connect_fd, config.dns_fd, config.status_fd),
        )
        self.assertFalse(captured["kwargs"]["shell"])
        self.assertEqual(captured["argv"], list(build_helper_argv(config)))
        self.assertEqual(
            captured["kwargs"]["env"]["PYTHONPATH"],
            "/tmp",
        )
        self.assertEqual(captured["kwargs"]["env"]["PYTHONDONTWRITEBYTECODE"], "1")


class ArgvTests(unittest.TestCase):
    def test_exact_unshare_prefix_and_helper_arguments(self):
        argv = build_helper_argv(_config())
        self.assertEqual(argv[0], UNSHARE_PATH)
        self.assertEqual(argv[1:4], UNSHARE_FLAGS)
        self.assertEqual(argv[4], "--")
        self.assertEqual(argv[5], PYTHON_PATH)
        self.assertEqual(argv[6:8], ("-m", HELPER_MODULE))
        joined = " ".join(argv)
        for expected in (
            "--user",
            "--map-root-user",
            "--net",
            "--connect-fd 10",
            "--dns-fd 11",
            "--status-fd 12",
            "--http-port 18080",
            "--dns-port 53",
            f"--ip-path {IP_PATH}",
        ):
            self.assertIn(expected, joined)
        self.assertNotIn("-c", argv)
        self.assertNotIn("sh", argv)

    def test_config_validation(self):
        with self.assertRaises(SandboxError):
            _config(connect_fd=-1)
        with self.assertRaises(SandboxError):
            _config(http_port=0)
        with self.assertRaises(SandboxError):
            _config(mode="nope")
        with self.assertRaises(SandboxError):
            _config(unshare_path="relative/unshare")
        with self.assertRaises(SandboxError):
            _config(module="not a module")
        with self.assertRaises(SandboxError):
            _config(src_path="relative/src")


class EnvTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.src = str(Path(self._tmp.name) / "src")

    def tearDown(self):
        self._tmp.cleanup()

    def test_minimal_env_drops_proxies_and_secrets(self):
        base = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "HTTPS_PROXY": "http://proxy.local:8080",
            "API_TOKEN": "secret",
            "AWS_SECRET_ACCESS_KEY": "secret",
            "RANDOM": "nope",
        }
        env = build_helper_env(self.src, base_env=base)
        self.assertEqual(env["PATH"], "/usr/bin:/bin")
        self.assertEqual(env["PYTHONPATH"], self.src)
        self.assertEqual(env["PYTHONDONTWRITEBYTECODE"], "1")
        for forbidden in ("HTTPS_PROXY", "API_TOKEN", "AWS_SECRET_ACCESS_KEY", "RANDOM"):
            self.assertNotIn(forbidden, env)
        self.assertFalse(any("proxy" in name.lower() for name in env))

    def test_extra_secret_like_name_rejected(self):
        with self.assertRaises(SandboxError):
            build_helper_env(self.src, base_env={}, extra={"HTTP_PROXY": "x"})

    def test_requires_absolute_src(self):
        with self.assertRaises(SandboxError):
            build_helper_env("relative/src", base_env={})


class RouteIsolationTests(unittest.TestCase):
    def test_empty_is_isolated(self):
        self.assertTrue(routes_are_isolated("", ""))
        self.assertEqual(unsafe_route_lines(""), ())

    def test_loopback_local_routes_are_safe(self):
        self.assertTrue(routes_are_isolated("local 1.1.1.1 dev lo", "local ::1 dev lo"))
        self.assertEqual(unsafe_route_lines("local 127.0.0.0/8 dev lo"), ())

    def test_default_and_non_loopback_routes_are_unsafe(self):
        self.assertFalse(routes_are_isolated("default via 172.17.0.1 dev eth0", ""))
        self.assertFalse(routes_are_isolated("10.0.0.0/8 dev eth0 scope link", ""))
        self.assertFalse(routes_are_isolated("", "fe80::/64 dev eth0 proto kernel"))
        self.assertEqual(
            unsafe_route_lines("default via 172.17.0.1 dev eth0"),
            ("default via 172.17.0.1 dev eth0",),
        )

    def test_non_text_is_unsafe(self):
        self.assertFalse(routes_are_isolated(None, ""))
        self.assertEqual(unsafe_route_lines(None), ("<non-text route output>",))


if __name__ == "__main__":
    unittest.main()
