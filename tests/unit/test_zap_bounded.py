"""Offline tests for the bounded, keyless, guarded Stage 2 Spider profile.

No socket, DNS, process, or target call occurs: every guard, manager, client,
transport, and inspector is faked. The production runner accepts neither an API
key nor a capability override, so the guarded launch seam is the *only* path and
is exercised directly.
"""

import json
import tempfile
import types
import unittest
from pathlib import Path

from red_teaming.tools.zap import bounded
from red_teaming.tools.zap.bounded import (
    ALLOWED_OPERATIONS,
    GUARD_HOST,
    GUARD_PORT,
    LAUNCH_HARDENING_PAIRS,
    PRELAUNCH_FILENAME,
    PROXY_CONFIG_PAIRS,
    SILENT_FLAG,
    SPIDER_CONFIG_PAIRS,
    STAGE2_SEED,
    ApiCallRecorder,
    Stage2AllowlistError,
    Stage2AllowlistedTransport,
    Stage2ApiClient,
    Stage2PreflightError,
    Stage2ProfileError,
    Stage2SpiderRunner,
    Stage2TargetPolicy,
    build_stage2_profile,
    evaluate_prelaunch_controls,
    evaluate_runtime_controls,
    read_callhome_config,
    read_proxy_config,
    read_spider_config,
)
from red_teaming.tools.zap.lifecycle import (
    ConnectionRecord,
    ProcessRecord,
    SystemSnapshot,
)
from red_teaming.tools.zap.models import HttpResponse, ZapConfigError
from red_teaming.tools.zap.process import (
    OFFLINE_CONFIG_CALLHOME_TEL_ENABLED,
    ZapProcessManager,
)

SCAN_ID = "20261003T120000Z-abc123"
PROJECT_MARKERS = ("AGENTS.md", "PROJECT.md", "CURRENT_TASK.md")
API_PORT = 18080
ZAP_PID = 4321
GUARD_PID = 5555
PINNED_A = "8.8.8.8"
PINNED_B = "1.1.1.1"
TARGET_HOST = "acme.example"
TARGET_PORT = 443


def make_checkout_root(root: Path) -> Path:
    for marker in PROJECT_MARKERS:
        (root / marker).write_text("marker\n", encoding="utf-8")
    (root / "projects").mkdir()
    return root


def write_config(
    zap_home: Path,
    *,
    overrides=None,
    proxy_overrides=None,
    callhome_overrides=None,
    omit_spider: bool = False,
    omit_proxy: bool = False,
    omit_callhome: bool = False,
) -> Path:
    zap_home.mkdir(parents=True, exist_ok=True)
    values = {
        "maxDepth": "3",
        "thread": "1",
        "maxDuration": "5",
        "requestwait": "1000",
        "processform": "false",
        "postform": "false",
    }
    if overrides:
        values.update(overrides)
    spider_children = "".join(f"<{k}>{v}</{k}>" for k, v in values.items())
    spider = "" if omit_spider else f'<spider version="3">{spider_children}</spider>'
    proxy_values = {"enabled": "true", "host": GUARD_HOST, "port": str(GUARD_PORT)}
    if proxy_overrides:
        proxy_values.update(proxy_overrides)
    proxy_children = "".join(f"<{k}>{v}</{k}>" for k, v in proxy_values.items())
    proxy = (
        ""
        if omit_proxy
        else (
            "<network><connection version=\"6\"><httpProxy>"
            f"{proxy_children}"
            "</httpProxy></connection></network>"
        )
    )
    callhome_values = {"uuid": "11111111-2222-3333-4444-555555555555", "enabled": "false"}
    if callhome_overrides:
        callhome_values.update(callhome_overrides)
    callhome_children = "".join(
        f"<{k}>{v}</{k}>" for k, v in callhome_values.items()
    )
    callhome = (
        ""
        if omit_callhome
        else f'<callhome version="1"><tel>{callhome_children}</tel></callhome>'
    )
    config = (
        '<?xml version="1.0"?>\n'
        f"<config>{spider}{proxy}{callhome}</config>\n"
    )
    path = zap_home / "config.xml"
    path.write_text(config, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeRawClient:
    def __init__(self, *, version="2.17.0", spider_results=(), fail_on=None, error=None,
                 on_start_spider=None):
        self.version = version
        self._spider_results = list(spider_results)
        self.fail_on = fail_on
        self.error = error
        self.on_start_spider = on_start_spider
        self.calls = []

    def _record(self, name, *args, **kwargs):
        self.calls.append((name,) + args + (kwargs,))
        if self.fail_on == name:
            raise self.error

    def get_version(self):
        return self.version

    def create_context(self, name):
        self._record("create_context", name)
        return 7

    def include_in_context(self, name, regex):
        self._record("include_in_context", name, regex)

    def start_spider(self, url, **kwargs):
        self._record("start_spider", url, **kwargs)
        if self.on_start_spider is not None:
            self.on_start_spider()
        return 0

    def spider_status(self, scan_id):
        self._record("spider_status", scan_id)
        return 100

    def spider_results(self, scan_id):
        self._record("spider_results", scan_id)
        return list(self._spider_results)

    def stop_spider(self, scan_id):
        self._record("stop_spider", scan_id)

    def shutdown(self):
        self._record("shutdown")

    def method_names(self):
        return [call[0] for call in self.calls]


def clean_lifecycle(*, shutdown_overrides=None):
    shutdown = {
        "mode": "identities_verified",
        "api_attempted": True,
        "api_result": "sent",
        "api_error": None,
        "result": "graceful",
        "daemon_running_after": False,
        "api_port_closed": True,
        "callback_port_closed": True,
        "both_ports_closed": True,
        "fallbacks": [],
        "control_errors": [],
        "process_exited": True,
        "launcher_exit_code": 0,
    }
    if shutdown_overrides:
        shutdown.update(shutdown_overrides)
    return {
        "launcher": {"pid": ZAP_PID - 1, "exit_code": 0, "running": False},
        "daemon": None,
        "daemon_running": False,
        "identity": None,
        "detach": None,
        "ready": None,
        "pre_shutdown": None,
        "final": None,
        "shutdown": shutdown,
    }


class FakeManager:
    def __init__(self, *, zap_home, version="2.17.0", daemon_pid=ZAP_PID,
                 launcher_pid=ZAP_PID - 1, start_error=None, stop_error=None,
                 shutdown_overrides=None, lifecycle_error=None,
                 lifecycle_provider=None):
        self.zap_home = Path(zap_home)
        self.version = version
        self.daemon_pid = daemon_pid
        self.launcher_pid = launcher_pid
        self.running = False
        self.started = 0
        self.stopped = 0
        self.kwargs = {}
        self.start_error = start_error
        self.stop_error = stop_error
        self._shutdown_overrides = shutdown_overrides
        self._lifecycle_error = lifecycle_error
        self._lifecycle_provider = lifecycle_provider

    def start(self):
        self.started += 1
        if self.start_error is not None:
            raise self.start_error
        self.running = True

    def wait_until_ready(self):
        return self.version

    def stop(self):
        self.stopped += 1
        if self.stop_error is not None:
            raise self.stop_error
        self.running = False

    def lifecycle_evidence(self):
        if self._lifecycle_error is not None:
            raise self._lifecycle_error
        if self._lifecycle_provider is not None:
            return self._lifecycle_provider()
        return clean_lifecycle(shutdown_overrides=self._shutdown_overrides)

    def safe_command(self):
        return ["zap.bat", "-daemon", "-config", "api.disablekey=true"]


class FakeGuard:
    """Lifecycle fake for the exact-host CONNECT egress guard."""

    def __init__(
        self,
        *,
        pinned_ips=(PINNED_A,),
        bind_host=GUARD_HOST,
        bind_port=GUARD_PORT,
        target_host=TARGET_HOST,
        target_port=TARGET_PORT,
        records=None,
        counters=None,
        prepare_error=None,
        start_error=None,
        stop_error=None,
        stop_noop=False,
        pid=GUARD_PID,
    ):
        self._pinned = tuple(pinned_ips)
        self._bind_host = bind_host
        self._bind_port = bind_port
        self._target = (target_host, target_port)
        self._records = list(records or [])
        self._counters = dict(counters or {"denied": 0, "errors": 0})
        self.prepare_error = prepare_error
        self.start_error = start_error
        self.stop_error = stop_error
        self.stop_noop = stop_noop
        self.pid = pid
        self.prepared = False
        self.running = False
        self.prepare_calls = 0
        self.start_calls = 0
        self.stop_calls = 0
        self.denied = False

    @property
    def bind_host(self):
        return self._bind_host

    @property
    def bind_port(self):
        return self._bind_port

    @property
    def target_endpoint(self):
        return self._target

    @property
    def pinned_ips(self):
        return self._pinned

    def prepare(self):
        self.prepare_calls += 1
        if self.prepare_error is not None:
            raise self.prepare_error
        self.prepared = True
        return self

    def start(self):
        self.start_calls += 1
        if self.start_error is not None:
            raise self.start_error
        self.running = True
        return self

    def stop(self):
        self.stop_calls += 1
        if self.stop_error is not None:
            raise self.stop_error
        if not self.stop_noop:
            self.running = False

    def get_records(self):
        records = list(self._records)
        if self.denied:
            records.append({"decision": "denied", "reason": "host_not_allowed"})
        return records

    def evidence(self):
        counters = dict(self._counters)
        records = list(self._records)
        if self.denied:
            counters["denied"] = counters.get("denied", 0) + 1
            records.append({"decision": "denied", "reason": "host_not_allowed"})
        return {
            "guard": "connect-egress",
            "running": self.running,
            "prepared": self.prepared,
            "bind_endpoint": f"{self._bind_host}:{self._bind_port}",
            "target": {
                "scheme": "https",
                "host": self._target[0],
                "port": self._target[1],
            },
            "pinned_ips": list(self._pinned),
            "counters": counters,
            "records": records,
        }


class FakeSystem:
    def __init__(self, provider):
        self._provider = provider
        self.snapshots = []

    def snapshot(self):
        snapshot = self._provider() if callable(self._provider) else self._provider
        self.snapshots.append(snapshot)
        return snapshot


def snapshot_provider(
    *,
    manager,
    guard,
    zap_pid=ZAP_PID,
    guard_pid=GUARD_PID,
    zap_external=None,
    guard_external=None,
    method="fake-inspection",
    always_listen=False,
    guard_listener_on=True,
    guard_listener_pid=None,
    guard_listener_address="127.0.0.1",
):
    """Build a provider reflecting live manager/guard listener state."""

    guard_owner = guard_pid if guard_listener_pid is None else guard_listener_pid

    def provider():
        connections = []
        if manager.running or always_listen:
            connections.append(
                ConnectionRecord(
                    local_address="127.0.0.1",
                    local_port=API_PORT,
                    remote_address="0.0.0.0",
                    remote_port=0,
                    state="Listen",
                    pid=zap_pid,
                )
            )
        if (guard.running or always_listen) and guard_listener_on:
            connections.append(
                ConnectionRecord(
                    local_address=guard_listener_address,
                    local_port=GUARD_PORT,
                    remote_address="0.0.0.0",
                    remote_port=0,
                    state="Listen",
                    pid=guard_owner,
                )
            )
        if zap_external and manager.running:
            connections.append(
                ConnectionRecord(
                    local_address="127.0.0.1",
                    local_port=55000,
                    remote_address=zap_external[0],
                    remote_port=zap_external[1],
                    state="Established",
                    pid=zap_pid,
                )
            )
        if guard_external and guard.running:
            connections.append(
                ConnectionRecord(
                    local_address="127.0.0.1",
                    local_port=55001,
                    remote_address=guard_external[0],
                    remote_port=guard_external[1],
                    state="Established",
                    pid=guard_pid,
                )
            )
        processes = (
            ProcessRecord(
                pid=zap_pid,
                parent_pid=zap_pid - 1,
                name="javaw.exe",
                command_line="javaw",
                creation_time=100.0,
            ),
        )
        return SystemSnapshot(
            method=method, processes=processes, connections=tuple(connections)
        )

    return provider


# ---------------------------------------------------------------------------
# Base test case + harness
# ---------------------------------------------------------------------------


class BoundedTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = make_checkout_root(Path(self._tmp.name))
        self.scan_id = SCAN_ID
        self.output_dir = (
            self.root
            / "projects"
            / "acme.example"
            / "targets"
            / "acme.example"
            / "scans"
            / "zap"
            / self.scan_id
        )
        self.exe = self.root / "zap.exe"
        self.exe.write_bytes(b"")

    def build_profile(self, **overrides):
        options = dict(
            workspace_root=self.root,
            output_dir=self.output_dir,
            zap_executable=self.exe,
            expected_root=self.root,
        )
        options.update(overrides)
        return build_stage2_profile(**options)

    def build_harness(
        self,
        *,
        guard=None,
        manager=None,
        raw=None,
        zap_external=None,
        guard_external=None,
        method="fake-inspection",
        always_listen=False,
        write_file=True,
        spider_overrides=None,
        proxy_overrides=None,
        callhome_overrides=None,
        omit_spider=False,
        omit_proxy=False,
        omit_callhome=False,
        guard_factory=None,
        manager_kwargs_hook=None,
        output_dir=None,
        guard_listener_on=True,
        guard_listener_pid=None,
        guard_listener_address="127.0.0.1",
    ):
        profile = (
            self.build_profile(output_dir=output_dir)
            if output_dir is not None
            else self.build_profile()
        )
        zap_home = profile.scan_path.scan_dir / "zap-home"
        if write_file:
            write_config(
                zap_home,
                overrides=spider_overrides,
                proxy_overrides=proxy_overrides,
                callhome_overrides=callhome_overrides,
                omit_spider=omit_spider,
                omit_proxy=omit_proxy,
                omit_callhome=omit_callhome,
            )
        raw = raw if raw is not None else FakeRawClient(spider_results=[{"url": STAGE2_SEED}])
        mgr = manager if manager is not None else FakeManager(zap_home=zap_home)
        grd = guard if guard is not None else FakeGuard()
        provider = snapshot_provider(
            manager=mgr,
            guard=grd,
            zap_external=zap_external,
            guard_external=guard_external,
            method=method,
            always_listen=always_listen,
            guard_listener_on=guard_listener_on,
            guard_listener_pid=guard_listener_pid,
            guard_listener_address=guard_listener_address,
        )
        system = FakeSystem(provider)

        def manager_factory(**kwargs):
            mgr.kwargs = kwargs
            if manager_kwargs_hook is not None:
                manager_kwargs_hook(kwargs)
            return mgr

        factory = guard_factory if guard_factory is not None else (lambda: grd)
        runner = Stage2SpiderRunner(
            profile=profile,
            system=system,
            manager_factory=manager_factory,
            client_factory=lambda endpoint, transport: Stage2ApiClient(raw, profile),
            transport_factory=lambda inner: Stage2AllowlistedTransport(
                inner, endpoint=profile.endpoint, recorder=ApiCallRecorder(lambda: "t")
            ),
            guard_factory=factory,
            now=lambda: "2026-10-03T00:00:00Z",
        )
        return types.SimpleNamespace(
            runner=runner,
            raw=raw,
            manager=mgr,
            guard=grd,
            system=system,
            profile=profile,
            zap_home=zap_home,
        )


# ---------------------------------------------------------------------------
# Runner construction: no key / capability arguments
# ---------------------------------------------------------------------------


class KeylessConstructionTests(BoundedTestCase):
    def test_runner_accepts_no_api_key_or_capability_arguments(self):
        profile = self.build_profile()
        with self.assertRaises(TypeError):
            Stage2SpiderRunner(profile=profile, api_key="leaked")
        with self.assertRaises(TypeError):
            Stage2SpiderRunner(
                profile=profile, capabilities=object()
            )
        # The keyless/guarded constructor succeeds with the profile only.
        runner = Stage2SpiderRunner(profile=profile)
        self.assertIsNone(runner._guard)


# ---------------------------------------------------------------------------
# Profile / target policy (unchanged behavior)
# ---------------------------------------------------------------------------


class ProfileTests(BoundedTestCase):
    def test_valid_profile_is_exact(self):
        profile = self.build_profile()
        self.assertEqual(profile.domain, "acme.example")
        self.assertEqual(profile.mode, "spider")
        self.assertEqual(profile.target.url, STAGE2_SEED)
        self.assertEqual(profile.target.host, "acme.example")
        self.assertEqual(profile.target.port, 443)
        self.assertTrue(profile.artifact_route_ok)
        self.assertTrue(profile.scope_regex_is_exact)

    def test_non_loopback_endpoint_is_rejected(self):
        with self.assertRaises(Stage2ProfileError):
            self.build_profile(zap_host="10.0.0.5")

    def test_output_must_be_canonical_acme_route(self):
        bad = (
            self.root
            / "projects"
            / "example.com"
            / "targets"
            / "example.com"
            / "scans"
            / "zap"
            / self.scan_id
        )
        with self.assertRaises(Stage2ProfileError):
            self.build_profile(output_dir=bad)

    def test_spider_timeout_over_300_is_rejected(self):
        with self.assertRaises(Stage2ProfileError):
            self.build_profile(spider_timeout=301.0)

    def test_existing_output_dir_is_rejected(self):
        self.output_dir.mkdir(parents=True)
        with self.assertRaises(Stage2ProfileError):
            self.build_profile()


class TargetPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = Stage2TargetPolicy()

    def test_allows_exact_host_urls(self):
        for url in (
            "https://acme.example/",
            "https://acme.example/path?q=1",
            "https://acme.example:443/x",
        ):
            with self.subTest(url=url):
                self.assertTrue(self.policy.is_allowed_url(url))

    def test_rejects_out_of_host_and_scheme(self):
        for url in (
            "http://acme.example/",
            "https://sub.acme.example/",
            "https://acme.example.evil.test/",
            "https://evil.test/",
            "https://acme.example:8443/",
            "https://user:pass@acme.example/",
            "ftp://acme.example/",
            "",
            None,
        ):
            with self.subTest(url=url):
                self.assertFalse(self.policy.is_allowed_url(url))

    def test_result_violations(self):
        results = [
            {"url": "https://acme.example/a"},
            {"url": "https://evil.test/b"},
            {"url": "http://acme.example/c"},
            {"other": "ignored"},
        ]
        self.assertEqual(
            self.policy.result_violations(results),
            ["https://evil.test/b", "http://acme.example/c"],
        )


# ---------------------------------------------------------------------------
# Allowlist transport (now secret-free)
# ---------------------------------------------------------------------------


class FakeTransport:
    def __init__(self):
        self.requests = []

    def request(self, method, url, timeout):
        self.requests.append((method, url, timeout))
        return HttpResponse(200, b'{"ok": true}')


class AllowlistTests(unittest.TestCase):
    def setUp(self):
        from red_teaming.tools.zap.models import ZapEndpoint

        self.endpoint = ZapEndpoint.from_host_port("127.0.0.1", API_PORT)
        self.recorder = ApiCallRecorder(lambda: "t")
        self.inner = FakeTransport()
        self.transport = Stage2AllowlistedTransport(
            self.inner, endpoint=self.endpoint, recorder=self.recorder
        )

    def _url(self, tail):
        return f"http://127.0.0.1:{API_PORT}/JSON/{tail}/"

    def test_allowed_operations_pass_through(self):
        for tail in (
            "core/view/version",
            "context/action/newContext",
            "context/action/includeInContext",
            "spider/action/scan",
            "spider/view/status",
            "spider/view/results",
            "spider/action/stop",
            "core/action/shutdown",
        ):
            with self.subTest(tail=tail):
                self.transport.request("GET", self._url(tail), 1.0)
        self.assertEqual(len(self.inner.requests), 8)

    def test_forbidden_operations_rejected_before_inner(self):
        for tail in (
            "core/action/accessUrl",
            "ajaxSpider/action/scan",
            "ajaxSpider/view/status",
            "ascan/action/scan",
            "pscan/view/recordsToScan",
            "core/action/shutdownNow",
            "reports/action/generate",
            "import/action/importUrl",
        ):
            with self.subTest(tail=tail):
                with self.assertRaises(Stage2AllowlistError):
                    self.transport.request("GET", self._url(tail), 1.0)
        self.assertEqual(self.inner.requests, [])
        self.assertTrue(all(not c["allowed"] for c in self.recorder.calls))

    def test_wrong_host_or_port_is_rejected(self):
        for url in (
            f"http://localhost:{API_PORT}/JSON/core/view/version/",
            f"http://127.0.0.1:{API_PORT + 1}/JSON/core/view/version/",
            f"http://evil.test:{API_PORT}/JSON/core/view/version/",
        ):
            with self.subTest(url=url):
                with self.assertRaises(Stage2AllowlistError):
                    self.transport.request("GET", url, 1.0)

    def test_allowlist_has_no_access_url_or_ajax(self):
        self.assertNotIn(("core", "action", "accessUrl"), ALLOWED_OPERATIONS)
        self.assertFalse(
            any(
                op[0].lower() in ("ajaxspider", "ascan", "pscan", "import", "reports")
                for op in ALLOWED_OPERATIONS
            )
        )


class ApiClientFacadeTests(BoundedTestCase):
    def test_facade_forces_exact_seed_context(self):
        profile = self.build_profile()
        raw = FakeRawClient()
        facade = Stage2ApiClient(raw, profile)
        facade.create_context()
        facade.include_in_context()
        scan_id = facade.start_spider(profile.target.url, context_name=profile.context_name)
        self.assertEqual(scan_id, 0)
        self.assertEqual(raw.calls[0], ("create_context", profile.context_name, {}))
        self.assertEqual(raw.calls[1][0], "include_in_context")
        self.assertEqual(raw.calls[2][1], STAGE2_SEED)

    def test_facade_rejects_foreign_host(self):
        profile = self.build_profile()
        facade = Stage2ApiClient(FakeRawClient(), profile)
        with self.assertRaises(Stage2ProfileError):
            facade.start_spider("https://evil.test/")

    def test_facade_has_no_access_url(self):
        profile = self.build_profile()
        facade = Stage2ApiClient(FakeRawClient(), profile)
        self.assertFalse(hasattr(facade, "access_url"))
        self.assertFalse(hasattr(facade, "start_ajax_spider"))


# ---------------------------------------------------------------------------
# config read-back / controls
# ---------------------------------------------------------------------------


class ReadConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.zap_home = Path(self._tmp.name) / "zap-home"

    def test_reads_spider_options(self):
        write_config(self.zap_home)
        options = read_spider_config(self.zap_home)
        self.assertEqual(options["maxDepth"], "3")
        self.assertEqual(options["thread"], "1")
        self.assertEqual(options["processform"], "false")

    def test_reads_proxy_options(self):
        write_config(self.zap_home)
        proxy = read_proxy_config(self.zap_home)
        self.assertEqual(proxy["enabled"], "true")
        self.assertEqual(proxy["host"], GUARD_HOST)
        self.assertEqual(proxy["port"], str(GUARD_PORT))

    def test_reads_callhome_options(self):
        write_config(self.zap_home)
        callhome = read_callhome_config(self.zap_home)
        self.assertEqual(callhome["enabled"], "false")

    def test_missing_config_raises(self):
        with self.assertRaises(Stage2PreflightError):
            read_spider_config(self.zap_home)
        with self.assertRaises(Stage2PreflightError):
            read_proxy_config(self.zap_home)
        with self.assertRaises(Stage2PreflightError):
            read_callhome_config(self.zap_home)

    def test_missing_sections_raise(self):
        write_config(self.zap_home, omit_spider=True)
        with self.assertRaises(Stage2PreflightError):
            read_spider_config(self.zap_home)
        write_config(self.zap_home, omit_proxy=True)
        with self.assertRaises(Stage2PreflightError):
            read_proxy_config(self.zap_home)
        write_config(self.zap_home, omit_callhome=True)
        with self.assertRaises(Stage2PreflightError):
            read_callhome_config(self.zap_home)


GOOD_GUARD = {
    "configured": True,
    "bind_host": GUARD_HOST,
    "bind_port": GUARD_PORT,
    "target": {"host": TARGET_HOST, "port": TARGET_PORT},
    "pinned_ips": [PINNED_A],
    "prepared": True,
    "running": True,
    "pid": GUARD_PID,
}

GOOD_PROXY = {"enabled": "true", "host": GUARD_HOST, "port": str(GUARD_PORT)}
GOOD_CALLHOME = {
    "uuid": "11111111-2222-3333-4444-555555555555",
    "enabled": "false",
}


class ControlEvaluationTests(BoundedTestCase):
    def setUp(self):
        super().setUp()
        self.profile = self.build_profile()
        self.good_spider = {
            "maxDepth": "3",
            "thread": "1",
            "maxDuration": "5",
            "requestwait": "1000",
            "processform": "false",
            "postform": "false",
        }

    def evaluate_runtime(self, **overrides):
        options = dict(
            version="2.17.0",
            spider_config=dict(self.good_spider),
            proxy_config=dict(GOOD_PROXY),
            callhome_config=dict(GOOD_CALLHOME),
            guard=dict(GOOD_GUARD),
            listener_ok=True,
            listener_detail="ok",
            identity_verified=True,
            zap_direct_egress_ok=True,
            guard_egress_ok=True,
            guard_records_clean=True,
            guard_listener_ok=True,
            scope_activated=True,
        )
        options.update(overrides)
        return evaluate_runtime_controls(self.profile, **options)

    def checks_by_name(self, checks):
        return {check.name: check for check in checks}

    def test_prelaunch_gate_is_clear_and_has_no_capability_blockers(self):
        checks = evaluate_prelaunch_controls(self.profile)
        self.assertTrue(all(check.active for check in checks), [c.name for c in checks if not c.active])
        names = {check.name for check in checks}
        self.assertIn("keyless_api_configured", names)
        self.assertIn("egress_guard_configured", names)
        self.assertNotIn("key_non_persistence_proven", names)
        self.assertNotIn("redirect_egress_prevention_proven", names)

    def test_silent_launch_control_is_prelaunch_active_with_flag_evidence(self):
        checks = self.checks_by_name(evaluate_prelaunch_controls(self.profile))
        self.assertIn("silent_launch_configured", checks)
        self.assertTrue(checks["silent_launch_configured"].active)
        self.assertEqual(
            checks["silent_launch_configured"].evidence.get("flag"), SILENT_FLAG
        )
        self.assertEqual(SILENT_FLAG, "-silent")

    def test_all_runtime_controls_active_when_everything_is_proven(self):
        checks = self.evaluate_runtime()
        self.assertTrue(all(check.active for check in checks), [c.name for c in checks if not c.active])

    def test_wrong_version_fails(self):
        checks = self.checks_by_name(self.evaluate_runtime(version="2.16.0"))
        self.assertFalse(checks["zap_version_exact"].active)

    def test_weak_spider_config_fails(self):
        for key, bad in (
            ("maxDepth", "5"),
            ("thread", "2"),
            ("maxDuration", "0"),
            ("requestwait", "200"),
        ):
            with self.subTest(key=key):
                config = dict(self.good_spider)
                config[key] = bad
                checks = self.checks_by_name(self.evaluate_runtime(spider_config=config))
                self.assertTrue(any(not c.active for c in checks.values()), key)

    def test_forms_enabled_fails(self):
        config = dict(self.good_spider)
        config["processform"] = "true"
        config["postform"] = "true"
        checks = self.checks_by_name(self.evaluate_runtime(spider_config=config))
        self.assertFalse(checks["no_form_processing_or_submission"].active)

    def test_proxy_config_must_be_exact(self):
        for proxy in (
            {"enabled": "false", "host": GUARD_HOST, "port": str(GUARD_PORT)},
            {"enabled": "true", "host": "10.0.0.1", "port": str(GUARD_PORT)},
            {"enabled": "true", "host": GUARD_HOST, "port": "1"},
            {},
        ):
            with self.subTest(proxy=proxy):
                checks = self.checks_by_name(self.evaluate_runtime(proxy_config=proxy))
                self.assertFalse(checks["proxy_config_exact"].active)

    def test_callhome_telemetry_must_be_explicitly_false(self):
        checks = self.checks_by_name(self.evaluate_runtime())
        self.assertTrue(checks["callhome_telemetry_disabled"].active)
        for callhome in (
            {"uuid": "x", "enabled": "true"},
            {"uuid": "x"},
            {},
            {"uuid": "x", "enabled": "maybe"},
        ):
            with self.subTest(callhome=callhome):
                checks = self.checks_by_name(
                    self.evaluate_runtime(callhome_config=callhome)
                )
                self.assertFalse(checks["callhome_telemetry_disabled"].active)

    def test_guard_controls_fail_closed(self):
        variants = {
            "guard_endpoint_exact": {"bind_port": 9999},
            "guard_target_exact": {"target": {"host": "evil.test", "port": 443}},
            "guard_pinned_ips_global": {"pinned_ips": []},
            "guard_running": {"running": False},
        }
        for name, override in variants.items():
            with self.subTest(name=name):
                guard = dict(GOOD_GUARD)
                guard.update(override)
                checks = self.checks_by_name(self.evaluate_runtime(guard=guard))
                self.assertFalse(checks[name].active)

    def test_runtime_egress_and_record_failures(self):
        checks = self.checks_by_name(self.evaluate_runtime(zap_direct_egress_ok=False))
        self.assertFalse(checks["zap_no_direct_egress_established"].active)
        checks = self.checks_by_name(self.evaluate_runtime(guard_egress_ok=False))
        self.assertFalse(checks["guard_egress_within_pinned_set"].active)
        checks = self.checks_by_name(self.evaluate_runtime(guard_records_clean=False))
        self.assertFalse(checks["guard_no_denied_or_error_records"].active)
        checks = self.checks_by_name(self.evaluate_runtime(guard_listener_ok=False))
        self.assertFalse(checks["guard_listener_exact"].active)

    def test_listener_and_identity_failures(self):
        checks = self.checks_by_name(self.evaluate_runtime(listener_ok=False))
        self.assertFalse(checks["api_loopback_only"].active)
        checks = self.checks_by_name(self.evaluate_runtime(identity_verified=False))
        self.assertFalse(checks["daemon_identity_unambiguous"].active)

    def test_scope_activated_control_reflects_api_success(self):
        checks = self.checks_by_name(self.evaluate_runtime(scope_activated=False))
        self.assertFalse(checks["scope_activated"].active)


# ---------------------------------------------------------------------------
# Runner: keyless, guarded, fail-closed flow
# ---------------------------------------------------------------------------


class RunnerFlowTests(BoundedTestCase):
    def test_successful_guarded_keyless_run(self):
        h = self.build_harness(
            guard_external=(PINNED_A, TARGET_PORT),
            raw=FakeRawClient(spider_results=[{"url": STAGE2_SEED}]),
        )
        state = h.runner.run()
        self.assertEqual(state["status"], "succeeded", state.get("errors"))
        self.assertEqual(state["phase"], "done")
        self.assertTrue(state["prelaunch"]["ready_to_launch"])
        self.assertTrue(state["preflight"]["ready_to_spider"])
        self.assertTrue(state["scope_activated"])
        self.assertEqual(state["zap_version"], "2.17.0")
        self.assertEqual(state["preflight"]["blockers"], [])

        # Guard lifecycle order: prepare -> start, before ZAP start.
        self.assertEqual(h.guard.prepare_calls, 1)
        self.assertEqual(h.guard.start_calls, 1)
        self.assertGreaterEqual(h.manager.started, 1)
        # Shutdown order: ZAP stopped before the guard.
        self.assertEqual(h.manager.stopped, 1)
        self.assertEqual(h.guard.stop_calls, 1)

        # Keyless manager + proxy config pairs.
        kwargs = h.manager.kwargs
        self.assertTrue(kwargs["keyless"])
        self.assertNotIn("api_key", kwargs)
        # Silent mode is forced on so no ZAP-initiated unsolicited request (the
        # auto-update/news fetch to news.zaproxy.org) can reach the guard.
        self.assertIs(kwargs["silent"], True)
        for pair in PROXY_CONFIG_PAIRS:
            self.assertIn(pair, kwargs["extra_config"])
        for pair in SPIDER_CONFIG_PAIRS:
            self.assertIn(pair, kwargs["extra_config"])
        self.assertEqual(kwargs["callback_port"], bounded.OAST_CALLBACK_PORT)
        # The exact callhome telemetry suppression pair is part of launch
        # hardening and is passed verbatim to the daemon.
        callhome_pair = (OFFLINE_CONFIG_CALLHOME_TEL_ENABLED, "false")
        self.assertIn(callhome_pair, LAUNCH_HARDENING_PAIRS)
        self.assertIn(callhome_pair, kwargs["extra_config"])

        # Proxy + spider + callhome read-backs recorded.
        self.assertEqual(state["proxy_config_readback"]["host"], GUARD_HOST)
        self.assertEqual(state["proxy_config_readback"]["port"], str(GUARD_PORT))
        self.assertEqual(state["spider_config_readback"]["maxDepth"], "3")
        self.assertEqual(state["callhome_config_readback"]["enabled"], "false")

        # Guard evidence + closure recorded.
        self.assertTrue(state["egress_guard"]["running"])
        self.assertTrue(state["guard_shutdown"]["stopped"])
        self.assertTrue(state["guard_shutdown"]["port_closed"])
        # Bounded guard evidence captured after runtime checks and after stop.
        self.assertTrue(state["guard_evidence"]["available"])
        self.assertIn("counters", state["guard_evidence"])
        self.assertIn("records", state["guard_evidence"])
        self.assertTrue(state["guard_shutdown_evidence"]["available"])
        # Clean manager shutdown proof persisted.
        shutdown = state["manager_shutdown"]
        self.assertTrue(shutdown["available"])
        self.assertEqual(shutdown["result"], "graceful")
        self.assertEqual(shutdown["reasons"], [])
        self.assertFalse(
            [e for e in state["errors"] if e["phase"] == "shutdown"], state["errors"]
        )

        # Exact seed/context.
        starts = [c for c in h.raw.calls if c[0] == "start_spider"]
        self.assertEqual(len(starts), 1)
        self.assertEqual(starts[0][1], STAGE2_SEED)
        self.assertEqual(starts[0][2]["context_name"], h.profile.context_name)
        self.assertNotIn("access_url", h.raw.method_names())
        self.assertTrue((h.profile.scan_path.scan_dir / "raw" / "spider.json").is_file())

    def test_scope_is_activated_before_the_spider_request(self):
        h = self.build_harness()
        h.runner.run()
        names = h.raw.method_names()
        self.assertLess(names.index("create_context"), names.index("start_spider"))
        self.assertLess(names.index("include_in_context"), names.index("start_spider"))

    def test_guard_prepare_failure_blocks_before_zap(self):
        guard = FakeGuard(prepare_error=RuntimeError("dns unavailable"))
        h = self.build_harness(guard=guard)
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertEqual(h.manager.started, 0)
        self.assertEqual(h.manager.stopped, 0)
        self.assertNotIn("start_spider", h.raw.method_names())
        # Guard stop is still attempted exactly once in the finally path.
        self.assertEqual(guard.stop_calls, 1)

    def test_guard_start_failure_blocks_before_zap(self):
        guard = FakeGuard(start_error=RuntimeError("bind failed"))
        h = self.build_harness(guard=guard)
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertEqual(h.manager.started, 0)
        self.assertEqual(guard.stop_calls, 1)

    def test_guard_exact_configuration_is_enforced(self):
        guards = (
            FakeGuard(bind_port=9999),
            FakeGuard(target_host="evil.test"),
            FakeGuard(pinned_ips=()),
            FakeGuard(pinned_ips=("127.0.0.1",)),
        )
        for index, guard in enumerate(guards):
            with self.subTest(guard=guard):
                scan_id = f"20261003T12000{index}Z-abc123"
                out = self.output_dir.parent / scan_id
                h = self.build_harness(guard=guard, output_dir=out)
                state = h.runner.run()
                self.assertEqual(state["status"], "failed")
                self.assertEqual(h.manager.started, 0)

    def test_zap_direct_egress_is_rejected(self):
        h = self.build_harness(zap_external=("9.9.9.9", 443))
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertIn("zap_no_direct_egress_established", state["preflight"]["blockers"])
        self.assertNotIn("start_spider", h.raw.method_names())

    def test_guard_off_pinned_egress_is_rejected(self):
        h = self.build_harness(guard_external=("9.9.9.9", 443))
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertIn("guard_egress_within_pinned_set", state["preflight"]["blockers"])
        self.assertNotIn("start_spider", h.raw.method_names())

    def test_guard_allowed_pinned_egress_passes_preflight(self):
        h = self.build_harness(guard_external=(PINNED_A, TARGET_PORT))
        state = h.runner.run()
        self.assertEqual(state["status"], "succeeded", state.get("errors"))

    def test_guard_denied_record_blocks(self):
        guard = FakeGuard(records=[{"decision": "denied", "reason": "host_not_allowed"}])
        h = self.build_harness(guard=guard)
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertIn(
            "guard_no_denied_or_error_records", state["preflight"]["blockers"]
        )
        self.assertNotIn("start_spider", h.raw.method_names())

    def test_unavailable_inspection_fails_closed(self):
        h = self.build_harness(method="unavailable")
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertIn("api_loopback_only", state["preflight"]["blockers"])
        self.assertNotIn("start_spider", h.raw.method_names())

    def test_scope_activation_failure_blocks_spider(self):
        raw = FakeRawClient(fail_on="include_in_context", error=RuntimeError("nope"))
        h = self.build_harness(raw=raw)
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertNotIn("start_spider", raw.method_names())

    def test_fail_closed_when_proxy_readback_absent(self):
        h = self.build_harness(omit_proxy=True)
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertIn("proxy_config_exact", state["preflight"]["blockers"])
        self.assertNotIn("start_spider", h.raw.method_names())

    def test_fail_closed_when_callhome_readback_absent(self):
        h = self.build_harness(omit_callhome=True)
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertIn("callhome_telemetry_disabled", state["preflight"]["blockers"])
        self.assertNotIn("start_spider", h.raw.method_names())

    def test_fail_closed_when_callhome_telemetry_true(self):
        h = self.build_harness(callhome_overrides={"enabled": "true"})
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertIn("callhome_telemetry_disabled", state["preflight"]["blockers"])
        self.assertNotIn("start_spider", h.raw.method_names())

    def test_out_of_host_spider_results_fail(self):
        raw = FakeRawClient(
            spider_results=[{"url": STAGE2_SEED}, {"url": "https://evil.test/redirected"}]
        )
        h = self.build_harness(raw=raw)
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertTrue(
            any("out-of-host" in e["message"] for e in state["errors"]), state["errors"]
        )
        self.assertIn("stop_spider", raw.method_names())


class ObserverFailClosedTests(BoundedTestCase):
    def test_observer_stops_spider_when_guard_denies_after_start(self):
        guard = FakeGuard()

        def mark_denied():
            guard.denied = True

        raw = FakeRawClient(
            spider_results=[{"url": STAGE2_SEED}], on_start_spider=mark_denied
        )
        h = self.build_harness(guard=guard, raw=raw)
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertTrue(
            any("runtime egress inspection failed" in e["message"] for e in state["errors"]),
            state["errors"],
        )
        # Existing best-effort Spider stop ran before the error propagated.
        self.assertIn("stop_spider", raw.method_names())


class ShutdownFailClosedTests(BoundedTestCase):
    def test_guard_stop_failure_fails_run(self):
        guard = FakeGuard(stop_error=RuntimeError("stop failed"))
        h = self.build_harness(guard=guard)
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertEqual(guard.stop_calls, 1)
        self.assertTrue(
            any(e["phase"] == "guard_shutdown" for e in state["errors"]), state["errors"]
        )

    def test_guard_port_not_closed_fails_run(self):
        guard = FakeGuard(stop_noop=True)  # stays "running"
        h = self.build_harness(guard=guard)
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertFalse(state["guard_shutdown"]["stopped"])
        self.assertTrue(
            any(e["phase"] == "guard_shutdown" for e in state["errors"]), state["errors"]
        )

    def test_manager_stop_failure_fails_run(self):
        manager = FakeManager(
            zap_home=self.output_dir / "zap-home", stop_error=RuntimeError("boom")
        )
        h = self.build_harness(manager=manager)
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")


class ShutdownGuardRecordTests(BoundedTestCase):
    """The final guard-records inspection after ZAP shutdown fails closed."""

    def _harness_with_shutdown_hook(self, hook):
        guard = FakeGuard()
        h = self.build_harness(guard=guard, guard_external=(PINNED_A, TARGET_PORT))

        def shutdown():
            hook(guard)
            h.manager.running = False

        h.manager.stop = shutdown
        return h, guard

    def test_shutdown_time_guard_denied_fails_run(self):
        h, guard = self._harness_with_shutdown_hook(
            lambda g: setattr(g, "denied", True)
        )
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertTrue(state["guard_shutdown_records"]["denied_or_error"])
        self.assertTrue(
            any(e["phase"] == "guard_shutdown" for e in state["errors"]),
            state["errors"],
        )

    def test_shutdown_time_guard_error_fails_run(self):
        h, guard = self._harness_with_shutdown_hook(
            lambda g: g._records.append({"decision": "error", "reason": "io_error"})
        )
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertTrue(state["guard_shutdown_records"]["denied_or_error"])

    def test_shutdown_time_guard_records_unavailable_fails_run(self):
        def break_records(guard):
            def boom():
                raise RuntimeError("no records")

            guard.get_records = boom
            guard.evidence = boom

        h, guard = self._harness_with_shutdown_hook(break_records)
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertFalse(state["guard_shutdown_records"]["available"])
        self.assertTrue(
            any(e["phase"] == "guard_shutdown" for e in state["errors"]),
            state["errors"],
        )


class ManagerShutdownProofTests(BoundedTestCase):
    def _run_with_shutdown(self, **kwargs):
        manager = FakeManager(zap_home=self.output_dir / "zap-home", **kwargs)
        h = self.build_harness(
            manager=manager, guard_external=(PINNED_A, TARGET_PORT)
        )
        return h, h.runner.run()

    def test_clean_shutdown_succeeds_and_persists_proof(self):
        h, state = self._run_with_shutdown()
        self.assertEqual(state["status"], "succeeded", state.get("errors"))
        self.assertEqual(state["manager_shutdown"]["result"], "graceful")
        self.assertEqual(state["manager_shutdown"]["reasons"], [])
        self.assertTrue(state["manager_shutdown"]["both_ports_closed"])

    def test_terminate_kill_fallback_fails_run(self):
        h, state = self._run_with_shutdown(
            shutdown_overrides={"result": "terminated", "fallbacks": ["terminate"]}
        )
        self.assertEqual(state["status"], "failed")
        self.assertTrue(
            any(e["phase"] == "shutdown" for e in state["errors"]), state["errors"]
        )
        self.assertIn("terminate", state["manager_shutdown"]["fallbacks"])

    def test_missing_lifecycle_evidence_fails_run(self):
        h, state = self._run_with_shutdown(lifecycle_provider=lambda: None)
        self.assertEqual(state["status"], "failed")
        self.assertFalse(state["manager_shutdown"]["available"])

    def test_lifecycle_evidence_error_fails_run(self):
        h, state = self._run_with_shutdown(
            lifecycle_error=RuntimeError("no evidence")
        )
        self.assertEqual(state["status"], "failed")
        self.assertIn(
            "no evidence",
            " ".join(e["message"] for e in state["errors"]),
        )

    def test_api_shutdown_error_fails_run(self):
        h, state = self._run_with_shutdown(
            shutdown_overrides={"api_result": "error", "api_error": "ZapApiError"}
        )
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["manager_shutdown"]["api_result"], "error")

    def test_ports_not_closed_fails_run(self):
        h, state = self._run_with_shutdown(
            shutdown_overrides={
                "api_port_closed": False,
                "both_ports_closed": False,
            }
        )
        self.assertEqual(state["status"], "failed")
        self.assertFalse(state["manager_shutdown"]["both_ports_closed"])

    def test_control_errors_fail_run(self):
        h, state = self._run_with_shutdown(
            shutdown_overrides={"control_errors": ["kill: OSError"]}
        )
        self.assertEqual(state["status"], "failed")
        self.assertEqual(
            state["manager_shutdown"]["control_errors"], ["kill: OSError"]
        )


class GuardListenerProofTests(BoundedTestCase):
    def test_wrong_owner_fails_closed(self):
        h = self.build_harness(guard_listener_pid=9999)
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertIn("guard_listener_exact", state["preflight"]["blockers"])
        self.assertNotIn("start_spider", h.raw.method_names())

    def test_wildcard_address_fails_closed(self):
        h = self.build_harness(guard_listener_address="0.0.0.0")
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertIn("guard_listener_exact", state["preflight"]["blockers"])

    def test_missing_listener_fails_closed(self):
        h = self.build_harness(guard_listener_on=False)
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertIn("guard_listener_exact", state["preflight"]["blockers"])

    def test_exact_listener_owner_and_address_pass(self):
        h = self.build_harness(
            guard_listener_pid=GUARD_PID,
            guard_listener_address="127.0.0.1",
            guard_external=(PINNED_A, TARGET_PORT),
        )
        state = h.runner.run()
        self.assertEqual(state["status"], "succeeded", state.get("errors"))
        self.assertTrue(state["runtime_inspections"][0]["guard_listener"]["exact"])


class InvalidRemoteAddressTests(BoundedTestCase):
    def test_unparseable_zap_remote_is_offending(self):
        h = self.build_harness(zap_external=("not-an-ip", 443))
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertIn(
            "zap_no_direct_egress_established", state["preflight"]["blockers"]
        )

    def test_unspecified_zap_remote_is_offending(self):
        h = self.build_harness(zap_external=("0.0.0.0", 443))
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertIn(
            "zap_no_direct_egress_established", state["preflight"]["blockers"]
        )

    def test_unparseable_guard_remote_is_offending(self):
        h = self.build_harness(guard_external=("not-an-ip", 443))
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertIn(
            "guard_egress_within_pinned_set", state["preflight"]["blockers"]
        )

    def test_unspecified_guard_remote_is_offending(self):
        h = self.build_harness(guard_external=("0.0.0.0", 443))
        state = h.runner.run()
        self.assertEqual(state["status"], "failed")
        self.assertIn(
            "guard_egress_within_pinned_set", state["preflight"]["blockers"]
        )


class GuardEvidenceBoundsTests(BoundedTestCase):
    def test_guard_records_are_bounded_and_request_data_free(self):
        records = [
            {
                "timestamp": f"t{i}",
                "decision": "allowed",
                "reason": "allowed",
                "host": "acme.example",
                "port": 443,
                "status": 200,
                "connected_ip": "8.8.8.8",
                "bytes_to_upstream": 1,
                "bytes_to_client": 2,
            }
            for i in range(100)
        ]
        guard = FakeGuard(records=records, counters={"allowed": 100})
        h = self.build_harness(guard=guard, guard_external=(PINNED_A, TARGET_PORT))
        state = h.runner.run()
        self.assertEqual(state["status"], "succeeded", state.get("errors"))
        evidence = state["guard_shutdown_evidence"]
        self.assertTrue(evidence["available"])
        self.assertEqual(evidence["record_count"], 100)
        self.assertLessEqual(len(evidence["records"]), bounded._MAX_GUARD_RECORDS)
        self.assertEqual(evidence["counters"]["allowed"], 100)
        blob = json.dumps(evidence)
        for token in ("Cookie:", "Authorization:", "GET ", "POST "):
            self.assertNotIn(token, blob, token)


class EvidenceTests(BoundedTestCase):
    def test_evidence_is_keyless_guarded_and_secret_free(self):
        h = self.build_harness(guard_external=(PINNED_A, TARGET_PORT))
        state = h.runner.run()
        run_dir = h.profile.scan_path.scan_dir
        for name in (
            bounded.STAGE2_STATE_FILENAME,
            PRELAUNCH_FILENAME,
            bounded.STAGE2_JSON_FILENAME,
            bounded.STAGE2_MARKDOWN_FILENAME,
        ):
            self.assertTrue((run_dir / name).is_file(), name)

        evidence = json.loads((run_dir / bounded.STAGE2_JSON_FILENAME).read_text("utf-8"))
        self.assertTrue(evidence["keyless_api"])
        self.assertEqual(evidence["guard_endpoint"], f"{GUARD_HOST}:{GUARD_PORT}")
        self.assertTrue(evidence["proxy_config_readback"])
        self.assertTrue(evidence["egress_guard"]["running"])
        self.assertTrue(evidence["guard_shutdown"]["port_closed"])
        self.assertTrue(evidence["guard_evidence"]["available"])
        self.assertTrue(evidence["guard_shutdown_evidence"]["available"])
        self.assertTrue(evidence["manager_shutdown"]["available"])
        self.assertEqual(evidence["manager_shutdown"]["result"], "graceful")
        self.assertGreaterEqual(len(evidence["runtime_inspections"]), 1)
        self.assertNotIn("capabilities", evidence)

        blob = json.dumps(evidence)
        for token in ("api.key=", "apikey", "API_KEY", "Cookie:", "Authorization:"):
            self.assertNotIn(token, blob, token)
        # The command is keyless: only the disable-key flag is present.
        self.assertIn("api.disablekey=true", blob)

        markdown = (run_dir / bounded.STAGE2_MARKDOWN_FILENAME).read_text("utf-8")
        self.assertIn("manager_shutdown", markdown)
        self.assertIn("guard_shutdown_evidence", markdown)

    def test_blocked_run_never_starts_guard_or_manager(self):
        # Force a static blocker by building a profile and monkeypatching the
        # static control evaluation to fail closed.
        h = self.build_harness()
        original = bounded.evaluate_prelaunch_controls

        def blocked(profile):
            checks = original(profile)
            broken = checks[0]
            checks[0] = type(broken)(
                name="forced_blocker",
                active=False,
                enforcement="test",
                detail="forced",
            )
            return checks

        bounded.evaluate_prelaunch_controls = blocked
        try:
            state = h.runner.run()
        finally:
            bounded.evaluate_prelaunch_controls = original
        self.assertEqual(state["status"], "blocked")
        self.assertEqual(h.guard.prepare_calls, 0)
        self.assertEqual(h.manager.started, 0)


class DefaultComponentTests(BoundedTestCase):
    def test_default_client_is_keyless(self):
        profile = self.build_profile()
        runner = Stage2SpiderRunner(profile=profile)
        facade = runner._default_client_factory(profile.endpoint, object())
        raw = facade._client
        self.assertTrue(raw.keyless)
        self.assertEqual(raw.endpoint.host, "127.0.0.1")
        self.assertEqual(raw.endpoint.port, API_PORT)
        self.assertIsNone(raw._api_key)
        rendered = repr(raw)
        self.assertIn("keyless=True", rendered)
        self.assertNotIn("api_key=", rendered)

    def test_default_guard_is_inert_exact_and_keyless(self):
        profile = self.build_profile()
        runner = Stage2SpiderRunner(profile=profile)
        guard = runner._default_guard_factory()
        self.assertEqual(guard.bind_host, "127.0.0.1")
        self.assertEqual(guard.bind_port, GUARD_PORT)
        self.assertEqual(guard.target_endpoint, ("acme.example", 443))
        self.assertFalse(guard.running)
        self.assertFalse(guard.prepared)


class ProcessManagerKeyDefaultTests(BoundedTestCase):
    def test_generic_manager_still_requires_a_key_by_default(self):
        from red_teaming.projects.models import ProjectDomain, Target
        from red_teaming.projects.paths import ScanPath

        domain = ProjectDomain.parse("acme.example")
        target = Target.parse(STAGE2_SEED, domain)
        scan = ScanPath.build(self.root, domain, target, scan_id=SCAN_ID)
        with self.assertRaises(ZapConfigError):
            ZapProcessManager(executable=self.exe, scan_path=scan, api_key=None)
        # Keyless requires explicit opt-in and forbids a key.
        with self.assertRaises(ZapConfigError):
            ZapProcessManager(
                executable=self.exe, scan_path=scan, api_key="x", keyless=True
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
