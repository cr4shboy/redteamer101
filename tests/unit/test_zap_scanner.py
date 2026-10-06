"""Offline tests for the high-level ZapScanner composition.

A fake daemon manager and fake API client (with the real bounded runners and an
injected fake clock/sleep) are used. No process, socket, or target call occurs.
"""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from red_teaming.orchestration.state import STATE_FILENAME, read_state
from red_teaming.projects.models import ProjectDomain, Target
from red_teaming.projects.paths import ScanPath
from red_teaming.tools.zap.models import ZapError, redact_secret
from red_teaming.tools.zap.process import ZapStopError
from red_teaming.tools.zap.scanner import (
    ScanConfigurationError,
    ZapScanner,
    build_scope_regex,
)

API_KEY = "scannerkey789"
BASE_TIME = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)


class FakeClock:
    def __init__(self, start=0.0):
        self.now = float(start)

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += float(seconds)


class FakeNow:
    def __init__(self, base=BASE_TIME):
        self.base = base
        self.count = 0

    def __call__(self):
        self.count += 1
        return self.base + timedelta(seconds=self.count)


class FakeManager:
    def __init__(self, *, version="2.17.0", start_error=None, stop_error=None):
        self.version = version
        self.start_error = start_error
        self.stop_error = stop_error
        self.started = 0
        self.stopped = 0
        self.waited = 0
        self.running = False

    def start(self):
        if self.start_error is not None:
            raise self.start_error
        self.started += 1
        self.running = True

    def wait_until_ready(self):
        self.waited += 1
        return self.version

    def stop(self):
        self.stopped += 1
        if self.stop_error is not None:
            raise self.stop_error
        self.running = False


class FakeScannerClient:
    def __init__(
        self,
        *,
        spider_statuses=(100,),
        spider_results=(),
        ajax_statuses=("stopped",),
        ajax_pages=(),
        fail_on=None,
        error=None,
    ):
        self._spider_statuses = list(spider_statuses)
        self._spider_results = list(spider_results)
        self._ajax_statuses = list(ajax_statuses)
        self._ajax_pages = list(ajax_pages)
        self.fail_on = fail_on
        self.error = error
        self.calls = []

    def _record(self, name, *args, **kwargs):
        self.calls.append((name, args, kwargs))
        if self.fail_on == name:
            raise self.error

    def create_context(self, context_name):
        self._record("create_context", context_name)
        return 7

    def include_in_context(self, context_name, regex):
        self._record("include_in_context", context_name, regex)

    def access_url(self, url):
        self._record("access_url", url)

    def start_spider(self, url, **kwargs):
        self._record("start_spider", url, **kwargs)
        return 0

    def spider_status(self, scan_id):
        self._record("spider_status", scan_id)
        if self._spider_statuses:
            return self._spider_statuses.pop(0)
        return 100

    def spider_results(self, scan_id):
        self._record("spider_results", scan_id)
        return list(self._spider_results)

    def stop_spider(self, scan_id):
        self._record("stop_spider", scan_id)

    def start_ajax_spider(self, url, **kwargs):
        self._record("start_ajax_spider", url, **kwargs)
        return None

    def ajax_spider_status(self):
        self._record("ajax_spider_status")
        if self._ajax_statuses:
            return self._ajax_statuses.pop(0)
        return "stopped"

    def ajax_spider_results(self, **kwargs):
        self._record("ajax_spider_results", **kwargs)
        if self._ajax_pages:
            return list(self._ajax_pages.pop(0))
        return []

    def stop_ajax_spider(self):
        self._record("stop_ajax_spider")

    def method_names(self):
        return [call[0] for call in self.calls]


class ScannerTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.domain = ProjectDomain.parse("example.com")
        self.target = Target.parse("https://app.example.com/App", self.domain)
        self.scan = ScanPath.build(
            self.root,
            self.domain,
            self.target,
            now=BASE_TIME,
            suffix="abc123",
        )
        self.clock = FakeClock()
        self.manager = FakeManager()

    def tearDown(self):
        self._tmp.cleanup()

    def make_scanner(self, **overrides):
        options = dict(
            scan_path=self.scan,
            target=self.target,
            project=self.domain.name,
            mode="spider",
            manager=self.manager,
            client=FakeScannerClient(),
            poll_interval=0.25,
            clock=self.clock,
            sleep=self.clock.sleep,
            now=FakeNow(),
        )
        options.update(overrides)
        return ZapScanner(**options)

    def read_disk_state(self):
        return json.loads((self.scan.scan_dir / STATE_FILENAME).read_text("utf-8"))


class SuccessTests(ScannerTestCase):
    def test_spider_only_success(self):
        client = FakeScannerClient(
            spider_results=[{"url": "https://app.example.com/"}]
        )
        scanner = self.make_scanner(mode="spider", client=client)
        state = scanner.run()

        self.assertEqual(state["status"], "succeeded")
        self.assertEqual(state["phase"], "done")
        self.assertEqual(state["zap_version"], "2.17.0")
        self.assertEqual(state["artifacts"], {"spider": "raw/spider.json"})
        self.assertIn("spider", state["steps"])
        self.assertNotIn("ajax", state["steps"])
        self.assertTrue((self.scan.scan_dir / STATE_FILENAME).is_file())
        self.assertFalse((self.scan.scan_dir / "state.json").exists())
        self.assertEqual(self.manager.stopped, 1)

        artifact = self.scan.scan_dir / "raw" / "spider.json"
        payload = json.loads(artifact.read_text("utf-8"))
        self.assertEqual(payload["mode"], "spider")
        self.assertEqual(payload["results"], [{"url": "https://app.example.com/"}])

        self.assertFalse(
            any("ajax" in name for name in client.method_names()), client.method_names()
        )

    def test_ajax_only_success(self):
        client = FakeScannerClient(
            ajax_pages=[[{"url": "https://app.example.com/"}]]
        )
        scanner = self.make_scanner(mode="ajax", client=client)
        state = scanner.run()

        self.assertEqual(state["status"], "succeeded")
        self.assertEqual(state["artifacts"], {"ajax": "raw/ajax.json"})
        self.assertIn("ajax", state["steps"])
        self.assertNotIn("spider", state["steps"])
        self.assertTrue((self.scan.scan_dir / "raw" / "ajax.json").is_file())
        self.assertFalse(
            any(name.startswith("spider") for name in client.method_names()),
            client.method_names(),
        )

    def test_both_modes_write_both_artifacts(self):
        client = FakeScannerClient(
            spider_results=[{"url": "s"}],
            ajax_pages=[[{"url": "a"}]],
        )
        scanner = self.make_scanner(mode="both", client=client)
        state = scanner.run()
        self.assertEqual(state["artifacts"]["spider"], "raw/spider.json")
        self.assertEqual(state["artifacts"]["ajax"], "raw/ajax.json")
        self.assertTrue((self.scan.scan_dir / "raw" / "spider.json").is_file())
        self.assertTrue((self.scan.scan_dir / "raw" / "ajax.json").is_file())

    def test_context_and_scope_are_applied(self):
        client = FakeScannerClient()
        scanner = self.make_scanner(mode="spider", client=client)
        scanner.run()
        self.assertIn(
            ("create_context", (scanner.context_name,), {}),
            [(c[0], c[1], c[2]) for c in client.calls],
        )
        include = [c for c in client.calls if c[0] == "include_in_context"]
        self.assertEqual(len(include), 1)
        self.assertEqual(include[0][1][1], scanner.scope_regex)
        self.assertEqual(scanner.scope_regex, build_scope_regex(self.target))

    def test_access_step_is_best_effort(self):
        client = FakeScannerClient(fail_on="access_url", error=ZapError("no seed"))
        scanner = self.make_scanner(mode="spider", client=client)
        state = scanner.run()
        self.assertEqual(state["status"], "succeeded")
        self.assertEqual(state["steps"]["access"]["status"], "warning")

    def test_access_step_can_be_disabled(self):
        client = FakeScannerClient()
        scanner = self.make_scanner(mode="spider", client=client, access_url=False)
        state = scanner.run()
        self.assertEqual(state["steps"]["access"]["status"], "skipped")
        self.assertNotIn("access_url", client.method_names())

    def test_timestamps_are_injected(self):
        now = FakeNow()
        scanner = self.make_scanner(now=now)
        state = scanner.run()
        self.assertEqual(
            state["created_at"], (BASE_TIME + timedelta(seconds=1)).isoformat()
        )
        self.assertLessEqual(state["created_at"], state["updated_at"])


class FailureTests(ScannerTestCase):
    def test_failure_persists_sanitized_failed_state(self):
        client = FakeScannerClient(
            fail_on="spider_status", error=ZapError("spider blew up")
        )
        scanner = self.make_scanner(mode="spider", client=client)
        with self.assertRaises(ZapError):
            scanner.run()

        state = self.read_disk_state()
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["error"]["type"], "ZapError")
        self.assertIn("spider blew up", state["error"]["message"])
        self.assertEqual(self.manager.stopped, 1)

    def test_failure_during_start_is_recorded(self):
        self.manager = FakeManager(start_error=ZapError("start failed"))
        scanner = self.make_scanner()
        with self.assertRaises(ZapError):
            scanner.run()
        state = self.read_disk_state()
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["error"]["type"], "ZapError")
        self.assertEqual(self.manager.stopped, 1)

    def test_api_key_never_enters_state_or_artifacts(self):
        client = FakeScannerClient(
            fail_on="spider_status", error=ZapError(f"leaked {API_KEY} here")
        )
        scanner = self.make_scanner(
            mode="spider",
            client=client,
            secret_redactor=lambda text: redact_secret(text, API_KEY),
        )
        with self.assertRaises(ZapError):
            scanner.run()
        raw = (self.scan.scan_dir / STATE_FILENAME).read_text("utf-8")
        self.assertNotIn(API_KEY, raw)
        self.assertIn("***", raw)


class ShutdownFailureTests(ScannerTestCase):
    def test_successful_discovery_with_stop_failure_persists_failed_state(self):
        manager = FakeManager(stop_error=ZapStopError("daemon survived stop"))
        client = FakeScannerClient(
            spider_results=[{"url": "https://app.example.com/"}]
        )
        scanner = self.make_scanner(mode="spider", client=client, manager=manager)

        with self.assertRaises(ZapStopError):
            scanner.run()

        state = self.read_disk_state()
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["phase"], "shutdown")
        self.assertEqual(state["error"]["type"], "ZapStopError")
        self.assertIn("daemon survived stop", state["error"]["message"])
        self.assertEqual(state["shutdown_error"]["type"], "ZapStopError")
        # Discovery artifacts were still written before shutdown was attempted.
        self.assertTrue((self.scan.scan_dir / "raw" / "spider.json").is_file())
        # Exactly one bounded shutdown attempt, never a double stop.
        self.assertEqual(manager.stopped, 1)

    def test_primary_failure_with_stop_failure_preserves_primary_error(self):
        primary = ZapError("spider blew up")
        manager = FakeManager(stop_error=ZapStopError("daemon survived stop"))
        client = FakeScannerClient(fail_on="spider_status", error=primary)
        scanner = self.make_scanner(mode="spider", client=client, manager=manager)

        with self.assertRaises(ZapError) as caught:
            scanner.run()
        self.assertIs(caught.exception, primary)

        state = self.read_disk_state()
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["error"]["type"], "ZapError")
        self.assertIn("spider blew up", state["error"]["message"])
        self.assertEqual(state["shutdown_error"]["type"], "ZapStopError")
        self.assertEqual(manager.stopped, 1)

    def test_stop_failure_message_is_redacted(self):
        manager = FakeManager(
            stop_error=ZapStopError(f"shutdown leaked {API_KEY} key")
        )
        scanner = self.make_scanner(
            mode="spider",
            manager=manager,
            secret_redactor=lambda text: redact_secret(text, API_KEY),
        )
        with self.assertRaises(ZapStopError):
            scanner.run()

        raw = (self.scan.scan_dir / STATE_FILENAME).read_text("utf-8")
        self.assertNotIn(API_KEY, raw)
        self.assertIn("***", raw)


class ConstructionTests(ScannerTestCase):
    def test_invalid_mode_is_rejected(self):
        with self.assertRaises(ScanConfigurationError):
            self.make_scanner(mode="active")

    def test_invalid_timeouts_are_rejected(self):
        for kwargs in ({"spider_timeout": 0}, {"ajax_timeout": float("nan")}, {"poll_interval": 0}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ScanConfigurationError):
                    self.make_scanner(**kwargs)

    def test_requires_scan_path_and_target(self):
        with self.assertRaises(ScanConfigurationError):
            ZapScanner(
                scan_path="nope",  # type: ignore[arg-type]
                target=self.target,
                project="example.com",
                mode="spider",
                manager=self.manager,
                client=FakeScannerClient(),
            )
        with self.assertRaises(ScanConfigurationError):
            ZapScanner(
                scan_path=self.scan,
                target="nope",  # type: ignore[arg-type]
                project="example.com",
                mode="spider",
                manager=self.manager,
                client=FakeScannerClient(),
            )

    def test_repr_has_no_secret(self):
        scanner = self.make_scanner()
        self.assertNotIn(API_KEY, repr(scanner))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
