"""Offline tests for bounded Spider and AJAX Spider runners.

Fake clients, a fake monotonic clock, and a fake sleep function are used; no
socket, process, or real sleep is involved.
"""

import unittest

from red_teaming.tools.zap.discovery import (
    AjaxSpiderRunner,
    DiscoveryError,
    DiscoveryProcessExitedError,
    DiscoveryStateError,
    DiscoveryTimeoutError,
    SpiderRunner,
)


class FakeClock:
    def __init__(self, start=0.0):
        self.now = float(start)

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += float(seconds)


class ProcessFlag:
    def __init__(self, exited=False):
        self.exited = exited

    def __call__(self):
        return self.exited


class FakeDiscoveryClient:
    """Records calls and replays scripted statuses/pages."""

    def __init__(
        self,
        *,
        spider_statuses=(),
        ajax_statuses=(),
        spider_results=(),
        ajax_pages=(),
        spider_scan_id=0,
        ajax_scan_id=None,
        on_start_spider=None,
    ):
        self.spider_statuses = list(spider_statuses)
        self.ajax_statuses = list(ajax_statuses)
        self._spider_results = list(spider_results)
        self.ajax_pages = list(ajax_pages)
        self.spider_scan_id = spider_scan_id
        self.ajax_scan_id = ajax_scan_id
        self.on_start_spider = on_start_spider
        self.calls = []
        self._last_spider = 100
        self._last_ajax = "stopped"

    def _pop(self, queue, last_attr):
        if queue:
            value = queue.pop(0)
            setattr(self, last_attr, value)
            return value
        return getattr(self, last_attr)

    def start_spider(self, url, **kwargs):
        self.calls.append(("start_spider", url, kwargs))
        if self.on_start_spider is not None:
            self.on_start_spider()
        return self.spider_scan_id

    def spider_status(self, scan_id):
        self.calls.append(("spider_status", scan_id))
        return self._pop(self.spider_statuses, "_last_spider")

    def spider_results(self, scan_id):
        self.calls.append(("spider_results", scan_id))
        return list(self._spider_results)

    def stop_spider(self, scan_id):
        self.calls.append(("stop_spider", scan_id))

    def start_ajax_spider(self, url, **kwargs):
        self.calls.append(("start_ajax_spider", url, kwargs))
        return self.ajax_scan_id

    def ajax_spider_status(self):
        self.calls.append(("ajax_spider_status",))
        return self._pop(self.ajax_statuses, "_last_ajax")

    def ajax_spider_results(self, **kwargs):
        self.calls.append(("ajax_spider_results", kwargs))
        if self.ajax_pages:
            return list(self.ajax_pages.pop(0))
        return []

    def stop_ajax_spider(self):
        self.calls.append(("stop_ajax_spider",))

    def method_names(self):
        return [call[0] for call in self.calls]


def make_spider(client, clock, **overrides):
    options = dict(
        timeout=1.0,
        poll_interval=0.25,
        process_exited=None,
        clock=clock,
        sleep=clock.sleep,
    )
    options.update(overrides)
    return SpiderRunner(client, **options)


def make_ajax(client, clock, **overrides):
    options = dict(
        timeout=1.0,
        poll_interval=0.25,
        page_size=2,
        max_results=100,
        process_exited=None,
        clock=clock,
        sleep=clock.sleep,
    )
    options.update(overrides)
    return AjaxSpiderRunner(client, **options)


class SpiderRunnerTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()

    def test_success_collects_results(self):
        client = FakeDiscoveryClient(
            spider_statuses=[0, 50, 100],
            spider_results=[{"url": "https://example.com/"}],
        )
        result = make_spider(client, self.clock).run(
            "https://example.com/", context_name="scan-1"
        )
        self.assertEqual(result.mode, "spider")
        self.assertEqual(result.scan_id, 0)
        self.assertEqual(result.results, [{"url": "https://example.com/"}])
        self.assertNotIn("stop_spider", client.method_names())
        start = client.calls[0]
        self.assertEqual(start[1], "https://example.com/")
        self.assertEqual(start[2]["context_name"], "scan-1")
        self.assertTrue(start[2]["subtree_only"])

    def test_timeout_stops_scan(self):
        client = FakeDiscoveryClient(spider_statuses=[10])
        with self.assertRaises(DiscoveryTimeoutError):
            make_spider(client, self.clock).run("https://example.com/")
        self.assertIn("stop_spider", client.method_names())

    def test_process_exit_before_start_is_detected(self):
        client = FakeDiscoveryClient()
        with self.assertRaises(DiscoveryProcessExitedError):
            make_spider(
                client, self.clock, process_exited=ProcessFlag(exited=True)
            ).run("https://example.com/")
        self.assertNotIn("start_spider", client.method_names())

    def test_process_exit_during_run_stops_scan(self):
        flag = ProcessFlag()
        client = FakeDiscoveryClient(
            spider_statuses=[10],
            on_start_spider=lambda: setattr(flag, "exited", True),
        )
        with self.assertRaises(DiscoveryProcessExitedError):
            make_spider(client, self.clock, process_exited=flag).run(
                "https://example.com/"
            )
        self.assertIn("stop_spider", client.method_names())

    def test_invalid_timeouts_are_rejected(self):
        client = FakeDiscoveryClient()
        for kwargs in ({"timeout": 0}, {"timeout": float("nan")}, {"poll_interval": 0}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(DiscoveryError):
                    make_spider(client, self.clock, **kwargs)

    def test_mode_isolation_never_calls_ajax(self):
        client = FakeDiscoveryClient(spider_statuses=[100])
        make_spider(client, self.clock).run("https://example.com/")
        self.assertFalse(
            any("ajax" in name for name in client.method_names()),
            client.method_names(),
        )


class SpiderObserverTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()

    def test_observer_runs_after_start_each_poll_and_before_results(self):
        calls = []
        client = FakeDiscoveryClient(spider_statuses=[0, 50, 100])
        result = make_spider(
            client, self.clock, observer=lambda: calls.append(1)
        ).run("https://example.com/")
        self.assertEqual(result.status, "100")
        # Three poll iterations plus one final check before results.
        self.assertEqual(len(calls), 4)

    def test_observer_exception_stops_spider_and_propagates(self):
        class ObserverError(RuntimeError):
            pass

        def observer():
            raise ObserverError("runtime violation")

        client = FakeDiscoveryClient(spider_statuses=[0, 100])
        with self.assertRaises(ObserverError):
            make_spider(client, self.clock, observer=observer).run(
                "https://example.com/"
            )
        self.assertIn("stop_spider", client.method_names())

    def test_invalid_observer_is_rejected(self):
        client = FakeDiscoveryClient()
        with self.assertRaises(DiscoveryError):
            make_spider(client, self.clock, observer="not-callable")

    def test_default_has_no_observer(self):
        client = FakeDiscoveryClient(spider_statuses=[100])
        # No observer => existing behavior, no extra calls.
        result = make_spider(client, self.clock).run("https://example.com/")
        self.assertEqual(result.status, "100")

    def test_ajax_runner_remains_observer_free(self):
        client = FakeDiscoveryClient(ajax_statuses=["stopped"])
        result = make_ajax(client, self.clock).run("https://example.com/")
        self.assertEqual(result.mode, "ajax")


class AjaxSpiderRunnerTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()

    def test_success_is_case_insensitive_and_collects_pages(self):
        client = FakeDiscoveryClient(
            ajax_statuses=["running", "Running", "STOPPED"],
            ajax_pages=[[{"url": "a"}, {"url": "b"}]],
        )
        result = make_ajax(client, self.clock).run(
            "https://example.com/", context_name="scan-1"
        )
        self.assertEqual(result.mode, "ajax")
        self.assertEqual(result.results, [{"url": "a"}, {"url": "b"}])
        self.assertNotIn("stop_ajax_spider", client.method_names())
        start = client.calls[0]
        self.assertTrue(start[2]["in_scope_only"])
        self.assertTrue(start[2]["subtree_only"])

    def test_pagination_stops_on_short_page(self):
        client = FakeDiscoveryClient(
            ajax_statuses=["stopped"],
            ajax_pages=[[1, 2], [3]],
        )
        result = make_ajax(client, self.clock).run("https://example.com/")
        self.assertEqual(result.results, [1, 2, 3])
        # Two pages requested: start=0/count=2 then start=2/count=2.
        page_calls = [c for c in client.calls if c[0] == "ajax_spider_results"]
        self.assertEqual(page_calls[0][1]["start"], 0)
        self.assertEqual(page_calls[1][1]["start"], 2)

    def test_timeout_stops_scan(self):
        client = FakeDiscoveryClient(ajax_statuses=["running"])
        with self.assertRaises(DiscoveryTimeoutError):
            make_ajax(client, self.clock).run("https://example.com/")
        self.assertIn("stop_ajax_spider", client.method_names())

    def test_unexpected_status_stops_scan(self):
        client = FakeDiscoveryClient(ajax_statuses=["bogus"])
        with self.assertRaises(DiscoveryStateError):
            make_ajax(client, self.clock).run("https://example.com/")
        self.assertIn("stop_ajax_spider", client.method_names())

    def test_process_exit_is_detected(self):
        client = FakeDiscoveryClient(ajax_statuses=["running"])
        with self.assertRaises(DiscoveryProcessExitedError):
            make_ajax(
                client, self.clock, process_exited=ProcessFlag(exited=True)
            ).run("https://example.com/")
        self.assertNotIn("start_ajax_spider", client.method_names())

    def test_invalid_page_settings_are_rejected(self):
        client = FakeDiscoveryClient()
        for kwargs in ({"page_size": 0}, {"max_results": 0}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(DiscoveryError):
                    make_ajax(client, self.clock, **kwargs)

    def test_mode_isolation_never_calls_spider(self):
        client = FakeDiscoveryClient(ajax_statuses=["stopped"])
        make_ajax(client, self.clock).run("https://example.com/")
        self.assertFalse(
            any(name.startswith("spider") for name in client.method_names()),
            client.method_names(),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
