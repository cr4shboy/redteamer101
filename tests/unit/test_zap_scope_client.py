"""Offline tests for ZAP scope-regex building and explicit client wrappers.

All requests use a fake transport with queued in-memory responses: no socket,
DNS, process, or target call is made.
"""

import re
import unittest

from red_teaming.projects.models import ProjectDomain, Target
from red_teaming.tools.zap.client import ZapApiClient
from red_teaming.tools.zap.models import (
    HttpResponse,
    ZapConfigError,
    ZapResponseError,
)
from red_teaming.tools.zap.scanner import build_scope_regex

API_KEY = "scopekey456"


class FakeTransport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def request(self, method, url, timeout):
        self.requests.append((method, url, timeout))
        if not self.responses:
            raise AssertionError("no queued response")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def make_client(*bodies):
    transport = FakeTransport(*(HttpResponse(200, body) for body in bodies))
    return ZapApiClient("http://127.0.0.1:8080", API_KEY, transport=transport), transport


class ScopeRegexTests(unittest.TestCase):
    def setUp(self):
        self.domain = ProjectDomain.parse("example.com")

    def test_root_target_scope(self):
        target = Target.parse("https://example.com/", self.domain)
        pattern = build_scope_regex(target)
        rx = re.compile(pattern)

        self.assertTrue(pattern.startswith("^"))
        self.assertTrue(pattern.endswith("$"))
        for url in [
            "https://example.com",
            "https://example.com/",
            "https://example.com/a/b?x=1",
            "https://example.com?a=1",
            "https://example.com#fragment",
            "https://example.com/?a=1",
            "https://example.com:443/x",
        ]:
            with self.subTest(url=url):
                self.assertTrue(rx.match(url))
        for url in [
            "http://example.com/",
            "https://evil.com/",
            "https://example.com.evil.com/",
            "https://notexample.com/",
            "https://example.com:8443/",
            "https://example.org/",
            "https://example.como/",
        ]:
            with self.subTest(url=url):
                self.assertFalse(rx.match(url))

    def test_explicit_default_port_is_optional(self):
        target = Target.parse("http://example.com:80/", self.domain)
        rx = re.compile(build_scope_regex(target))
        self.assertTrue(rx.match("http://example.com/"))
        self.assertTrue(rx.match("http://example.com:80/x"))
        self.assertFalse(rx.match("http://example.com:8080/x"))

    def test_path_subtree_scope_excludes_siblings(self):
        target = Target.parse("https://example.com/App", self.domain)
        rx = re.compile(build_scope_regex(target))
        for url in [
            "https://example.com/App",
            "https://example.com/App/",
            "https://example.com/App/Login",
            "https://example.com/App?x=1",
            "https://example.com/App#frag",
        ]:
            with self.subTest(url=url):
                self.assertTrue(rx.match(url))
        for url in [
            "https://example.com/Application",
            "https://example.com/Appx",
            "https://example.com/App2",
            "https://example.com/Other",
        ]:
            with self.subTest(url=url):
                self.assertFalse(rx.match(url))

    def test_trailing_slash_seed_stays_distinct(self):
        target = Target.parse("https://example.com/App/", self.domain)
        rx = re.compile(build_scope_regex(target))
        for url in [
            "https://example.com/App/",
            "https://example.com/App/Login",
            "https://example.com/App/?x=1",
        ]:
            with self.subTest(url=url):
                self.assertTrue(rx.match(url))
        for url in [
            "https://example.com/App",
            "https://example.com/App2",
            "https://example.com/Application",
            "https://example.com/Other",
        ]:
            with self.subTest(url=url):
                self.assertFalse(rx.match(url))

    def test_idna_host_is_escaped_and_exact(self):
        domain = ProjectDomain.parse("bücher.example")
        target = Target.parse("https://www.bücher.example/", domain)
        pattern = build_scope_regex(target)
        rx = re.compile(pattern)
        self.assertTrue(rx.match("https://www.xn--bcher-kva.example/"))
        self.assertFalse(rx.match("https://www.xn--bcher-kva.example.evil.com/"))
        self.assertFalse(rx.match("https://www.bücher.example/"))

    def test_rejects_non_target(self):
        with self.assertRaises(ValueError):
            build_scope_regex("https://example.com")  # type: ignore[arg-type]


class ContextClientTests(unittest.TestCase):
    def test_create_context_parses_string_id(self):
        client, transport = make_client(b'{"contextId": "3"}')
        self.assertEqual(client.create_context("scan-1"), 3)
        url = transport.requests[0][1]
        self.assertIn("/JSON/context/action/newContext/", url)
        self.assertIn("contextName=scan-1", url)

    def test_create_context_missing_id_raises(self):
        client, _ = make_client(b'{"other": "x"}')
        with self.assertRaises(ZapResponseError):
            client.create_context("scan-1")

    def test_create_context_rejects_blank_name(self):
        client, _ = make_client(b'{"contextId": "1"}')
        with self.assertRaises(ZapConfigError):
            client.create_context("  ")

    def test_include_in_context_sends_regex(self):
        client, transport = make_client(b'{"result": "OK"}')
        pattern = r"^https://example\.com(?:/.*)?$"
        client.include_in_context("scan-1", pattern)
        url = transport.requests[0][1]
        self.assertIn("/JSON/context/action/includeInContext/", url)
        self.assertIn("contextName=scan-1", url)
        self.assertIn("regex=", url)

    def test_include_in_context_rejects_blank_regex(self):
        client, _ = make_client(b'{"result": "OK"}')
        with self.assertRaises(ZapConfigError):
            client.include_in_context("scan-1", "  ")

    def test_access_url_uses_core_action(self):
        client, transport = make_client(b'{"result": "OK"}')
        client.access_url("https://example.com/App")
        url = transport.requests[0][1]
        self.assertIn("/JSON/core/action/accessUrl/", url)
        self.assertIn("url=", url)

    def test_access_url_rejects_non_http(self):
        client, _ = make_client(b'{"result": "OK"}')
        for value in ["ftp://example.com/", "example.com", ""]:
            with self.subTest(value=value):
                with self.assertRaises(ZapConfigError):
                    client.access_url(value)


class SpiderClientTests(unittest.TestCase):
    def test_start_spider_parses_id_and_sends_controls(self):
        client, transport = make_client(b'{"scan": "0"}')
        scan_id = client.start_spider(
            "https://example.com/App", context_name="scan-1", subtree_only=True
        )
        self.assertEqual(scan_id, 0)
        url = transport.requests[0][1]
        self.assertIn("/JSON/spider/action/scan/", url)
        self.assertIn("subtreeOnly=true", url)
        self.assertIn("recurse=true", url)
        self.assertIn("contextName=scan-1", url)

    def test_start_spider_missing_id_raises(self):
        client, _ = make_client(b'{"other": "x"}')
        with self.assertRaises(ZapResponseError):
            client.start_spider("https://example.com/")

    def test_start_spider_rejects_bad_url(self):
        client, _ = make_client(b'{"scan": "0"}')
        with self.assertRaises(ZapConfigError):
            client.start_spider("not-a-url")

    def test_spider_status_parses_and_bounds(self):
        client, _ = make_client(b'{"status": "50"}')
        self.assertEqual(client.spider_status(0), 50)

        out_of_range, _ = make_client(b'{"status": "150"}')
        with self.assertRaises(ZapResponseError):
            out_of_range.spider_status(0)

        non_numeric, _ = make_client(b'{"status": "abc"}')
        with self.assertRaises(ZapResponseError):
            non_numeric.spider_status(0)

    def test_spider_status_rejects_bad_scan_id(self):
        client, _ = make_client(b'{"status": "0"}')
        for scan_id in [-1, True, "0"]:
            with self.subTest(scan_id=scan_id):
                with self.assertRaises(ZapConfigError):
                    client.spider_status(scan_id)  # type: ignore[arg-type]

    def test_spider_results_returns_list(self):
        client, transport = make_client(b'{"results": [{"url": "https://example.com/"}]}')
        results = client.spider_results(2)
        self.assertEqual(len(results), 1)
        self.assertIn("scanId=2", transport.requests[0][1])

    def test_spider_results_missing_key_raises(self):
        client, _ = make_client(b'{"other": []}')
        with self.assertRaises(ZapResponseError):
            client.spider_results(0)

    def test_stop_spider_uses_action(self):
        client, transport = make_client(b'{"result": "OK"}')
        client.stop_spider(2)
        self.assertIn("/JSON/spider/action/stop/", transport.requests[0][1])
        self.assertIn("scanId=2", transport.requests[0][1])


class AjaxSpiderClientTests(unittest.TestCase):
    def test_start_ajax_spider_returns_id_when_present(self):
        client, transport = make_client(b'{"scan": "0"}')
        self.assertEqual(client.start_ajax_spider("https://example.com/"), 0)
        url = transport.requests[0][1]
        self.assertIn("/JSON/ajaxSpider/action/scan/", url)
        self.assertIn("inScope=true", url)
        self.assertIn("subtreeOnly=true", url)

    def test_start_ajax_spider_returns_none_without_id(self):
        client, _ = make_client(b'{"result": "OK"}')
        self.assertIsNone(client.start_ajax_spider("https://example.com/"))

    def test_ajax_spider_status_parses(self):
        client, _ = make_client(b'{"status": "running"}')
        self.assertEqual(client.ajax_spider_status(), "running")

    def test_ajax_spider_status_missing_raises(self):
        client, _ = make_client(b'{"other": "x"}')
        with self.assertRaises(ZapResponseError):
            client.ajax_spider_status()

    def test_ajax_spider_results_paginated_params(self):
        client, transport = make_client(b'{"results": [{"url": "x"}]}')
        results = client.ajax_spider_results(start=10, count=5)
        self.assertEqual(results, [{"url": "x"}])
        url = transport.requests[0][1]
        self.assertIn("start=10", url)
        self.assertIn("count=5", url)

    def test_ajax_spider_results_missing_key_raises(self):
        client, _ = make_client(b'{"other": []}')
        with self.assertRaises(ZapResponseError):
            client.ajax_spider_results()

    def test_stop_ajax_spider_uses_action(self):
        client, transport = make_client(b'{"result": "OK"}')
        client.stop_ajax_spider()
        self.assertIn("/JSON/ajaxSpider/action/stop/", transport.requests[0][1])


class RedactionTests(unittest.TestCase):
    def test_client_errors_never_leak_key(self):
        client, _ = make_client(
            b'{"code": "BAD", "message": "key scopekey456 invalid"}',
            b"scopekey456 in malformed body",
        )
        with self.assertRaises(Exception) as ctx:
            client.create_context("scan-1")
        self.assertNotIn(API_KEY, str(ctx.exception))

    def test_client_repr_never_leaks_key(self):
        client, _ = make_client()
        self.assertNotIn(API_KEY, repr(client))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
