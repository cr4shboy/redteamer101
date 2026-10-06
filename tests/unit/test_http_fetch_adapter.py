"""Synthetic HTTP metadata adapter checks; no network transport is composed."""

import unittest
from dataclasses import FrozenInstanceError

from red_teaming.projects.models import ValidationError
from red_teaming.recon.scope import DomainScope
from red_teaming.tools.http_fetch import (
    FetchResult,
    FetchResponse,
    HttpFetchAdapter,
    HttpFetchError,
)


class HttpFetchAdapterTests(unittest.TestCase):
    def setUp(self):
        self.scope = DomainScope.parse(["example.com"], ["excluded.example.com"])
        self.calls = []

    def adapter(self, response=FetchResponse(200, "Apache/2.4.41 (Unix)")):
        def transport(request):
            self.calls.append(request)
            return response
        return HttpFetchAdapter(transport)

    def test_one_bounded_get_extracts_only_status_and_claim(self):
        result = self.adapter().fetch(
            url="HTTPS://WWW.EXAMPLE.COM/", scope=self.scope, source_id="response-1",
        )
        self.assertEqual(len(self.calls), 1)
        request = self.calls[0]
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.url, "https://www.example.com/")
        self.assertEqual(request.timeout_seconds, 10.0)
        self.assertEqual(request.max_server_header_chars, 256)
        self.assertFalse(request.follow_redirects)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.fingerprint.status, "reported")
        self.assertEqual(result.fingerprint.claimed_product, "Apache")
        self.assertEqual(result.fingerprint.claimed_version, "2.4.41")
        self.assertNotIn("Unix", repr(result))
        with self.assertRaises(FrozenInstanceError):
            result.status_code = 404

    def test_missing_header_is_an_unknown_claim(self):
        result = self.adapter(FetchResponse(204, None)).fetch(
            url="https://www.example.com/", scope=self.scope, source_id="response-1",
        )
        self.assertEqual(result.status_code, 204)
        self.assertEqual(result.fingerprint.status, "unknown")

    def test_oversized_or_garbage_header_fails_closed(self):
        for header in ("A" * 257, "", " nginx", "nginx\r\nX-Test: x", "☃", "---"):
            with self.subTest(header=header):
                self.calls.clear()
                with self.assertRaises(HttpFetchError):
                    self.adapter(FetchResponse(200, header)).fetch(
                        url="https://www.example.com/", scope=self.scope,
                        source_id="response-1",
                    )
                self.assertEqual(len(self.calls), 1)

    def test_bad_response_shape_or_status_fails_closed(self):
        for response in (None, {"status_code": 200}, FetchResponse(True, "nginx"),
                         FetchResponse(99, "nginx"), FetchResponse(600, "nginx")):
            with self.subTest(response=response):
                with self.assertRaises(HttpFetchError):
                    self.adapter(response).fetch(
                        url="https://www.example.com/", scope=self.scope,
                        source_id="response-1",
                    )

    def test_fetch_result_contract_rejects_invalid_values(self):
        fingerprint = self.adapter().fetch(
            url="https://www.example.com/", scope=self.scope,
            source_id="response-1",
        ).fingerprint
        for status in (True, 99, 600, "200"):
            with self.subTest(status=status), self.assertRaises(ValueError):
                FetchResult(status, fingerprint)
        with self.assertRaises(ValueError):
            FetchResult(200, "not-a-fingerprint")

    def test_scope_and_source_rejected_before_transport(self):
        adapter = self.adapter()
        for url in ("https://elsewhere.test/", "https://excluded.example.com/",
                    "https://www.example.com/?q=1", "https://www.example.com:8443/"):
            with self.subTest(url=url), self.assertRaises(ValidationError):
                adapter.fetch(url=url, scope=self.scope, source_id="response-1")
        with self.assertRaises(ValidationError):
            adapter.fetch(
                url="https://www.example.com/", scope=self.scope,
                source_id="../invalid",
            )
        self.assertEqual(self.calls, [])

    def test_transport_failure_has_no_data_in_error(self):
        def transport(_request):
            raise RuntimeError("sensitive response detail")
        with self.assertRaisesRegex(HttpFetchError, "^HTTP metadata transport failed$") as ctx:
            HttpFetchAdapter(transport).fetch(
                url="https://www.example.com/", scope=self.scope,
                source_id="response-1",
            )
        self.assertIsNone(ctx.exception.__cause__)


if __name__ == "__main__":
    unittest.main()
