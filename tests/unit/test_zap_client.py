"""Offline unit tests for the low-level ZAP API client.

Every test uses a fake transport and in-memory responses: no sockets, no
subprocesses, and no network access.
"""

import unittest

from red_teaming.tools.zap.client import UrllibTransport, ZapApiClient
from red_teaming.tools.zap.models import (
    DEFAULT_API_TIMEOUT,
    HttpResponse,
    ZapApiResultError,
    ZapConfigError,
    ZapEndpoint,
    ZapHttpError,
    ZapResponseError,
    ZapTransportError,
    ZapVersionError,
    compare_versions,
    parse_version,
    version_at_least,
)

API_KEY = "testkey123"


class FakeTransport:
    """Records requests and replays queued responses/exceptions."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def request(self, method, url, timeout):
        self.requests.append((method, url, timeout))
        if not self.responses:
            raise ZapTransportError("no queued response")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class EndpointValidationTests(unittest.TestCase):
    def test_accepts_loopback_variants(self):
        cases = {
            "http://127.0.0.1:8080": "http://127.0.0.1:8080",
            "http://localhost:8080": "http://localhost:8080",
            "http://LOCALHOST:8080": "http://localhost:8080",
            "http://[::1]:8080": "http://[::1]:8080",
            "https://127.0.0.1:9090/": "https://127.0.0.1:9090",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                endpoint = ZapEndpoint.parse(raw)
                self.assertEqual(endpoint.base_url, expected)
                self.assertEqual(str(endpoint), expected)

    def test_rejects_non_loopback_hosts(self):
        for raw in [
            "http://example.com:8080",
            "http://10.0.0.1:8080",
            "http://192.0.2.1:8080",
            "http://[2001:db8::1]:8080",
            "http://localhost.evil.com:8080",
        ]:
            with self.subTest(raw=raw):
                with self.assertRaises(ZapConfigError):
                    ZapEndpoint.parse(raw)

    def test_rejects_credentials(self):
        for raw in [
            "http://user:pass@127.0.0.1:8080",
            "http://user@127.0.0.1:8080",
            "http://@127.0.0.1:8080",
        ]:
            with self.subTest(raw=raw):
                with self.assertRaises(ZapConfigError):
                    ZapEndpoint.parse(raw)

    def test_rejects_path_query_and_fragment(self):
        for raw in [
            "http://127.0.0.1:8080/api",
            "http://127.0.0.1:8080/?x=1",
            "http://127.0.0.1:8080/#frag",
        ]:
            with self.subTest(raw=raw):
                with self.assertRaises(ZapConfigError):
                    ZapEndpoint.parse(raw)

    def test_rejects_unsupported_schemes(self):
        for raw in ["ftp://127.0.0.1:8080", "file://127.0.0.1:8080", "//127.0.0.1:8080"]:
            with self.subTest(raw=raw):
                with self.assertRaises(ZapConfigError):
                    ZapEndpoint.parse(raw)

    def test_rejects_invalid_ports(self):
        for raw in [
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:99999",
            "http://127.0.0.1:notaport",
        ]:
            with self.subTest(raw=raw):
                with self.assertRaises(ZapConfigError):
                    ZapEndpoint.parse(raw)

    def test_rejects_blank_and_control_input(self):
        for raw in ["", "   ", " http://127.0.0.1:8080", "http://127.0.0.1:8080\n"]:
            with self.subTest(raw=repr(raw)):
                with self.assertRaises(ZapConfigError):
                    ZapEndpoint.parse(raw)

    def test_rejects_non_string(self):
        with self.assertRaises(ZapConfigError):
            ZapEndpoint.parse(123)  # type: ignore[arg-type]

    def test_from_host_port_validates(self):
        endpoint = ZapEndpoint.from_host_port("127.0.0.1", 8080)
        self.assertEqual(endpoint.base_url, "http://127.0.0.1:8080")
        for host, port in [("example.com", 8080), ("127.0.0.1", 0), ("127.0.0.1", True)]:
            with self.subTest(host=host, port=port):
                with self.assertRaises(ZapConfigError):
                    ZapEndpoint.from_host_port(host, port)


class ClientConstructionTests(unittest.TestCase):
    def test_default_transport_is_urllib(self):
        client = ZapApiClient("http://127.0.0.1:8080", API_KEY)
        self.assertIsInstance(client._transport, UrllibTransport)

    def test_accepts_endpoint_object_and_parses_string(self):
        endpoint = ZapEndpoint.parse("http://127.0.0.1:8080")
        client = ZapApiClient(endpoint, API_KEY, transport=FakeTransport())
        self.assertEqual(client.endpoint, endpoint)
        self.assertEqual(client.min_version, "2.17.0")

    def test_rejects_blank_or_invalid_api_keys(self):
        for key in ["", "   ", "abc 123", "abc\n", 123, None]:
            with self.subTest(key=key):
                with self.assertRaises(ZapConfigError):
                    ZapApiClient("http://127.0.0.1:8080", key)  # type: ignore[arg-type]

    def test_rejects_invalid_timeout(self):
        for timeout in [0, -1, float("inf"), float("nan"), "10", True]:
            with self.subTest(timeout=timeout):
                with self.assertRaises(ZapConfigError):
                    ZapApiClient("http://127.0.0.1:8080", API_KEY, timeout=timeout)  # type: ignore[arg-type]

    def test_repr_redacts_api_key(self):
        client = ZapApiClient("http://127.0.0.1:8080", API_KEY, transport=FakeTransport())
        self.assertNotIn(API_KEY, repr(client))
        self.assertIn("***", repr(client))


class KeylessClientTests(unittest.TestCase):
    """Explicit, loopback-only keyless mode for the local health smoke."""

    def test_default_mode_still_requires_and_sends_a_key(self):
        # Accidental ``api_key=None`` without opt-in stays a config error.
        with self.assertRaises(ZapConfigError):
            ZapApiClient("http://127.0.0.1:8080", None, transport=FakeTransport())
        transport = FakeTransport(HttpResponse(200, b'{"version": "2.17.0"}'))
        client = ZapApiClient("http://127.0.0.1:8080", API_KEY, transport=transport)
        self.assertFalse(client.keyless)
        self.assertEqual(client.get_version(), "2.17.0")
        self.assertIn(f"apikey={API_KEY}", transport.requests[0][1])

    def test_keyless_accepts_none_only_with_explicit_opt_in(self):
        client = ZapApiClient(
            "http://127.0.0.1:8080",
            None,
            keyless=True,
            transport=FakeTransport(),
        )
        self.assertTrue(client.keyless)

    def test_keyless_rejects_a_supplied_api_key(self):
        for key in ["secret", "", "   "]:
            with self.subTest(key=key):
                with self.assertRaises(ZapConfigError):
                    ZapApiClient(
                        "http://127.0.0.1:8080", key, keyless=True, transport=FakeTransport()
                    )

    def test_keyless_flag_must_be_a_boolean(self):
        with self.assertRaises(ZapConfigError):
            ZapApiClient(
                "http://127.0.0.1:8080",
                None,
                keyless="yes",  # type: ignore[arg-type]
                transport=FakeTransport(),
            )

    def test_keyless_requests_never_include_an_apikey_parameter(self):
        transport = FakeTransport(HttpResponse(200, b'{"version": "2.17.0"}'))
        client = ZapApiClient(
            "http://127.0.0.1:8080", None, keyless=True, transport=transport
        )
        self.assertEqual(client.get_version(), "2.17.0")
        url = transport.requests[0][1]
        self.assertNotIn("apikey", url.lower())
        self.assertTrue(url.endswith("/JSON/core/view/version/?"))

    def test_keyless_repr_does_not_imply_a_secret_exists(self):
        client = ZapApiClient(
            "http://127.0.0.1:8080", None, keyless=True, transport=FakeTransport()
        )
        text = repr(client)
        self.assertIn("keyless=True", text)
        self.assertNotIn("api_key", text)
        self.assertNotIn("***", text)

    def test_keyless_revalidates_a_prebuilt_endpoint_as_loopback(self):
        # ``ZapEndpoint`` fields are public; a dataclass built by hand must
        # still be rejected in keyless mode.
        rogue = ZapEndpoint(scheme="http", host="example.com", port=80)
        with self.assertRaises(ZapConfigError):
            ZapApiClient(rogue, None, keyless=True, transport=FakeTransport())


class VersionHelperTests(unittest.TestCase):
    def test_parse_version(self):
        self.assertEqual(parse_version("2.17.0"), (2, 17, 0))
        self.assertEqual(parse_version("2.17.1-SNAPSHOT"), (2, 17, 1))

    def test_parse_rejects_invalid(self):
        for value in ["", "abc", None]:
            with self.subTest(value=value):
                with self.assertRaises(ZapConfigError):
                    parse_version(value)  # type: ignore[arg-type]

    def test_compare_versions(self):
        self.assertEqual(compare_versions("2.17.0", "2.17.0"), 0)
        self.assertEqual(compare_versions("2.17", "2.17.0"), 0)
        self.assertEqual(compare_versions("2.17.1", "2.17.0"), 1)
        self.assertEqual(compare_versions("2.16.1", "2.17.0"), -1)

    def test_version_at_least(self):
        self.assertTrue(version_at_least("2.17.0", "2.17.0"))
        self.assertTrue(version_at_least("3.0.0", "2.17.0"))
        self.assertFalse(version_at_least("2.16.1", "2.17.0"))


class RequestBuildingTests(unittest.TestCase):
    def setUp(self):
        self.transport = FakeTransport(HttpResponse(200, b'{"version": "2.17.0"}'))
        self.client = ZapApiClient(
            "http://127.0.0.1:8080", API_KEY, transport=self.transport
        )

    def test_version_request_shape(self):
        self.assertEqual(self.client.get_version(), "2.17.0")
        method, url, timeout = self.transport.requests[0]
        self.assertEqual(method, "GET")
        self.assertIn("/JSON/core/view/version/", url)
        self.assertIn(f"apikey={API_KEY}", url)
        self.assertEqual(timeout, DEFAULT_API_TIMEOUT)

    def test_parameters_are_encoded_safely(self):
        self.client._call("core", "version", {"note": "a b&c=d", "n": 5, "flag": True})
        url = self.transport.requests[0][1]
        self.assertIn("note=a+b%26c%3Dd", url)
        self.assertIn("n=5", url)
        self.assertIn("flag=true", url)

    def test_reserved_and_invalid_parameters_are_rejected(self):
        with self.assertRaises(ZapConfigError):
            self.client._call("core", "version", {"apikey": "evil"})
        with self.assertRaises(ZapConfigError):
            self.client._call("core", "version", {"bad name": "x"})

    def test_invalid_identifiers_are_rejected(self):
        for component, operation in [
            ("core/../x", "version"),
            ("core", "ver sion"),
            ("1core", "version"),
        ]:
            with self.subTest(component=component, operation=operation):
                with self.assertRaises(ZapConfigError):
                    self.client._call(component, operation)

    def test_shutdown_uses_action_endpoint(self):
        transport = FakeTransport(HttpResponse(200, b'{"message": "shutting down"}'))
        client = ZapApiClient("http://127.0.0.1:8080", API_KEY, transport=transport)
        client.shutdown()
        self.assertIn("/JSON/core/action/shutdown/", transport.requests[0][1])

    def test_health_reflects_reachability(self):
        healthy = ZapApiClient(
            "http://127.0.0.1:8080",
            API_KEY,
            transport=FakeTransport(HttpResponse(200, b'{"version": "2.17.0"}')),
        )
        self.assertTrue(healthy.health())
        unhealthy = ZapApiClient(
            "http://127.0.0.1:8080",
            API_KEY,
            transport=FakeTransport(ZapTransportError("down")),
        )
        self.assertFalse(unhealthy.health())

    def test_check_version_success_and_mismatch(self):
        ok = ZapApiClient(
            "http://127.0.0.1:8080",
            API_KEY,
            transport=FakeTransport(HttpResponse(200, b'{"version": "2.18.0"}')),
        )
        self.assertEqual(ok.check_version(), "2.18.0")

        old = ZapApiClient(
            "http://127.0.0.1:8080",
            API_KEY,
            transport=FakeTransport(HttpResponse(200, b'{"version": "2.16.1"}')),
        )
        with self.assertRaises(ZapVersionError):
            old.check_version()

    def test_custom_minimum_version(self):
        client = ZapApiClient(
            "http://127.0.0.1:8080",
            API_KEY,
            transport=FakeTransport(HttpResponse(200, b'{"version": "2.16.0"}')),
            min_version="2.15.0",
        )
        self.assertEqual(client.check_version(), "2.16.0")


class ResponseHandlingTests(unittest.TestCase):
    def make_client(self, *responses):
        return ZapApiClient(
            "http://127.0.0.1:8080", API_KEY, transport=FakeTransport(*responses)
        )

    def test_malformed_json_raises_response_error(self):
        client = self.make_client(HttpResponse(200, b"<html>not json</html>"))
        with self.assertRaises(ZapResponseError):
            client.get_version()

    def test_invalid_utf8_raises_response_error(self):
        client = self.make_client(HttpResponse(200, b"\xff\xfe\xfa"))
        with self.assertRaises(ZapResponseError):
            client.get_version()

    def test_non_object_root_raises_response_error(self):
        for body in [b"[1, 2, 3]", b'"scalar"', b"42"]:
            with self.subTest(body=body):
                client = self.make_client(HttpResponse(200, body))
                with self.assertRaises(ZapResponseError):
                    client.get_version()

    def test_missing_version_field_raises_response_error(self):
        client = self.make_client(HttpResponse(200, b'{"other": "value"}'))
        with self.assertRaises(ZapResponseError):
            client.get_version()

    def test_zap_code_error_raises_result_error(self):
        client = self.make_client(
            HttpResponse(200, b'{"code": "BAD_KEY", "message": "invalid key"}')
        )
        with self.assertRaises(ZapApiResultError) as ctx:
            client.get_version()
        self.assertEqual(ctx.exception.code, "BAD_KEY")

    def test_zap_error_field_raises_result_error(self):
        client = self.make_client(HttpResponse(200, b'{"error": "nope"}'))
        with self.assertRaises(ZapApiResultError):
            client.get_version()

    def test_http_error_status_is_preserved(self):
        client = self.make_client(HttpResponse(500, b"server exploded"))
        with self.assertRaises(ZapHttpError) as ctx:
            client.get_version()
        self.assertEqual(ctx.exception.status, 500)

    def test_transport_exception_becomes_transport_error(self):
        for exc in [TimeoutError("timed out"), OSError("reset"), ZapTransportError("down")]:
            with self.subTest(exc=exc):
                client = self.make_client(exc)
                with self.assertRaises(ZapTransportError):
                    client.get_version()

    def test_unexpected_transport_exception_is_wrapped(self):
        client = self.make_client(ValueError("boom"))
        with self.assertRaises(ZapTransportError):
            client.get_version()

    def test_invalid_transport_result_is_rejected(self):
        client = self.make_client("not-a-response")
        with self.assertRaises(ZapTransportError):
            client.get_version()


class RedactionTests(unittest.TestCase):
    def test_error_bodies_never_leak_the_key(self):
        cases = [
            HttpResponse(200, b'{"code": "BAD", "message": "key testkey123 invalid"}'),
            HttpResponse(500, b"server said testkey123 is wrong"),
            HttpResponse(200, b"testkey123 leaked in malformed json"),
        ]
        for body in cases:
            with self.subTest(body=body):
                client = ZapApiClient(
                    "http://127.0.0.1:8080",
                    API_KEY,
                    transport=FakeTransport(body),
                )
                with self.assertRaises(Exception) as ctx:
                    client.get_version()
                self.assertNotIn(API_KEY, str(ctx.exception))

    def test_transport_error_is_redacted(self):
        client = ZapApiClient(
            "http://127.0.0.1:8080",
            API_KEY,
            transport=FakeTransport(ZapTransportError(f"failure for {API_KEY}")),
        )
        with self.assertRaises(ZapTransportError) as ctx:
            client.get_version()
        self.assertNotIn(API_KEY, str(ctx.exception))

    def test_repr_and_endpoint_never_contain_key(self):
        client = ZapApiClient("http://127.0.0.1:8080", API_KEY, transport=FakeTransport())
        self.assertNotIn(API_KEY, repr(client))
        self.assertNotIn(API_KEY, repr(client.endpoint))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
