"""Unit tests for domain/target validation and normalization.

All names use reserved example domains and no test performs network,
socket, DNS, or process calls.
"""

import unittest

from red_teaming.projects.models import (
    DEFAULT_PORTS,
    SUPPORTED_SCHEMES,
    ProjectDomain,
    Target,
    ValidationError,
    normalize_dns_name,
    normalize_url_path,
)


class NormalizeDnsNameTests(unittest.TestCase):
    def test_lowercases_and_removes_one_trailing_dot(self):
        self.assertEqual(normalize_dns_name("Example.COM."), "example.com")

    def test_rejects_double_trailing_dot(self):
        with self.assertRaises(ValidationError):
            normalize_dns_name("example.com..")

    def test_idna_unicode_is_encoded(self):
        self.assertEqual(normalize_dns_name("Bücher.Example"), "xn--bcher-kva.example")

    def test_idna_subdomain_is_encoded(self):
        self.assertEqual(
            normalize_dns_name("WWW.Bücher.Example."),
            "www.xn--bcher-kva.example",
        )

    def test_rejects_blank_and_whitespace(self):
        for value in ["", "   ", " example.com", "example.com "]:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    normalize_dns_name(value)

    def test_rejects_non_string(self):
        with self.assertRaises(ValidationError):
            normalize_dns_name(123)  # type: ignore[arg-type]

    def test_rejects_ip_literals(self):
        for value in ["192.0.2.1", "198.51.100.7", "[2001:db8::1]", "::1", "999.999.999.999"]:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    normalize_dns_name(value)

    def test_rejects_traversal_like_input(self):
        for value in ["..", "example.com/..", "a..b.example", ".example.com", "example..com"]:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    normalize_dns_name(value)

    def test_rejects_single_label(self):
        with self.assertRaises(ValidationError):
            normalize_dns_name("localhost")

    def test_rejects_invalid_characters(self):
        for value in ["exa mple.com", "exa_mple.com", "ex@mple.com", "example.com:80"]:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    normalize_dns_name(value)


class NormalizeUrlPathTests(unittest.TestCase):
    def test_empty_path_is_preserved(self):
        self.assertEqual(normalize_url_path(""), "")

    def test_unicode_is_percent_encoded(self):
        self.assertEqual(normalize_url_path("/café"), "/caf%C3%A9")

    def test_existing_encoding_is_preserved(self):
        self.assertEqual(normalize_url_path("/a%20b"), "/a%20b")

    def test_case_is_preserved(self):
        self.assertEqual(normalize_url_path("/App/Login"), "/App/Login")

    def test_rejects_backslashes_and_control_characters(self):
        for value in ["/a\\b", "/a\tb"]:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    normalize_url_path(value)

    def test_rejects_relative_and_traversal_paths(self):
        for value in ["relative", "/a/../b", "/..", "/%2e%2e/x"]:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    normalize_url_path(value)


class ProjectDomainTests(unittest.TestCase):
    def test_parse_normalizes(self):
        domain = ProjectDomain.parse("Example.COM.")
        self.assertEqual(domain.name, "example.com")
        self.assertEqual(str(domain), "example.com")

    def test_contains(self):
        domain = ProjectDomain.parse("example.com")
        self.assertTrue(domain.contains("example.com"))
        self.assertTrue(domain.contains("App.Example.com"))
        self.assertFalse(domain.contains("example.org"))
        self.assertFalse(domain.contains("notexample.com"))


class TargetTests(unittest.TestCase):
    def setUp(self):
        self.domain = ProjectDomain.parse("example.com")

    def test_constants(self):
        self.assertEqual(SUPPORTED_SCHEMES, ("http", "https"))
        self.assertEqual(DEFAULT_PORTS, {"http": 80, "https": 443})

    def test_accepts_root_domain_http(self):
        target = Target.parse("http://example.com", self.domain)
        self.assertEqual(target.scheme, "http")
        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.port, 80)
        self.assertEqual(target.path, "")
        self.assertEqual(target.url, "http://example.com")

    def test_accepts_https_subdomain_and_path(self):
        target = Target.parse("https://App.Example.com/App/Login", self.domain)
        self.assertEqual(target.host, "app.example.com")
        self.assertEqual(target.port, 443)
        self.assertEqual(target.path, "/App/Login")
        self.assertEqual(target.url, "https://app.example.com/App/Login")

    def test_accepts_explicit_default_ports(self):
        self.assertEqual(
            Target.parse("http://example.com:80/", self.domain).url,
            "http://example.com/",
        )
        self.assertEqual(
            Target.parse("https://example.com:443/x", self.domain).url,
            "https://example.com/x",
        )

    def test_rejects_unsupported_ports(self):
        for url in [
            "http://example.com:8080/",
            "https://example.com:8443/",
            "http://example.com:0/",
            "http://example.com:99999/",
        ]:
            with self.subTest(url=url):
                with self.assertRaises(ValidationError):
                    Target.parse(url, self.domain)

    def test_rejects_userinfo(self):
        for url in [
            "http://user@example.com/",
            "http://user:pass@example.com/",
            "https://a:b@example.com/",
            "http://@example.com/",
        ]:
            with self.subTest(url=url):
                with self.assertRaises(ValidationError):
                    Target.parse(url, self.domain)

    def test_rejects_query_and_fragment(self):
        for url in [
            "http://example.com/?a=1",
            "http://example.com/#frag",
            "http://example.com/p#x",
        ]:
            with self.subTest(url=url):
                with self.assertRaises(ValidationError):
                    Target.parse(url, self.domain)

    def test_rejects_blank_and_malformed_hosts(self):
        for url in [
            "http://",
            "http:///path",
            "http://exa mple.com/",
            "http://example.com\\evil",
            "http://example.com:/",
        ]:
            with self.subTest(url=url):
                with self.assertRaises(ValidationError):
                    Target.parse(url, self.domain)

    def test_rejects_ip_literal_hosts(self):
        for url in ["http://192.0.2.1/", "http://[2001:db8::1]/"]:
            with self.subTest(url=url):
                with self.assertRaises(ValidationError):
                    Target.parse(url, self.domain)

    def test_rejects_non_http_schemes(self):
        for url in [
            "ftp://example.com/",
            "file://example.com/",
            "javascript:alert(1)",
            "//example.com/",
        ]:
            with self.subTest(url=url):
                with self.assertRaises(ValidationError):
                    Target.parse(url, self.domain)

    def test_rejects_unrelated_and_embedded_domains(self):
        for url in [
            "http://example.org/",
            "http://notexample.com/",
            "http://example.com.evil.com/",
        ]:
            with self.subTest(url=url):
                with self.assertRaises(ValidationError):
                    Target.parse(url, self.domain)

    def test_normalizes_unicode_path(self):
        target = Target.parse("http://example.com/café", self.domain)
        self.assertEqual(target.path, "/caf%C3%A9")

    def test_preserves_percent_encoding(self):
        target = Target.parse("http://example.com/a%20b", self.domain)
        self.assertEqual(target.path, "/a%20b")

    def test_rejects_path_traversal_segments(self):
        for url in [
            "http://example.com/a/../b",
            "http://example.com/..",
            "http://example.com/%2e%2e/x",
        ]:
            with self.subTest(url=url):
                with self.assertRaises(ValidationError):
                    Target.parse(url, self.domain)

    def test_accepts_idn_domain_and_subdomain(self):
        domain = ProjectDomain.parse("bücher.example")
        target = Target.parse("https://www.bücher.example/", domain)
        self.assertEqual(target.domain, "xn--bcher-kva.example")
        self.assertEqual(target.host, "www.xn--bcher-kva.example")

    def test_accepts_string_domain_argument(self):
        target = Target.parse("https://example.com/x", "Example.COM")
        self.assertEqual(target.domain, "example.com")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
