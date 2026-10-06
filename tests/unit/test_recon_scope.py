"""Unit tests for deterministic, domain-neutral recon scope intake.

All names use reserved example domains. No test performs DNS, socket,
subprocess, or filesystem activity.
"""

import unittest

from red_teaming.projects.models import ProjectDomain, ValidationError
from red_teaming.recon.scope import EXCLUDED, IN_SCOPE, OUT_OF_SCOPE, DomainScope


class ScopeNormalizationTests(unittest.TestCase):
    def test_lowercases_dedups_and_orders_roots(self):
        scope = DomainScope.parse(["B.Example.", "a.example", "A.EXAMPLE"])
        self.assertEqual(scope.authorized_domains, ("a.example", "b.example"))

    def test_blank_collection_rejected(self):
        with self.assertRaises(ValidationError):
            DomainScope.parse([])

    def test_bare_string_collection_rejected(self):
        with self.assertRaises(ValidationError):
            DomainScope.parse("example.com")

    def test_non_iterable_rejected(self):
        with self.assertRaises(ValidationError):
            DomainScope.parse(123)

    def test_idna_roots_normalized(self):
        scope = DomainScope.parse(["Bücher.Example"])
        self.assertEqual(scope.authorized_domains, ("xn--bcher-kva.example",))

    def test_accepts_project_domain_instances(self):
        scope = DomainScope.parse([ProjectDomain.parse("example.com")])
        self.assertEqual(scope.authorized_domains, ("example.com",))

    def test_invalid_root_values_rejected(self):
        for value in [
            "",
            "   ",
            "localhost",
            "192.0.2.1",
            "[2001:db8::1]",
            "*.example.com",
            "http://example.com",
            "https://example.com/path",
            "exa mple.com",
            "exa\tmple.com",
            "example.com/..",
            "..",
            "example.com..",
            "example.com:443",
            "user@example.com",
        ]:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    DomainScope.parse([value])


class ExclusionTests(unittest.TestCase):
    def setUp(self):
        self.scope = DomainScope.parse(["example.com"], ["Www.Example.com", "example.com"])

    def test_exclusions_normalized_dedup_sorted(self):
        self.assertEqual(
            self.scope.excluded_hosts, ("example.com", "www.example.com")
        )

    def test_exact_exclusion_only(self):
        self.assertEqual(self.scope.classify("www.example.com"), EXCLUDED)
        self.assertEqual(self.scope.classify("deep.www.example.com"), IN_SCOPE)
        self.assertTrue(self.scope.is_excluded("www.example.com"))
        self.assertTrue(self.scope.is_excluded("example.com"))
        self.assertFalse(self.scope.is_excluded("foo.example.com"))

    def test_unrelated_exclusion_rejected(self):
        with self.assertRaises(ValidationError):
            DomainScope.parse(["example.com"], ["other.org"])

    def test_invalid_exclusions_rejected(self):
        for value in [
            "",
            "*.example.com",
            "http://example.com",
            "exa mple.com",
            "192.0.2.1",
            "notexample.org",
        ]:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    DomainScope.parse(["example.com"], [value])


class ClassificationTests(unittest.TestCase):
    def setUp(self):
        self.scope = DomainScope.parse(["a.example", "b.example"])

    def test_root_is_in_scope(self):
        self.assertEqual(self.scope.classify("a.example"), IN_SCOPE)
        self.assertEqual(self.scope.classify("A.EXAMPLE."), IN_SCOPE)

    def test_arbitrary_depth_in_scope(self):
        self.assertEqual(self.scope.classify("deep.nested.a.example"), IN_SCOPE)
        self.assertTrue(self.scope.contains("a.b.c.d.a.example"))

    def test_sibling_roots_rejected(self):
        for value in ["a.example.org", "nota.example", "b.example.net", "other.example"]:
            with self.subTest(value=value):
                self.assertEqual(self.scope.classify(value), OUT_OF_SCOPE)

    def test_per_root_classification(self):
        self.assertEqual(self.scope.classify("x.a.example", "a.example"), IN_SCOPE)
        self.assertEqual(self.scope.classify("x.b.example", "a.example"), OUT_OF_SCOPE)
        self.assertEqual(self.scope.classify("x.b.example", "b.example"), IN_SCOPE)

    def test_unknown_root_rejected(self):
        with self.assertRaises(ValidationError):
            self.scope.classify("x.a.example", "c.example")

    def test_invalid_candidate_rejected(self):
        for value in ["", "exa mple.com", "http://a.example", "192.0.2.1"]:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    self.scope.classify(value)

    def test_for_root_projection(self):
        scope = DomainScope.parse(
            ["a.example", "b.example"], ["x.a.example", "y.b.example"]
        )
        projection = scope.for_root("a.example")
        self.assertEqual(projection.authorized_domains, ("a.example",))
        self.assertEqual(projection.excluded_hosts, ("x.a.example",))
        with self.assertRaises(ValidationError):
            scope.for_root("c.example")

    def test_to_dict_schema(self):
        scope = DomainScope.parse(["b.example", "a.example"], ["x.a.example"])
        self.assertEqual(
            scope.to_dict(),
            {
                "schema_version": 1,
                "authorized_domains": ["a.example", "b.example"],
                "excluded_hosts": ["x.a.example"],
            },
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
