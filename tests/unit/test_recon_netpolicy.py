"""Offline unit tests for the immutable RECON-002 network policy.

No network, DNS, socket, or process activity occurs.
"""

import unittest
from dataclasses import FrozenInstanceError

from red_teaming.recon.netpolicy import (
    DNS_SCOPE_BOOTSTRAP,
    DNS_SCOPE_TARGET,
    DNS_TYPE_A,
    DNS_TYPE_AAAA,
    DNS_TYPE_CNAME,
    RECON_002_POLICY,
    PolicyError,
    ReconNetworkPolicy,
    describe_dns_type,
    is_global_literal,
    normalize_policy_name,
    validate_upstream_ip,
)


class CanonicalConstantsTests(unittest.TestCase):
    def test_exact_allowlist(self):
        self.assertEqual(RECON_002_POLICY.root_domain, "acme.example")
        self.assertEqual(RECON_002_POLICY.https_host, "crt.sh")
        self.assertEqual(RECON_002_POLICY.https_port, 443)
        self.assertEqual(RECON_002_POLICY.upstream_dns_host, "1.1.1.1")
        self.assertEqual(RECON_002_POLICY.upstream_dns_port, 53)
        self.assertEqual(RECON_002_POLICY.dns_qps, 5)
        self.assertEqual(RECON_002_POLICY.dns_max_concurrent, 2)

    def test_policy_is_frozen(self):
        with self.assertRaises(FrozenInstanceError):
            RECON_002_POLICY.root_domain = "example.com"  # type: ignore[misc]


class NameClassificationTests(unittest.TestCase):
    def test_target_scope(self):
        p = RECON_002_POLICY
        self.assertEqual(p.classify_dns_question("acme.example", DNS_TYPE_A), DNS_SCOPE_TARGET)
        self.assertEqual(p.classify_dns_question("WWW.Acme.Example.", DNS_TYPE_AAAA), DNS_SCOPE_TARGET)
        self.assertEqual(p.classify_dns_question("www.acme.example", DNS_TYPE_CNAME), DNS_SCOPE_TARGET)

    def test_bootstrap_scope(self):
        p = RECON_002_POLICY
        self.assertEqual(p.classify_dns_question("CRT.SH", DNS_TYPE_A), DNS_SCOPE_BOOTSTRAP)
        self.assertEqual(p.classify_dns_question("crt.sh.", DNS_TYPE_AAAA), DNS_SCOPE_BOOTSTRAP)
        self.assertIsNone(p.classify_dns_question("crt.sh", DNS_TYPE_CNAME))
        self.assertIsNone(p.classify_dns_question("www.crt.sh", DNS_TYPE_A))

    def test_disallowed_names(self):
        p = RECON_002_POLICY
        for name in ("example.com", "evilacme.example", "acme.example.evil.com", "notacme.example"):
            self.assertIsNone(p.classify_dns_question(name, DNS_TYPE_A), name)

    def test_disallowed_types(self):
        p = RECON_002_POLICY
        self.assertIsNone(p.classify_dns_question("acme.example", 15))  # MX
        self.assertIsNone(p.classify_dns_question("acme.example", 16))  # TXT
        self.assertIsNone(p.classify_dns_question("crt.sh", 28 + 1))

    def test_malformed_names(self):
        p = RECON_002_POLICY
        self.assertIsNone(p.classify_dns_question("127.0.0.1", DNS_TYPE_A))
        self.assertIsNone(p.classify_dns_question("localhost", DNS_TYPE_A))
        self.assertIsNone(p.classify_dns_question("bad..name", DNS_TYPE_A))
        self.assertIsNone(p.classify_dns_question(None, DNS_TYPE_A))

    def test_is_target_and_bootstrap(self):
        p = RECON_002_POLICY
        self.assertTrue(p.is_target_name("acme.example"))
        self.assertTrue(p.is_target_name("a.acme.example"))
        self.assertFalse(p.is_target_name("crt.sh"))
        self.assertTrue(p.is_bootstrap_name("crt.sh"))
        self.assertFalse(p.is_bootstrap_name("acme.example"))


class ConnectAuthorityTests(unittest.TestCase):
    def test_exact_authority_only(self):
        p = RECON_002_POLICY
        self.assertTrue(p.is_allowed_connect_authority("crt.sh", 443))
        self.assertTrue(p.is_allowed_connect_authority("CRT.SH.", 443))
        for host, port in (
            ("crt.sh", 80),
            ("crt.sh", 8443),
            ("crt.sh", 444),
            ("acme.example", 443),
            ("www.crt.sh", 443),
            ("evilcrt.sh", 443),
            ("127.0.0.1", 443),
        ):
            self.assertFalse(p.is_allowed_connect_authority(host, port), (host, port))


class UpstreamLiteralTests(unittest.TestCase):
    def test_global_literals_only(self):
        self.assertTrue(is_global_literal("8.8.8.8"))
        self.assertTrue(is_global_literal("1.1.1.1"))
        self.assertTrue(is_global_literal("2606:4700::1111"))
        for bad in (
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "::1",
            "fc00::1",
            "2001:db8::1",
            "::ffff:8.8.8.8",
            "",
            "8.8.8.8 ",
            "not-an-ip",
        ):
            self.assertFalse(is_global_literal(bad), bad)

    def test_validate_upstream_ip_raises(self):
        self.assertEqual(validate_upstream_ip("1.1.1.1"), "1.1.1.1")
        with self.assertRaises(PolicyError):
            validate_upstream_ip("127.0.0.1")

    def test_normalize_policy_name(self):
        self.assertEqual(normalize_policy_name("CRT.SH."), "crt.sh")
        with self.assertRaises(PolicyError):
            normalize_policy_name("bad name")

    def test_describe_dns_type(self):
        self.assertEqual(describe_dns_type(1), "A")
        self.assertEqual(describe_dns_type(5), "CNAME")
        self.assertEqual(describe_dns_type(28), "AAAA")
        self.assertEqual(describe_dns_type(15), "TYPE15")


class PolicyValidationTests(unittest.TestCase):
    def test_rejects_bad_configuration(self):
        with self.assertRaises(PolicyError):
            ReconNetworkPolicy(root_domain="localhost")
        with self.assertRaises(PolicyError):
            ReconNetworkPolicy(https_port=0)
        with self.assertRaises(PolicyError):
            ReconNetworkPolicy(upstream_dns_host="not-an-ip")
        with self.assertRaises(PolicyError):
            ReconNetworkPolicy(upstream_dns_host="127.0.0.1")
        with self.assertRaises(PolicyError):
            ReconNetworkPolicy(dns_qps=0)
        with self.assertRaises(PolicyError):
            ReconNetworkPolicy(dns_max_concurrent=0)

    def test_accepts_narrowed_valid_policy(self):
        narrowed = ReconNetworkPolicy(root_domain="Example.COM.")
        self.assertEqual(narrowed.root_domain, "example.com")
        self.assertEqual(narrowed.https_host, "crt.sh")


if __name__ == "__main__":
    unittest.main()
