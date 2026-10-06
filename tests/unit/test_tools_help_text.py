"""Unit tests for exact option-token matching (no substring false positives)."""

import unittest

from red_teaming.tools.help_text import has_options, option_tokens, select_option


class OptionTokenTests(unittest.TestCase):
    def test_extracts_short_and_long_options(self):
        tokens = option_tokens("-d, -domain string --passive [-json]")
        self.assertEqual(tokens, frozenset({"-d", "-domain", "--passive", "-json"}))

    def test_near_collisions_do_not_match(self):
        self.assertFalse(has_options("-aaaa -json -cname", ("-a",)))
        self.assertFalse(has_options("-debug DOMAIN", ("-d",)))
        self.assertFalse(has_options("-jsonl", ("-json",)))
        self.assertFalse(has_options("-silent-mode", ("-silent",)))
        self.assertFalse(has_options("-domain", ("-d",)))

    def test_exact_matches(self):
        self.assertTrue(
            has_options("-a -aaaa -cname -json", ("-a", "-aaaa", "-cname", "-json"))
        )
        self.assertTrue(has_options("usage: [-d]", ("-d",)))

    def test_non_string_is_empty(self):
        self.assertEqual(option_tokens(None), frozenset())
        self.assertFalse(has_options(None, ("-d",)))

    def test_select_option_respects_preference_order(self):
        self.assertEqual(select_option("-d -domain", ("-d", "-domain")), "-d")
        self.assertEqual(select_option("-domain -d", ("-d", "-domain")), "-d")
        self.assertEqual(select_option("-domain", ("-d", "-domain")), "-domain")
        self.assertIsNone(select_option("-debug", ("-d", "-domain")))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
