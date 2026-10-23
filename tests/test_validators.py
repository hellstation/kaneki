import unittest

from kaneki.security.validators import normalize_domain


class NormalizeDomainTest(unittest.TestCase):
    def test_plain_domain(self):
        self.assertEqual(normalize_domain("example.com"), "example.com")

    def test_strips_www(self):
        self.assertEqual(normalize_domain("https://www.example.com/path"), "example.com")

    def test_rejects_invalid(self):
        self.assertIsNone(normalize_domain("not a domain"))
        self.assertIsNone(normalize_domain(""))
