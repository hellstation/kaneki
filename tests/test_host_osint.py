import unittest

from kaneki.host_osint import parse_host_target


class ParseHostTargetTest(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(parse_host_target("8.8.8.8"), ("ip", "8.8.8.8"))

    def test_domain(self):
        self.assertEqual(parse_host_target("example.com"), ("domain", "example.com"))

    def test_url(self):
        self.assertEqual(
            parse_host_target("https://sub.example.com/x"),
            ("domain", "sub.example.com"),
        )

    def test_invalid(self):
        self.assertIsNone(parse_host_target("???"))
