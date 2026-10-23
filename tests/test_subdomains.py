import unittest

from kaneki.security.subdomains import parse_crtsh_records


class ParseCrtshRecordsTest(unittest.TestCase):
    def test_newline_sans_and_common_name(self):
        data = [
            {
                "common_name": "www.edostavka.by",
                "name_value": "test-17.test.edostavka.by\ntest-18.test.edostavka.by",
            }
        ]
        subs, emails = parse_crtsh_records(data, "edostavka.by")
        self.assertEqual(
            subs,
            [
                "test-17.test.edostavka.by",
                "test-18.test.edostavka.by",
                "www.edostavka.by",
            ],
        )
        self.assertEqual(emails, [])

    def test_keeps_wildcard_instead_of_dropping_apex(self):
        data = [{"name_value": "edostavka.by\n*.edostavka.by\n*.api.edostavka.by"}]
        subs, _emails = parse_crtsh_records(data, "edostavka.by")
        self.assertEqual(subs, ["*.api.edostavka.by", "*.edostavka.by"])

    def test_skips_apex_and_unrelated_hosts(self):
        data = [
            {
                "name_value": "edostavka.by\nexample.com\nmail.example.com",
                "common_name": "edostavka.by",
            }
        ]
        subs, _emails = parse_crtsh_records(data, "edostavka.by")
        self.assertEqual(subs, [])

    def test_extracts_certificate_emails(self):
        data = [{"name_value": "admin@edostavka.by\nwww.edostavka.by"}]
        subs, emails = parse_crtsh_records(data, "edostavka.by")
        self.assertEqual(subs, ["www.edostavka.by"])
        self.assertEqual(emails, ["admin@edostavka.by"])


if __name__ == "__main__":
    unittest.main()
