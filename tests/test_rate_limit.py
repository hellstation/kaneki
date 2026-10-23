import unittest

from kaneki.rate_limit import check_rate_limit, configure_redis


class RateLimitMemoryTest(unittest.TestCase):
    def setUp(self) -> None:
        configure_redis(None)

    def test_allows_first_call(self):
        self.assertIsNone(check_rate_limit(42, "phone"))

    def test_blocks_immediate_repeat(self):
        check_rate_limit(99, "phone")
        remaining = check_rate_limit(99, "phone")
        self.assertIsNotNone(remaining)
        self.assertGreater(remaining, 0)
