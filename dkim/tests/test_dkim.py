import unittest

import dkim


class TestFold(unittest.TestCase):

    def test_short_line(self):
        self.assertEqual(
            "foo", dkim.fold("foo"))

    def DISABLED_test_long_line(self):
        # The function is terribly broken, not passing even this simple
        # test.
        self.assertEqual(
            "foo"*24 + "\r\n foo", dkim.fold("foo" * 25))


if __name__ == '__main__':
    unittest.main()
