import os.path
import unittest

import dkim
from dkim.util import (
    InvalidTagValueList,
    parse_tag_value,
    )


def read_test_data(filename):
    """Get the content of the given test data file.

    The files live in dkim/tests/data.
    """
    path = os.path.join(os.path.dirname(__file__), 'data', filename)
    return open(path).read()


class TestFold(unittest.TestCase):

    def test_short_line(self):
        self.assertEqual(
            "foo", dkim.fold("foo"))

    def DISABLED_test_long_line(self):
        # The function is terribly broken, not passing even this simple
        # test.
        self.assertEqual(
            "foo"*24 + "\r\n foo", dkim.fold("foo" * 25))


class TestSignAndVerify(unittest.TestCase):
    """End-to-end signature and verification tests."""

    def setUp(self):
        self.message = read_test_data("test.message")
        self.key = read_test_data("test.private")

    def dnsfunc(self, domain):
        self.assertEqual('test._domainkey.example.com.', domain)
        return read_test_data("test.txt")

    def test_verifies(self):
        # A message verifies after being signed.
        sig = dkim.sign(self.message, "test", "example.com", self.key)
        res = dkim.verify(sig + self.message, dnsfunc=self.dnsfunc)
        self.assertTrue(res)

    def test_altered_body_fails(self):
        # An altered body fails verification.
        sig = dkim.sign(self.message, "test", "example.com", self.key)
        res = dkim.verify(sig + self.message + "foo", dnsfunc=self.dnsfunc)
        self.assertFalse(res)


class TestParseTagValue(unittest.TestCase):
    """Tag=Value parsing tests."""

    def test_single(self):
        self.assertEqual(
            {'foo': 'bar'},
            parse_tag_value('foo=bar'))

    def test_trailing_separator_ignored(self):
        self.assertEqual(
            {'foo': 'bar'},
            parse_tag_value('foo=bar;'))

    def test_multiple(self):
        self.assertEqual(
            {'foo': 'bar', 'baz': 'foo'},
            parse_tag_value('foo=bar;baz=foo'))

    def test_value_with_equals(self):
        self.assertEqual(
            {'foo': 'bar', 'baz': 'foo=bar'},
            parse_tag_value('foo=bar;baz=foo=bar'))

    def test_missing_value_is_an_error(self):
        self.assertRaises(
            InvalidTagValueList,
            parse_tag_value, 'foo=bar;baz')

    def test_duplicate_tag_is_an_error(self):
        self.assertRaises(
            InvalidTagValueList,
            parse_tag_value, 'foo=bar;foo=baz')


if __name__ == '__main__':
    unittest.main()
