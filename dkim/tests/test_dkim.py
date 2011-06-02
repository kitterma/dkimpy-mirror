# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the author be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
# 2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.
#
# Copyright (c) 2011 William Grant <me@williamgrant.id.au>

import os.path
import unittest

import dkim


def read_test_data(filename):
    """Get the content of the given test data file.

    The files live in dkim/tests/data.
    """
    path = os.path.join(os.path.dirname(__file__), 'data', filename)
    with open(path, 'rb') as f:
        return f.read()


class TestFold(unittest.TestCase):

    def test_short_line(self):
        self.assertEqual(
            b"foo", dkim.fold(b"foo"))

    def DISABLED_test_long_line(self):
        # The function is terribly broken, not passing even this simple
        # test.
        self.assertEqual(
            b"foo"*24 + b"\r\n foo", dkim.fold(b"foo" * 25))


class TestSignAndVerify(unittest.TestCase):
    """End-to-end signature and verification tests."""

    def setUp(self):
        self.message = read_test_data("test.message")
        self.key = read_test_data("test.private")

    def dnsfunc(self, domain):
        self.assertEqual('test._domainkey.example.com.', domain)
        return read_test_data("test.txt").decode('utf-8')

    def test_verifies(self):
        # A message verifies after being signed.
        sig = dkim.sign(self.message, b"test", b"example.com", self.key)
        res = dkim.verify(sig + self.message, dnsfunc=self.dnsfunc)
        self.assertTrue(res)

    def test_altered_body_fails(self):
        # An altered body fails verification.
        sig = dkim.sign(self.message, b"test", b"example.com", self.key)
        res = dkim.verify(sig + self.message + b"foo", dnsfunc=self.dnsfunc)
        self.assertFalse(res)


def test_suite():
    from unittest import TestLoader
    return TestLoader().loadTestsFromName(__name__)
