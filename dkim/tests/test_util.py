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

import unittest

from dkim.util import (
    DuplicateTag,
    InvalidTagSpec,
    parse_tag_value,
    )


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

    def test_whitespace_is_stripped(self):
        self.assertEqual(
            {'foo': 'bar', 'baz': 'f oo=bar'},
            parse_tag_value('   foo  \t= bar;\tbaz=  f oo=bar  '))

    def test_missing_value_is_an_error(self):
        self.assertRaisesRegexp(
            InvalidTagSpec, 'baz',
            parse_tag_value, 'foo=bar;baz')

    def test_duplicate_tag_is_an_error(self):
        self.assertRaisesRegexp(
            DuplicateTag, 'foo',
            parse_tag_value, 'foo=bar;foo=baz')


def test_suite():
    from unittest import TestLoader
    return TestLoader().loadTestsFromName(__name__)
