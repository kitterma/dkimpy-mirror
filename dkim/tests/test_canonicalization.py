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

from dkim.canonicalization import Simple, Relaxed


class TestSimpleAlgorithm(unittest.TestCase):

    def test_headers_untouched(self):
        test_headers = [(b'Foo  ', b'bar\r\n'), (b'Foo', b'baz\r\n')]
        self.assertEqual(
            test_headers,
            Simple.canonicalize_headers(test_headers))

    def test_strips_trailing_empty_lines_from_body(self):
        self.assertEqual(
            b'Foo  \tbar    \r\n',
            Simple.canonicalize_body(
                b'Foo  \tbar    \r\n\r\n'))


class TestRelaxedAlgorithm(unittest.TestCase):

    def test_lowercases_headers(self):
        self.assertEqual(
            [(b'foo', b'Bar\r\n'), (b'baz', b'Foo\r\n')],
            Relaxed.canonicalize_headers(
                [(b'Foo', b'Bar\r\n'), (b'BaZ', b'Foo\r\n')]))

    def test_unfolds_headers(self):
        self.assertEqual(
            [(b'foo', b'Bar baz\r\n')],
            Relaxed.canonicalize_headers(
                [(b'Foo', b'Bar\r\n baz\r\n')]))

    def test_wsp_compresses_headers(self):
        self.assertEqual(
            [(b'foo', b'Bar baz\r\n')],
            Relaxed.canonicalize_headers(
                [(b'Foo', b'Bar \t baz\r\n')]))

    def test_wsp_strips_headers(self):
        self.assertEqual(
            [(b'foo', b'Bar baz\r\n')],
            Relaxed.canonicalize_headers(
                [(b'Foo  ', b'   Bar \t baz   \r\n')]))

    def test_strips_trailing_wsp_from_body(self):
        self.assertEqual(
            b'Foo\r\nbar\r\n',
            Relaxed.canonicalize_body(b'Foo  \t\r\nbar\r\n'))

    def test_wsp_compresses_body(self):
        self.assertEqual(
            b'Foo bar\r\n',
            Relaxed.canonicalize_body(b'Foo  \t  bar\r\n'))

    def test_strips_trailing_empty_lines_from_body(self):
        self.assertEqual(
            b'Foo\r\nbar\r\n',
            Relaxed.canonicalize_body(b'Foo\r\nbar\r\n\r\n\r\n'))


def test_suite():
    from unittest import TestLoader
    return TestLoader().loadTestsFromName(__name__)
