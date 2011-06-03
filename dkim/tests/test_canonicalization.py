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


class BaseCanonicalizationTest(unittest.TestCase):

    def assertCanonicalForm(self, expected, input):
        self.assertEqual(expected, self.func(expected))
        self.assertEqual(expected, self.func(input))


class TestSimpleAlgorithmHeaders(BaseCanonicalizationTest):

    func = staticmethod(Simple.canonicalize_headers)

    def test_untouched(self):
        test_headers = [(b'Foo  ', b'bar\r\n'), (b'Foo', b'baz\r\n')]
        self.assertCanonicalForm(
            test_headers,
            test_headers)


class TestSimpleAlgorithmBody(BaseCanonicalizationTest):

    func = staticmethod(Simple.canonicalize_body)

    def test_strips_trailing_empty_lines_from_body(self):
        self.assertCanonicalForm(
            b'Foo  \tbar    \r\n',
            b'Foo  \tbar    \r\n\r\n')


class TestRelaxedAlgorithmHeaders(BaseCanonicalizationTest):

    func = staticmethod(Relaxed.canonicalize_headers)

    def test_lowercases_names(self):
        self.assertCanonicalForm(
            [(b'foo', b'Bar\r\n'), (b'baz', b'Foo\r\n')],
            [(b'Foo', b'Bar\r\n'), (b'BaZ', b'Foo\r\n')])

    def test_unfolds_values(self):
        self.assertCanonicalForm(
            [(b'foo', b'Bar baz\r\n')],
            [(b'Foo', b'Bar\r\n baz\r\n')])

    def test_wsp_compresses_values(self):
        self.assertCanonicalForm(
            [(b'foo', b'Bar baz\r\n')],
            [(b'Foo', b'Bar \t baz\r\n')])

    def test_wsp_strips(self):
        self.assertCanonicalForm(
            [(b'foo', b'Bar baz\r\n')],
            [(b'Foo  ', b'   Bar \t baz   \r\n')])


class TestRelaxedAlgorithmBody(BaseCanonicalizationTest):

    func = staticmethod(Relaxed.canonicalize_body)

    def test_strips_trailing_wsp(self):
        self.assertCanonicalForm(
            b'Foo\r\nbar\r\n',
            b'Foo  \t\r\nbar\r\n')

    def test_wsp_compresses(self):
        self.assertCanonicalForm(
            b'Foo bar\r\n',
            b'Foo  \t  bar\r\n')

    def test_strips_trailing_empty_lines(self):
        self.assertCanonicalForm(
            b'Foo\r\nbar\r\n',
            b'Foo\r\nbar\r\n\r\n\r\n')


def test_suite():
    from unittest import TestLoader
    return TestLoader().loadTestsFromName(__name__)
