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

from dkim import (
    HASHID_SHA1,
    HASHID_SHA256,
    )
from dkim.crypto import (
    DigestTooLargeError,
    EMSA_PKCS1_v1_5_encode,
    )


class TestEMSA_PKCS1_v1_5(unittest.TestCase):

    def test_encode_sha256(self):
        digest = '0123456789abcdef0123456789abcdef'
        self.assertEquals(
            '\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\x00'
            '010\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04 '
            + digest,
            EMSA_PKCS1_v1_5_encode(digest, 62, HASHID_SHA256))

    def test_encode_sha1(self):
        digest = '0123456789abcdef0123'
        self.assertEquals(
            '\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\x00'
            '0!0\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
            + digest,
            EMSA_PKCS1_v1_5_encode(digest, 46, HASHID_SHA1))

    def test_encode_forbids_too_short(self):
        # PKCS#1 requires at least 8 bytes of padding, so there must be
        # at least that much space.
        digest = '0123456789abcdef0123'
        self.assertRaises(
            DigestTooLargeError,
            EMSA_PKCS1_v1_5_encode, digest, 45, HASHID_SHA1)


def test_suite():
    from unittest import TestLoader
    return TestLoader().loadTestsFromName(__name__)
