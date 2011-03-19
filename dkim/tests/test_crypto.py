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

import base64
import unittest

from dkim import (
    HASHID_SHA1,
    HASHID_SHA256,
    )
from dkim.crypto import (
    DigestTooLargeError,
    EMSA_PKCS1_v1_5_encode,
    int2str,
    parse_pem_private_key,
    parse_public_key,
    perform_rsa,
    RSASSA_PKCS1_v1_5_sign,
    RSASSA_PKCS1_v1_5_verify,
    str2int,
    )
from dkim.tests.test_dkim import read_test_data
from dkim.util import parse_tag_value


TEST_KEY_MODULUS = int(
    '160190232090260054474895273563294777865179886824815261110923286158270437'
    '657769966074370477716411064825849317279563494735400250019233722215662302'
    '997403060159149904218292658425241195497467863155064737257198115261596066'
    '733086923624062366294295557722551666415445482671442053150678674937682352'
    '837105556539434741981')
TEST_KEY_PUBLIC_EXPONENT = 65537
TEST_KEY_PRIVATE_EXPONENT = int(
    '219642251791061057038224045690185219631125389170665415924249912174530136'
    '074693824121380763959239792563755125360354847443780863736947713174228520'
    '489900956461640273471526152019568303807247290486052565153701534491987040'
    '131529720476525111651818771481293273124837542067061293644354088836358900'
    '29771161475005043329')


class TestStrIntConversion(unittest.TestCase):

    def test_str2int(self):
        self.assertEquals(1234, str2int('\x04\xd2'))

    def test_int2str(self):
        self.assertEquals('\x04\xd2', int2str(1234))

    def test_int2str_with_length(self):
        self.assertEquals('\x00\x00\x04\xd2', int2str(1234, 4))

    def test_int2str_fails_on_negative(self):
        self.assertRaises(AssertionError, int2str, -1)


class TestParseKeys(unittest.TestCase):

    def test_parse_pem_private_key(self):
        key = parse_pem_private_key(read_test_data('test.private'))
        self.assertEquals(key['modulus'], TEST_KEY_MODULUS)
        self.assertEquals(key['publicExponent'], TEST_KEY_PUBLIC_EXPONENT)
        self.assertEquals(key['privateExponent'], TEST_KEY_PRIVATE_EXPONENT)

    def test_parse_public_key(self):
        data = read_test_data('test.txt')
        key = parse_public_key(base64.b64decode(parse_tag_value(data)['p']))
        self.assertEquals(key['modulus'], TEST_KEY_MODULUS)
        self.assertEquals(key['publicExponent'], TEST_KEY_PUBLIC_EXPONENT)


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


class TestRSA(unittest.TestCase):

    message = '0004fb'.decode('hex')
    modulus = 186101
    modlen = 3
    public_exponent = 907
    private_exponent = 2851

    def test_perform(self):
        signed = perform_rsa(
            self.message, self.private_exponent, self.modulus, self.modlen)
        self.assertEquals('01f140'.decode('hex'), signed)

    def test_sign_and_verify(self):
        signed = perform_rsa(
            self.message, self.private_exponent, self.modulus, self.modlen)
        unsigned = perform_rsa(
            signed, self.public_exponent, self.modulus, self.modlen)
        self.assertEquals(self.message, unsigned)


class TestRSASSA(unittest.TestCase):

    def setUp(self):
        self.key = parse_pem_private_key(read_test_data('test.private'))

    test_digest = '0123456789abcdef0123'
    test_signature = (
        '3702809f62db933a5c3d18c2c76a3470658d2e79868fac98eaaca7e87d0cdc7'
        'fd091182673ed57c66531835d814ff367ffa3d764e74ca8ab301982d13eabb5'
        'dbe90e5c46ea223c5d3ee835aa74aaffe06e8018affeb78b5178818cb33656c'
        'ed462905bc0dc608e354f6ed3d4ec160ce9326ed227ccb0c1e5ba22098e10e6'
        'c083').decode('hex')

    def test_sign_and_verify(self):
        signature = RSASSA_PKCS1_v1_5_sign(
            self.test_digest, HASHID_SHA1, TEST_KEY_PRIVATE_EXPONENT,
            TEST_KEY_MODULUS)
        self.assertEquals(
            self.test_signature, signature)
        self.assertTrue(
            RSASSA_PKCS1_v1_5_verify(
                self.test_digest, HASHID_SHA1, signature,
                TEST_KEY_PUBLIC_EXPONENT, TEST_KEY_MODULUS))

    def test_invalid_signature(self):
        self.assertFalse(
            RSASSA_PKCS1_v1_5_verify(
                self.test_digest, HASHID_SHA1, self.test_signature,
                TEST_KEY_PUBLIC_EXPONENT, TEST_KEY_MODULUS + 1))


def test_suite():
    from unittest import TestLoader
    return TestLoader().loadTestsFromName(__name__)
