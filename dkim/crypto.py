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
# Copyright (c) 2008 Greg Hewgill http://hewgill.com
#
# This has been modified from the original software.
# Copyright (c) 2011 William Grant <me@williamgrant.id.au>

__all__ = [
    'DigestTooLargeError',
    'parse_private_key',
    'parse_public_key',
    'RSASSA_PKCS1_v1_5_sign',
    'RSASSA_PKCS1_v1_5_verify',
    'UnparsableKeyError',
    ]

from dkim.asn1 import (
    ASN1FormatError,
    asn1_build,
    asn1_parse,
    BIT_STRING,
    INTEGER,
    SEQUENCE,
    OBJECT_IDENTIFIER,
    OCTET_STRING,
    NULL,
    )


ASN1_Object = [
    (SEQUENCE, [
        (SEQUENCE, [
            (OBJECT_IDENTIFIER,),
            (NULL,),
        ]),
        (BIT_STRING,),
    ])
]

ASN1_RSAPublicKey = [
    (SEQUENCE, [
        (INTEGER,),
        (INTEGER,),
    ])
]

ASN1_RSAPrivateKey = [
    (SEQUENCE, [
        (INTEGER,),
        (INTEGER,),
        (INTEGER,),
        (INTEGER,),
        (INTEGER,),
        (INTEGER,),
        (INTEGER,),
        (INTEGER,),
        (INTEGER,),
    ])
]


class DigestTooLargeError(Exception):
    """The digest is too large to fit within the requested length."""
    pass


class UnparsableKeyError(Exception):
    """The data could not be parsed as a key."""
    pass


def parse_public_key(data):
    """Parse an RSA public key.

    @param data: DER-encoded X.509 subjectPublicKeyInfo
        containing an RFC3447 RSAPublicKey.
    @return: RSA public key
    """
    try:
        # Not sure why the [1:] is necessary to skip a byte.
        x = asn1_parse(ASN1_Object, data)
        pkd = asn1_parse(ASN1_RSAPublicKey, x[0][1][1:])
    except ASN1FormatError, e:
        raise UnparsableKeyError(str(e))
    pk = {
        'modulus': pkd[0][0],
        'publicExponent': pkd[0][1],
    }
    return pk


def parse_private_key(data):
    """Parse an RSA private key.

    @param data: DER-encoded RFC3447 RSAPrivateKey.
    @return: RSA private key
    """
    try:
        pka = asn1_parse(ASN1_RSAPrivateKey, data)
    except ASN1FormatError, e:
        raise UnparsableKeyError(str(e))
    pk = {
        'version': pka[0][0],
        'modulus': pka[0][1],
        'publicExponent': pka[0][2],
        'privateExponent': pka[0][3],
        'prime1': pka[0][4],
        'prime2': pka[0][5],
        'exponent1': pka[0][6],
        'exponent2': pka[0][7],
        'coefficient': pka[0][8],
    }
    return pk


def EMSA_PKCS1_v1_5_encode(digest, mlen, hashid):
    """Encode a digest with RFC3447 EMSA-PKCS1-v1_5.

    @param digest: digest byte string to encode
    @param mlen: desired message length
    @param hashid: ID of the hash used to generate the digest
    @return: encoded digest byte string
    """
    dinfo = asn1_build(
        (SEQUENCE, [
            (SEQUENCE, [
                (OBJECT_IDENTIFIER, hashid),
                (NULL, None),
            ]),
            (OCTET_STRING, digest),
        ]))
    if len(dinfo)+3 > mlen:
        raise DigestTooLargeError()
    return "\x00\x01"+"\xff"*(mlen-len(dinfo)-3)+"\x00"+dinfo


def str2int(s):
    """Convert a byte string to an integer.

    @param s: byte string representing a positive integer to convert
    @return: converted integer
    """
    r = 0
    for c in s:
        r = (r << 8) | ord(c)
    return r


def int2str(n, length=-1):
    """Convert an integer to a byte string.

    @param n: positive integer to convert
    @param length: minimum length
    @return: converted bytestring, of at least the minimum length if it was
        specified
    """
    assert n >= 0
    r = []
    while length < 0 or len(r) < length:
        r.append(chr(n & 0xff))
        n >>= 8
        if length < 0 and n == 0:
            break
    r.reverse()
    assert length < 0 or len(r) == length
    return ''.join(r)


def perform_rsa(message, exponent, modulus, mlen):
    """Perform RSA signing or verification.

    @param message: byte string to operate on
    @param exponent: public or private key exponent
    @param modulus: key modulus
    @param mlen: desired output length
    @return: byte string result of the operation
    """
    return int2str(pow(str2int(message), exponent, modulus), mlen)


def RSASSA_PKCS1_v1_5_sign(digest, hashid, private_exponent, modulus):
    """Sign a digest with RFC3447 RSASSA-PKCS1-v1_5.

    @param digest: digest byte string to sign
    @param hashid: ID of the hash used to generate the digest
    @param private_exponent: private key exponent
    @param modulus: key modulus
    @return: signed digest byte string
    """
    modlen = len(int2str(modulus))
    encoded_digest = EMSA_PKCS1_v1_5_encode(digest, modlen, hashid)
    return perform_rsa(encoded_digest, private_exponent, modulus, modlen)


def RSASSA_PKCS1_v1_5_verify(digest, hashid, signature, public_exponent,
                             modulus):
    """Verify a digest signed with RFC3447 RSASSA-PKCS1-v1_5.

    @param digest: digest byte string to check
    @param hashid: ID of the hash used to generate the digest
    @param signature: signed digest byte string
    @param public_exponent: public key exponent
    @param modulus: key modulus
    @return: True if the signature is valid, False otherwise
    """
    modlen = len(int2str(modulus))
    encoded_digest = EMSA_PKCS1_v1_5_encode(digest, modlen, hashid)
    signed_digest = perform_rsa(signature, public_exponent, modulus, modlen)
    return encoded_digest == signed_digest
