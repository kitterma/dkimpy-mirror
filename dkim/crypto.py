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
# Copyright (c) 2011 William Grant <me@williamgrant.id.au>

__all__ = [
    'parse_private_key',
    'parse_public_key',
    'RSASSA_PKCS1_v1_5_sign',
    'RSASSA_PKCS1_v1_5_verify',
    ]

from dkim.asn1 import (
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


def parse_public_key(data):
    x = asn1_parse(ASN1_Object, data)
    # Not sure why the [1:] is necessary to skip a byte.
    pkd = asn1_parse(ASN1_RSAPublicKey, x[0][1][1:])
    pk = {
        'modulus': pkd[0][0],
        'publicExponent': pkd[0][1],
    }
    return pk


def parse_private_key(data):
    pka = asn1_parse(ASN1_RSAPrivateKey, data)
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


def EMSA_PKCS1_v1_5_encode(digest, modlen, hashid):
    dinfo = asn1_build(
        (SEQUENCE, [
            (SEQUENCE, [
                (OBJECT_IDENTIFIER, hashid),
                (NULL, None),
            ]),
            (OCTET_STRING, digest),
        ]),
    )
    if len(dinfo)+3 > modlen:
        raise Exception("Hash too large for modulus") # XXX: DKIMException
    return "\x00\x01"+"\xff"*(modlen-len(dinfo)-3)+"\x00"+dinfo


def str2int(s):
    """Convert an octet string to an integer.

    Octet string assumed to represent a positive integer.
    """
    r = 0
    for c in s:
        r = (r << 8) | ord(c)
    return r


def int2str(n, length = -1):
    """Convert an integer to an octet string. Number must be positive.

    @param n: Number to convert.
    @param length: Minimum length, or -1 to return the smallest number of
        bytes that represent the integer.
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


def perform_rsa(input, exponent, modulus, modlen):
    return int2str(pow(str2int(input), exponent, modulus), modlen)


def RSASSA_PKCS1_v1_5_sign(digest, hashid, private_exponent, modulus):
    modlen = len(int2str(modulus))
    encoded_digest = EMSA_PKCS1_v1_5_encode(digest, modlen, hashid)
    return perform_rsa(encoded_digest, private_exponent, modulus, modlen)


def RSASSA_PKCS1_v1_5_verify(digest, hashid, signature, public_exponent,
                             modulus):
    modlen = len(int2str(modulus))
    encoded_digest = EMSA_PKCS1_v1_5_encode(digest, modlen, hashid)
    signed_digest = perform_rsa(signature, public_exponent, modulus, modlen)
    return encoded_digest == signed_digest
