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

import base64
import hashlib
import logging
import re
import time

from dkim.canonicalization import (
    CanonicalizationPolicy,
    InvalidCanonicalizationPolicyError,
    )
from dkim.crypto import (
    DigestTooLargeError,
    HASH_ALGORITHMS,
    parse_pem_private_key,
    parse_public_key,
    RSASSA_PKCS1_v1_5_sign,
    RSASSA_PKCS1_v1_5_verify,
    UnparsableKeyError,
    )
from dkim.dnsplug import get_txt
from dkim.util import (
    get_default_logger,
    InvalidTagValueList,
    parse_tag_value,
    )

__all__ = [
    "DKIMException",
    "InternalError",
    "KeyFormatError",
    "MessageFormatError",
    "ParameterError",
    "Relaxed",
    "Simple",
    "DKIM",
    "sign",
    "verify",
]

Relaxed = b'relaxed'    # for clients passing dkim.Relaxed
Simple = b'simple'      # for clients passing dkim.Simple

class DKIMException(Exception):
    """Base class for DKIM errors."""
    pass

class InternalError(DKIMException):
    """Internal error in dkim module. Should never happen."""
    pass

class KeyFormatError(DKIMException):
    """Key format error while parsing an RSA public or private key."""
    pass

class MessageFormatError(DKIMException):
    """RFC822 message format error."""
    pass

class ParameterError(DKIMException):
    """Input parameter error."""
    pass

class ValidationError(DKIMException):
    """Validation error."""
    pass

def _remove(s, t):
    i = s.find(t)
    assert i >= 0
    return s[:i] + s[i+len(t):]

def select_headers(headers, include_headers):
    """Select message header fields to be signed/verified.
    >>> h = [('from','biz'),('foo','bar'),('from','baz'),('subject','boring')]
    >>> i = ['from','subject','from']
    >>> select_headers(h,i)
    [('from', 'baz'), ('subject', 'boring'), ('from', 'biz')]
    """
    sign_headers = []
    lastindex = {}
    for h in [x.lower() for x in include_headers]:
        i = lastindex.get(h, len(headers))
        while i > 0:
            i -= 1
            if h == headers[i][0].lower():
                sign_headers.append(headers[i])
                break
        lastindex[h] = i
    return sign_headers

def hash_headers(hasher, canonicalize_headers, headers, include_headers,
                 sigheaders, sig):
    """Sign message header fields."""
    sign_headers = select_headers(headers,include_headers)
    # The call to _remove() assumes that the signature b= only appears
    # once in the signature header
    cheaders = canonicalize_headers.canonicalize_headers(
        [(sigheaders[0][0], _remove(sigheaders[0][1], sig[b'b']))])
    sign_headers += [(x[0], x[1].rstrip()) for x in cheaders]
    for x in sign_headers:
        hasher.update(x[0])
        hasher.update(b":")
        hasher.update(x[1])

def validate_signature_fields(sig):
    """Validate DKIM-Signature fields.

    Basic checks for presence and correct formatting of mandatory fields.
    Raises a ValidationError if checks fail, otherwise returns None.

    @param sig: A dict mapping field keys to values.
    """
    mandatory_fields = (b'v', b'a', b'b', b'bh', b'd', b'h', b's')
    for field in mandatory_fields:
        if field not in sig:
            raise ValidationError("signature missing %s=" % field)

    if sig[b'v'] != b"1":
        raise ValidationError("v= value is not 1 (%s)" % sig[b'v'])
    if re.match(br"[\s0-9A-Za-z+/]+=*$", sig[b'b']) is None:
        raise ValidationError("b= value is not valid base64 (%s)" % sig[b'b'])
    if re.match(br"[\s0-9A-Za-z+/]+=*$", sig[b'bh']) is None:
        raise ValidationError(
            "bh= value is not valid base64 (%s)" % sig[b'bh'])
    # Nasty hack to support both str and bytes... check for both the
    # character and integer values.
    if b'i' in sig and (
        not sig[b'i'].endswith(sig[b'd']) or
        sig[b'i'][-len(sig[b'd'])-1] not in ('@', '.', 64, 46)):
        raise ValidationError(
            "i= domain is not a subdomain of d= (i=%s d=%d)" %
            (sig[b'i'], sig[b'd']))
    if b'l' in sig and re.match(br"\d{,76}$", sig['l']) is None:
        raise ValidationError(
            "l= value is not a decimal integer (%s)" % sig[b'l'])
    if b'q' in sig and sig[b'q'] != b"dns/txt":
        raise ValidationError("q= value is not dns/txt (%s)" % sig[b'q'])
    if b't' in sig and re.match(br"\d+$", sig[b't']) is None:
        raise ValidationError(
            "t= value is not a decimal integer (%s)" % sig[b't'])
    if b'x' in sig:
        if re.match(br"\d+$", sig[b'x']) is None:
            raise ValidationError(
                "x= value is not a decimal integer (%s)" % sig[b'x'])
        if int(sig[b'x']) < int(sig[b't']):
            raise ValidationError(
                "x= value is less than t= value (x=%s t=%s)" %
                (sig[b'x'], sig[b't']))


def rfc822_parse(message):
    """Parse a message in RFC822 format.

    @param message: The message in RFC822 format. Either CRLF or LF is an accepted line separator.

    @return Returns a tuple of (headers, body) where headers is a list of (name, value) pairs.
    The body is a CRLF-separated string.

    """
    headers = []
    lines = re.split(b"\r?\n", message)
    i = 0
    while i < len(lines):
        if len(lines[i]) == 0:
            # End of headers, return what we have plus the body, excluding the blank line.
            i += 1
            break
        if lines[i][0] in ("\x09", "\x20", 0x09, 0x20):
            headers[-1][1] += lines[i]+b"\r\n"
        else:
            m = re.match(br"([\x21-\x7e]+?):", lines[i])
            if m is not None:
                headers.append([m.group(1), lines[i][m.end(0):]+b"\r\n"])
            elif lines[i].startswith(b"From "):
                pass
            else:
                raise MessageFormatError("Unexpected characters in RFC822 header: %s" % lines[i])
        i += 1
    return (headers, b"\r\n".join(lines[i:]))



def fold(header):
    """Fold a header line into multiple crlf-separated lines at column 72.
    >>> fold(b'foo')
    'foo'
    >>> fold(b'foo  '+b'foo'*24).splitlines()[0]
    'foo  '
    >>> fold(b'foo'*25).splitlines()[-1]
    ' foo'
    >>> len(fold(b'foo'*25).splitlines()[0])
    72
    """
    i = header.rfind(b"\r\n ")
    if i == -1:
        pre = b""
    else:
        i += 3
        pre = header[:i]
        header = header[i:]
    while len(header) > 72:
        i = header[:72].rfind(b" ")
        if i == -1:
            j = 72
        else:
            j = i + 1
        pre += header[:j] + b"\r\n "
        header = header[j:]
    return pre + header

class DKIM(object):

  def __init__(self,message,logger=None,signature_algorithm=b'rsa-sha256'):
    (self.headers, self.body) = rfc822_parse(message)
    self.domain = None
    self.selector = 'default'
    if logger is None:
        logger = get_default_logger()
    self.logger = logger
    if signature_algorithm not in HASH_ALGORITHMS:
        raise ParameterError(
            "Unsupported signature algorithm: "+signature_algorithm)
    self.signature_algorithm = signature_algorithm

  def sign(self, selector, domain, privkey, identity=None,
        canonicalize=(b'simple',b'simple'), include_headers=None, length=False):
    try:
        pk = parse_pem_private_key(privkey)
    except UnparsableKeyError as e:
        raise KeyFormatError(str(e))

    if identity is not None and not identity.endswith(domain):
        raise ParameterError("identity must end with domain")

    canon_policy = CanonicalizationPolicy.from_c_value(
        b'/'.join(canonicalize))
    headers = canon_policy.canonicalize_headers(self.headers)

    if include_headers is None:
        include_headers = [x[0].lower() for x in headers]
    else:
        include_headers = [x.lower() for x in include_headers]
    sign_headers = [x for x in headers if x[0].lower() in include_headers]

    body = canon_policy.canonicalize_body(self.body)

    hasher = HASH_ALGORITHMS[self.signature_algorithm]
    h = hasher()
    h.update(body)
    bodyhash = base64.b64encode(h.digest())

    sigfields = [x for x in [
        (b'v', b"1"),
        (b'a', self.signature_algorithm),
        (b'c', canon_policy.to_c_value()),
        (b'd', domain),
        (b'i', identity or b"@"+domain),
        length and (b'l', len(body)),
        (b'q', b"dns/txt"),
        (b's', selector),
        (b't', str(int(time.time())).encode('ascii')),
        (b'h', b" : ".join(x[0] for x in sign_headers)),
        (b'bh', bodyhash),
        (b'b', b""),
    ] if x]

    sig_value = fold(b"; ".join(b"=".join(x) for x in sigfields))
    dkim_header = canon_policy.canonicalize_headers([
        [b'DKIM-Signature', b' ' + sig_value]])[0]
    # the dkim sig is hashed with no trailing crlf, even if the
    # canonicalization algorithm would add one.
    if dkim_header[1][-2:] == b'\r\n':
        dkim_header = (dkim_header[0], dkim_header[1][:-2])
    sign_headers.append(dkim_header)

    self.logger.debug("sign headers: %r" % sign_headers)
    h = hashlib.sha256()
    for x in sign_headers:
        h.update(x[0])
        h.update(b":")
        h.update(x[1])

    try:
        sig2 = RSASSA_PKCS1_v1_5_sign(
            h, pk['privateExponent'], pk['modulus'])
    except DigestTooLargeError:
        raise ParameterError("digest too large for modulus")
    sig_value += base64.b64encode(bytes(sig2))

    self.domain = domain
    self.selector = selector
    return b'DKIM-Signature: ' + sig_value + b"\r\n"


  def verify(self,dnsfunc=get_txt):

    sigheaders = [x for x in self.headers if x[0].lower() == b"dkim-signature"]
    if len(sigheaders) < 1:
        return False

    # Currently, we only validate the first DKIM-Signature line found.
    try:
        sig = parse_tag_value(sigheaders[0][1])
    except InvalidTagValueList as e:
        raise MessageFormatError(e)

    sig = parse_tag_value(sigheaders[0][1])
    logger = self.logger
    logger.debug("sig: %r" % sig)

    validate_signature_fields(sig)

    try:
        canon_policy = CanonicalizationPolicy.from_c_value(sig.get(b'c'))
    except InvalidCanonicalizationPolicyError as e:
        raise MessageFormatError("invalid c= value: %s" % e.args[0])
    headers = canon_policy.canonicalize_headers(self.headers)
    body = canon_policy.canonicalize_body(self.body)

    try:
        hasher = HASH_ALGORITHMS[sig[b'a']]
    except KeyError as e:
        raise MessageFormatError("unknown signature algorithm: %s" % e.args[0])

    self.domain = sig[b'd']
    self.selector = sig[b's']
    if b'l' in sig:
        body = body[:int(sig[b'l'])]

    h = hasher()
    h.update(body)
    bodyhash = h.digest()
    logger.debug("bh: %s" % base64.b64encode(bodyhash))
    try:
        bh = base64.b64decode(re.sub(br"\s+", b"", sig[b'bh']))
    except TypeError as e:
        raise MessageFormatError(str(e))
    if bodyhash != bh:
        raise ValidationError(
            "body hash mismatch (got %s, expected %s)" %
            (base64.b64encode(bodyhash), sig[b'bh']))

    name = sig[b's'] + b"._domainkey." + sig[b'd'] + b"."
    s = dnsfunc(name)
    if not s:
        raise KeyFormatError("missing public key: %s"%name)
    try:
        pub = parse_tag_value(s)
    except InvalidTagValueList:
        raise KeyFormatError(e)
    try:
        pk = parse_public_key(base64.b64decode(pub[b'p']))
    except (TypeError,UnparsableKeyError) as e:
        raise KeyFormatError("could not parse public key (%s): %s" % (pub[b'p'],e))

    include_headers = re.split(br"\s*:\s*", sig[b'h'])
    # address bug#644046 by including any additional From header
    # fields when verifying.  Since there should be only one From header,
    # this shouldn't break any legitimate messages.  This could be
    # generalized to check for extras of other singleton headers.
    if 'from' in [x.lower() for x in include_headers]:
      include_headers.append('from')      
    h = hasher()
    hash_headers(h, canon_policy, headers, include_headers, sigheaders, sig)
    try:
        signature = base64.b64decode(re.sub(br"\s+", b"", sig[b'b']))
        return RSASSA_PKCS1_v1_5_verify(
            h, signature, pk['publicExponent'], pk['modulus'])
    except (TypeError,DigestTooLargeError) as e:
        raise KeyFormatError("digest too large for modulus: %s"%e)

def sign(message, selector, domain, privkey, identity=None,
         canonicalize=(b'simple', b'simple'),
         signature_algorithm=b'rsa-sha256',
         include_headers=None, length=False, logger=None):
    """Sign an RFC822 message and return the DKIM-Signature header line.

    @param message: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param selector: the DKIM selector value for the signature
    @param domain: the DKIM domain value for the signature
    @param privkey: a PKCS#1 private key in base64-encoded text form
    @param identity: the DKIM identity value for the signature (default "@"+domain)
    @param canonicalize: the canonicalization algorithms to use (default (Simple, Simple))
    @param include_headers: a list of strings indicating which headers are to be signed (default all headers)
    @param length: true if the l= tag should be included to indicate body length (default False)
    @param logger: a logger to which debug info will be written (default None)
    """

    d = DKIM(message,logger=logger)
    return d.sign(selector, domain, privkey, identity=identity, canonicalize=canonicalize, include_headers=include_headers, length=length)

def verify(message, logger=None, dnsfunc=get_txt):
    """Verify a DKIM signature on an RFC822 formatted message.

    @param message: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param logger: a logger to which debug info will be written (default None)

    """
    d = DKIM(message,logger=logger)
    try:
        return d.verify(dnsfunc=dnsfunc)
    except DKIMException as x:
        if logger is not None:
            logger.error("%s" % e)
        return False
