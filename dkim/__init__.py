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
import re
import time

import dns.resolver

from dkim.crypto import (
    DigestTooLargeError,
    parse_private_key,
    parse_public_key,
    RSASSA_PKCS1_v1_5_sign,
    RSASSA_PKCS1_v1_5_verify,
    UnparsableKeyError,
    )
from dkim.util import (
    InvalidTagValueList,
    parse_tag_value,
    )

__all__ = [
    "Simple",
    "Relaxed",
    "InternalError",
    "KeyFormatError",
    "MessageFormatError",
    "ParameterError",
    "sign",
    "verify",
]

class Simple:
    """Class that represents the "simple" canonicalization algorithm."""

    name = "simple"

    @staticmethod
    def canonicalize_headers(headers):
        # No changes to headers.
        return headers

    @staticmethod
    def canonicalize_body(body):
        # Ignore all empty lines at the end of the message body.
        return re.sub("(\r\n)*$", "\r\n", body)

class Relaxed:
    """Class that represents the "relaxed" canonicalization algorithm."""

    name = "relaxed"

    @staticmethod
    def canonicalize_headers(headers):
        # Convert all header field names to lowercase.
        # Unfold all header lines.
        # Compress WSP to single space.
        # Remove all WSP at the start or end of the field value (strip).
        return [(x[0].lower(), re.sub(r"\s+", " ", re.sub("\r\n", "", x[1])).strip()+"\r\n") for x in headers]

    @staticmethod
    def canonicalize_body(body):
        # Remove all trailing WSP at end of lines.
        # Compress non-line-ending WSP to single space.
        # Ignore all empty lines at the end of the message body.
        return re.sub("(\r\n)*$", "\r\n", re.sub(r"[\x09\x20]+", " ", re.sub("[\\x09\\x20]+\r\n", "\r\n", body)))

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

def _remove(s, t):
    i = s.find(t)
    assert i >= 0
    return s[:i] + s[i+len(t):]

def hash_headers(hasher, canonicalize_headers, headers, include_headers,
                 sigheaders, sig):
    """Sign message header fields."""
    sign_headers = []
    lastindex = {}
    for h in include_headers:
        i = lastindex.get(h, len(headers))
        while i > 0:
            i -= 1
            if h.lower() == headers[i][0].lower():
                sign_headers.append(headers[i])
                break
        lastindex[h] = i
    # The call to _remove() assumes that the signature b= only appears
    # once in the signature header
    cheaders = canonicalize_headers.canonicalize_headers(
        [(sigheaders[0][0], _remove(sigheaders[0][1], sig['b']))])
    sign_headers += [(x[0], x[1].rstrip()) for x in cheaders]
    for x in sign_headers:
        hasher.update(x[0])
        hasher.update(":")
        hasher.update(x[1])


def validate_signature_fields(sig, debuglog=None):
    """Validate DKIM-Signature fields.

    Basic checks for presence and correct formatting of mandatory fields.

    @param sig: A dict mapping field keys to values.
    @param debuglog: A file-like object to which details will be written
        on error.
    """
    mandatory_fields = ('v', 'a', 'b', 'bh', 'd', 'h', 's')
    for field in mandatory_fields:
        if field not in sig:
            if debuglog is not None:
                print >>debuglog, "signature missing %s=" % field
            return False

    if sig['v'] != "1":
        if debuglog is not None:
            print >>debuglog, "v= value is not 1 (%s)" % sig['v']
        return False
    if re.match(r"[\s0-9A-Za-z+/]+=*$", sig['b']) is None:
        if debuglog is not None:
            print >>debuglog, "b= value is not valid base64 (%s)" % sig['b']
        return False
    if re.match(r"[\s0-9A-Za-z+/]+=*$", sig['bh']) is None:
        if debuglog is not None:
            print >>debuglog, "bh= value is not valid base64 (%s)" % sig['bh']
        return False
    if 'i' in sig and (not sig['i'].endswith(sig['d']) or sig['i'][-len(sig['d'])-1] not in "@."):
        if debuglog is not None:
            print >>debuglog, "i= domain is not a subdomain of d= (i=%s d=%d)" % (sig['i'], sig['d'])
        return False
    if 'l' in sig and re.match(r"\d{,76}$", sig['l']) is None:
        if debuglog is not None:
            print >>debuglog, "l= value is not a decimal integer (%s)" % sig['l']
        return False
    if 'q' in sig and sig['q'] != "dns/txt":
        if debuglog is not None:
            print >>debuglog, "q= value is not dns/txt (%s)" % sig['q']
        return False
    if 't' in sig and re.match(r"\d+$", sig['t']) is None:
        if debuglog is not None:
            print >>debuglog, "t= value is not a decimal integer (%s)" % sig['t']
        return False
    if 'x' in sig:
        if re.match(r"\d+$", sig['x']) is None:
            if debuglog is not None:
                print >>debuglog, "x= value is not a decimal integer (%s)" % sig['x']
            return False
        if int(sig['x']) < int(sig['t']):
            if debuglog is not None:
                print >>debuglog, "x= value is less than t= value (x=%s t=%s)" % (sig['x'], sig['t'])
            return False
    return True

# These values come from RFC 3447, section 9.2 Notes, page 43.
HASHID_SHA1 = "\x2b\x0e\x03\x02\x1a"
HASHID_SHA256 = "\x60\x86\x48\x01\x65\x03\x04\x02\x01"

def rfc822_parse(message):
    """Parse a message in RFC822 format.

    @param message: The message in RFC822 format. Either CRLF or LF is an accepted line separator.

    @return Returns a tuple of (headers, body) where headers is a list of (name, value) pairs.
    The body is a CRLF-separated string.

    """

    headers = []
    lines = re.split("\r?\n", message)
    i = 0
    while i < len(lines):
        if len(lines[i]) == 0:
            # End of headers, return what we have plus the body, excluding the blank line.
            i += 1
            break
        if re.match(r"[\x09\x20]", lines[i][0]):
            headers[-1][1] += lines[i]+"\r\n"
        else:
            m = re.match(r"([\x21-\x7e]+?):", lines[i])
            if m is not None:
                headers.append([m.group(1), lines[i][m.end(0):]+"\r\n"])
            elif lines[i].startswith("From "):
                pass
            else:
                raise MessageFormatError("Unexpected characters in RFC822 header: %s" % lines[i])
        i += 1
    return (headers, "\r\n".join(lines[i:]))

def dnstxt(name):
    """Return a TXT record associated with a DNS name."""
    a = dns.resolver.query(name, dns.rdatatype.TXT)
    for r in a.response.answer:
        if r.rdtype == dns.rdatatype.TXT:
            return "".join(r.items[0].strings)
    return None

def fold(header):
    """Fold a header line into multiple crlf-separated lines at column 72."""
    i = header.rfind("\r\n ")
    if i == -1:
        pre = ""
    else:
        i += 3
        pre = header[:i]
        header = header[i:]
    while len(header) > 72:
        i = header[:72].rfind(" ")
        if i == -1:
            j = i
        else:
            j = i + 1
        pre += header[:i] + "\r\n "
        header = header[j:]
    return pre + header

def sign(message, selector, domain, privkey, identity=None, canonicalize=(Simple, Simple), include_headers=None, length=False, debuglog=None):
    """Sign an RFC822 message and return the DKIM-Signature header line.

    @param message: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param selector: the DKIM selector value for the signature
    @param domain: the DKIM domain value for the signature
    @param privkey: a PKCS#1 private key in base64-encoded text form
    @param identity: the DKIM identity value for the signature (default "@"+domain)
    @param canonicalize: the canonicalization algorithms to use (default (Simple, Simple))
    @param include_headers: a list of strings indicating which headers are to be signed (default all headers)
    @param length: true if the l= tag should be included to indicate body length (default False)
    @param debuglog: a file-like object to which debug info will be written (default None)

    """

    (headers, body) = rfc822_parse(message)

    m = re.search("--\n(.*?)\n--", privkey, re.DOTALL)
    if m is None:
        raise KeyFormatError("Private key not found")
    try:
        pkdata = base64.b64decode(m.group(1))
    except TypeError, e:
        raise KeyFormatError(str(e))
    if debuglog is not None:
        print >>debuglog, " ".join("%02x" % ord(x) for x in pkdata)
    try:
        pk = parse_private_key(pkdata)
    except UnparsableKeyError, e:
        raise KeyFormatError(str(e))

    if identity is not None and not identity.endswith(domain):
        raise ParameterError("identity must end with domain")

    headers = canonicalize[0].canonicalize_headers(headers)

    if include_headers is None:
        include_headers = [x[0].lower() for x in headers]
    else:
        include_headers = [x.lower() for x in include_headers]
    sign_headers = [x for x in headers if x[0].lower() in include_headers]

    body = canonicalize[1].canonicalize_body(body)

    h = hashlib.sha256()
    h.update(body)
    bodyhash = base64.b64encode(h.digest())

    sigfields = [x for x in [
        ('v', "1"),
        ('a', "rsa-sha256"),
        ('c', "%s/%s" % (canonicalize[0].name, canonicalize[1].name)),
        ('d', domain),
        ('i', identity or "@"+domain),
        length and ('l', len(body)),
        ('q', "dns/txt"),
        ('s', selector),
        ('t', str(int(time.time()))),
        ('h', " : ".join(x[0] for x in sign_headers)),
        ('bh', bodyhash),
        ('b', ""),
    ] if x]

    sig_value = fold("; ".join("%s=%s" % x for x in sigfields))
    dkim_header = canonicalize[0].canonicalize_headers([
        ['DKIM-Signature', ' ' + sig_value]])[0]
    # the dkim sig is hashed with no trailing crlf, even if the
    # canonicalization algorithm would add one.
    if dkim_header[1][-2:] == '\r\n':
        dkim_header = (dkim_header[0], dkim_header[1][:-2])
    sign_headers.append(dkim_header)

    if debuglog is not None:
        print >>debuglog, "sign headers:", sign_headers
    h = hashlib.sha256()
    for x in sign_headers:
        h.update(x[0])
        h.update(":")
        h.update(x[1])
    d = h.digest()
    if debuglog is not None:
        print >>debuglog, "sign digest:", " ".join("%02x" % ord(x) for x in d)

    try:
        sig2 = RSASSA_PKCS1_v1_5_sign(
            d, HASHID_SHA256, pk['privateExponent'], pk['modulus'])
    except DigestTooLargeError:
        raise ParameterError("digest too large for modulus")
    sig_value += base64.b64encode(sig2)

    return 'DKIM-Signature: ' + sig_value + "\r\n"

def verify(message, debuglog=None, dnsfunc=dnstxt):
    """Verify a DKIM signature on an RFC822 formatted message.

    @param message: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param debuglog: a file-like object to which debug info will be written (default None)

    """

    (headers, body) = rfc822_parse(message)

    sigheaders = [x for x in headers if x[0].lower() == "dkim-signature"]
    if len(sigheaders) < 1:
        return False

    # Currently, we only validate the first DKIM-Signature line found.
    try:
        sig = parse_tag_value(sigheaders[0][1])
    except InvalidTagValueList:
        return False
    if debuglog is not None:
        print >>debuglog, "sig:", sig

    if not validate_signature_fields(sig, debuglog):
        return False

    m = re.match("(\w+)(?:/(\w+))?$", sig['c'])
    if m is None:
        if debuglog is not None:
            print >>debuglog, "c= value is not in format method/method (%s)" % sig['c']
        return False
    can_headers = m.group(1)
    if m.group(2) is not None:
        can_body = m.group(2)
    else:
        can_body = "simple"

    if can_headers == "simple":
        canonicalize_headers = Simple
    elif can_headers == "relaxed":
        canonicalize_headers = Relaxed
    else:
        if debuglog is not None:
            print >>debuglog, "Unknown header canonicalization (%s)" % can_headers
        return False

    headers = canonicalize_headers.canonicalize_headers(headers)

    if can_body == "simple":
        body = Simple.canonicalize_body(body)
    elif can_body == "relaxed":
        body = Relaxed.canonicalize_body(body)
    else:
        if debuglog is not None:
            print >>debuglog, "Unknown body canonicalization (%s)" % can_body
        return False

    if sig['a'] == "rsa-sha1":
        hasher = hashlib.sha1
        hashid = HASHID_SHA1
    elif sig['a'] == "rsa-sha256":
        hasher = hashlib.sha256
        hashid = HASHID_SHA256
    else:
        if debuglog is not None:
            print >>debuglog, "Unknown signature algorithm (%s)" % sig['a']
        return False

    if 'l' in sig:
        body = body[:int(sig['l'])]

    h = hasher()
    h.update(body)
    bodyhash = h.digest()
    if debuglog is not None:
        print >>debuglog, "bh:", base64.b64encode(bodyhash)
    if bodyhash != base64.b64decode(re.sub(r"\s+", "", sig['bh'])):
        if debuglog is not None:
            print >>debuglog, "body hash mismatch (got %s, expected %s)" % (base64.b64encode(bodyhash), sig['bh'])
        return False

    s = dnsfunc(sig['s']+"._domainkey."+sig['d']+".")
    if not s:
        return False
    try:
        pub = parse_tag_value(s)
    except InvalidTagValueList:
        return False
    try:
        pk = parse_public_key(base64.b64decode(pub['p']))
    except UnparsableKeyError, e:
        if debuglog is not None:
            print >>debuglog, "could not parse public key: %s" % e
        return False

    include_headers = re.split(r"\s*:\s*", sig['h'])
    h = hasher()
    hash_headers(
        h, canonicalize_headers, headers, include_headers, sigheaders, sig)
    d = h.digest()
    if debuglog is not None:
        print >>debuglog, "verify digest:", " ".join("%02x" % ord(x) for x in d)
    signature = base64.b64decode(re.sub(r"\s+", "", sig['b']))
    try:
        return RSASSA_PKCS1_v1_5_verify(
            d, hashid, signature, pk['publicExponent'], pk['modulus'])
    except DigestTooLargeError:
        if debuglog is not None:
            print >>debuglog, "digest too large for modulus"
        return False
