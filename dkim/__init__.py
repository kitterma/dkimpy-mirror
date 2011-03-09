import base64
import hashlib
import re
import time

import dns.resolver

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
        raise ParameterError("Hash too large for modulus")
    return "\x00\x01"+"\xff"*(modlen-len(dinfo)-3)+"\x00"+dinfo


def hash_headers(hasher, canonicalize_headers, headers, include_headers,
                 sigheaders, sig):
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


def validate_signature_fields(sig, debuglog=None):
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

# These values come from RFC 3447, section 9.2 Notes, page 43.
HASHID_SHA1 = "\x2b\x0e\x03\x02\x1a"
HASHID_SHA256 = "\x60\x86\x48\x01\x65\x03\x04\x02\x01"

def str2int(s):
    """Convert an octet string to an integer. Octet string assumed to represent a positive integer."""
    r = 0
    for c in s:
        r = (r << 8) | ord(c)
    return r

def int2str(n, length = -1):
    """Convert an integer to an octet string. Number must be positive.

    @param n: Number to convert.
    @param length: Minimum length, or -1 to return the smallest number of bytes that represent the integer.

    """

    assert n >= 0
    r = []
    while length < 0 or len(r) < length:
        r.append(chr(n & 0xff))
        n >>= 8
        if length < 0 and n == 0: break
    r.reverse()
    assert length < 0 or len(r) == length
    return r

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
    pk = parse_private_key(pkdata)
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
    sig = "DKIM-Signature: " + "; ".join("%s=%s" % x for x in sigfields)

    sig = fold(sig)

    if debuglog is not None:
        print >>debuglog, "sign headers:", sign_headers + [("DKIM-Signature", " "+"; ".join("%s=%s" % x for x in sigfields))]
    h = hashlib.sha256()
    for x in sign_headers:
        h.update(x[0])
        h.update(":")
        h.update(x[1])
    h.update(sig)
    d = h.digest()
    if debuglog is not None:
        print >>debuglog, "sign digest:", " ".join("%02x" % ord(x) for x in d)

    modlen = len(int2str(pk['modulus']))
    encoded = EMSA_PKCS1_v1_5_encode(d, modlen, HASHID_SHA256)
    sig2 = int2str(pow(str2int(encoded), pk['privateExponent'], pk['modulus']), modlen)
    sig += base64.b64encode(''.join(sig2))

    return sig + "\r\n"

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

    a = re.split(r"\s*;\s*", sigheaders[0][1].strip())
    if debuglog is not None:
        print >>debuglog, "a:", a
    sig = {}
    for x in a:
        if x:
            m = re.match(r"(\w+)\s*=\s*(.*)", x, re.DOTALL)
            if m is None:
                if debuglog is not None:
                    print >>debuglog, "invalid format of signature part: %s" % x
                return False
            sig[m.group(1)] = m.group(2)
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
    a = re.split(r"\s*;\s*", s)
    # Trailing ';' on signature record is valid, see RFC 4871 3.2
    #  tag-list  =  tag-spec 0*( ";" tag-spec ) [ ";" ]
    if a[-1] == '':
        a.pop(-1)
    pub = {}
    for f in a:
        m = re.match(r"(\w+)=(.*)", f)
        if m is not None:
            pub[m.group(1)] = m.group(2)
        else:
            if debuglog is not None:
                print >>debuglog, "invalid format in _domainkey txt record"
            return False
    pk = parse_public_key(base64.b64decode(pub['p']))
    modlen = len(int2str(pk['modulus']))
    if debuglog is not None:
        print >>debuglog, "modlen:", modlen

    include_headers = re.split(r"\s*:\s*", sig['h'])
    h = hasher()
    hash_headers(
        h, canonicalize_headers, headers, include_headers, sigheaders, sig)
    d = h.digest()
    if debuglog is not None:
        print >>debuglog, "verify digest:", " ".join("%02x" % ord(x) for x in d)
    try:
        sig2 = EMSA_PKCS1_v1_5_encode(d, modlen, hashid)
    except ParameterError:
        return False
    if debuglog is not None:
        print >>debuglog, "sig2:", " ".join("%02x" % ord(x) for x in sig2)
        print >>debuglog, sig['b']
        print >>debuglog, re.sub(r"\s+", "", sig['b'])
    v = int2str(pow(str2int(base64.b64decode(re.sub(r"\s+", "", sig['b']))), pk['publicExponent'], pk['modulus']), modlen)
    if debuglog is not None:
        print >>debuglog, "v:", " ".join("%02x" % ord(x) for x in v)
    assert len(v) == len(sig2)
    # Byte-by-byte compare of signatures
    return not [1 for x in zip(v, sig2) if x[0] != x[1]]
