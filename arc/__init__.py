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
#
# This has been modified from the original software.
# Copyright (c) 2016 Google, Inc.
# Contact: Brandon Long <blong@google.com>

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
from dkim import (
    bitsize,
    select_headers,
    RE_BTAG,
    hash_headers,
    rfc822_parse,
    text,
    fold,
    DKIM,
    )

__all__ = [
    "CV_Pass",
    "CV_Fail",
    "CV_None",
    "ARCException",
    "KeyFormatError",
    "MessageFormatError",
    "ParameterError",
    "ValidationError",
    "ARC",
    "sign",
    "verify",
]

CV_Pass = b'pass'
CV_Fail = b'fail'
CV_None = b'none'

class ARCException(Exception):
    """Base class for ARC errors."""
    pass

class KeyFormatError(ARCException):
    """Key format error while parsing an RSA public or private key."""
    pass

class MessageFormatError(ARCException):
    """RFC822 message format error."""
    pass

class ParameterError(ARCException):
    """Input parameter error."""
    pass

class ValidationError(ARCException):
    """Validation error."""
    pass

class HashThrough(object):
  def __init__(self, hasher):
    self.data = []
    self.hasher = hasher
    self.name = hasher.name

  def update(self, data):
    self.data.append(data)
    return self.hasher.update(data)

  def digest(self):
    return self.hasher.digest()

  def hexdigest(self):
    return self.hasher.hexdigest()

  def hashed(self):
    return ''.join(self.data)

def validate_arc_signature_fields(sig):
    """Validate ARC-Message-Signature fields.

    Basic checks for presence and correct formatting of mandatory fields.
    Raises a ValidationError if checks fail, otherwise returns None.

    @param sig: A dict mapping field keys to values.
    """
    mandatory_fields = (b'i', b'a', b'b', b'bh', b'd', b'h', b's')
    for field in mandatory_fields:
        if field not in sig:
            raise ValidationError("arc-message-signature missing %s=" % field)

    if re.match(br"[\s0-9A-Za-z+/]+=*$", sig[b'b']) is None:
        raise ValidationError("b= value is not valid base64 (%s)" % sig[b'b'])
    if re.match(br"[\s0-9A-Za-z+/]+=*$", sig[b'bh']) is None:
        raise ValidationError(
            "bh= value is not valid base64 (%s)" % sig[b'bh'])
    now = int(time.time())
    slop = 36000 # 10H leeway for mailers with inaccurate clocks
    t_sign = 0
    if b't' in sig:
        if re.match(br"\d+$", sig[b't']) is None:
            raise ValidationError(
                "t= value is not a decimal integer (%s)" % sig[b't'])
        t_sign = int(sig[b't'])
        if t_sign > now + slop:
            raise ValidationError("t= value is in the future (%s)" % sig[b't'])

def validate_arc_seal_fields(sig):
    """Validate ARC-Seal fields.

    Basic checks for presence and correct formatting of mandatory fields.
    Raises a ValidationError if checks fail, otherwise returns None.

    @param sig: A dict mapping field keys to values.
    """
    mandatory_fields = (b'i', b'a', b'b', b'cv', b'd', b's', b't')
    for field in mandatory_fields:
        if field not in sig:
            raise ValidationError("arc-seal missing %s=" % field)

    if re.match(br"[\s0-9A-Za-z+/]+=*$", sig[b'b']) is None:
        raise ValidationError("b= value is not valid base64 (%s)" % sig[b'b'])
    if sig[b'cv'] not in (CV_Pass, CV_Fail, CV_None):
      raise ValidationError("cv= value is not valid (%s)" % sig[b'cv'])
    now = int(time.time())
    slop = 36000 # 10H leeway for mailers with inaccurate clocks
    t_sign = 0
    if b't' in sig:
        if re.match(br"\d+$", sig[b't']) is None:
            raise ValidationError(
                "t= value is not a decimal integer (%s)" % sig[b't'])
        t_sign = int(sig[b't'])
        if t_sign > now + slop:
            raise ValidationError("t= value is in the future (%s)" % sig[b't'])

#: Hold messages and options during ARC signing and verification.
class ARC(object):
  #: Header fields used by ARC
  ARC_HEADERS = (b'arc-seal', b'arc-message-signature', b'arc-authentication-results')

  #: Regex to extract i= value from ARC headers
  INSTANCE_RE = re.compile(r'[\s;]?i\s*=\s*(\d+)', re.MULTILINE | re.IGNORECASE)

  #: Create an ARC instance to sign and verify rfc5322 messages.
  #:
  #: @param message: an RFC822 formatted message to be signed or verified
  #: (with either \\n or \\r\\n line endings)
  #: @param logger: a logger to which debug info will be written (default None)
  #: @param signature_algorithm: the signing algorithm to use when signing
  #: @param minkey: the minimum key size to accept
  def __init__(self,message=None,logger=None,signature_algorithm=b'rsa-sha256',
        minkey=1024):
    self.set_message(message)
    if logger is None:
        logger = get_default_logger()
    self.logger = logger
    if signature_algorithm not in HASH_ALGORITHMS:
        raise ParameterError(
            "Unsupported signature algorithm: "+signature_algorithm)
    self.signature_algorithm = signature_algorithm
    #: Header fields which should be signed.  Default from RFC4871
    self.should_sign = set(DKIM.SHOULD)
    #: Header fields which should not be signed.  The default is from RFC4871.
    #: Attempting to sign these headers results in an exception.
    #: If it is necessary to sign one of these, it must be removed
    #: from this list first.
    self.should_not_sign = set(DKIM.SHOULD_NOT)
    #: Header fields to sign an extra time to prevent additions.
    self.frozen_sign = set(DKIM.FROZEN)
    #: Minimum public key size.  Shorter keys raise KeyFormatError. The
    #: default is 1024
    self.minkey = minkey

  def add_frozen(self,s):
    """ Add headers not in should_not_sign to frozen_sign.
    @param s: list of headers to add to frozen_sign

    >>> arc = ARC()
    >>> arc.add_frozen(DKIM.RFC5322_SINGLETON)
    >>> [text(x) for x in sorted(arc.frozen_sign)]
    ['cc', 'date', 'from', 'in-reply-to', 'message-id', 'references', 'reply-to', 'sender', 'subject', 'to']
    """
    self.frozen_sign.update(x.lower() for x in s
        if x.lower() not in self.should_not_sign)

  #: Load a new message to be signed or verified.
  #: @param message: an RFC822 formatted message to be signed or verified
  #: (with either \\n or \\r\\n line endings)
  def set_message(self,message):
    if message:
      self.headers, self.body = rfc822_parse(message)
    else:
      self.headers, self.body = [],''

    # ARC only supports relaxed/relaxed, so canonicalize now.
    canon_policy = CanonicalizationPolicy.from_c_value(b'relaxed/relaxed')
    self.headers = canon_policy.canonicalize_headers(self.headers)
    self.body = canon_policy.canonicalize_body(self.body)

  def default_sign_headers(self):
    """Return the default list of headers to sign: those in should_sign or
    frozen_sign, with those in frozen_sign signed an extra time to prevent
    additions."""
    hset = self.should_sign | self.frozen_sign
    include_headers = [ x for x,y in self.headers
        if x.lower() in hset ]
    return include_headers + [ x for x in include_headers
        if x.lower() in self.frozen_sign]

  def all_sign_headers(self):
    """Return header list of all existing headers not in should_not_sign.
    @since: 0.5"""
    return [x for x,y in self.headers if x.lower() not in self.should_not_sign]

  def sorted_arc_headers(self):
    headers = []
    for x,y in self.headers:
      if x.lower() in ARC.ARC_HEADERS:
        m = ARC.INSTANCE_RE.search(y)
        if m is not None:
          try:
            i = int(m.group(1))
            headers.append((i, (x, y)))
          except ValueError:
            self.logger.debug("invalid instance number %s: '%s: %s'" % (m.group(1), x, y))
        else:
          self.logger.debug("not instance number: '%s: %s'" % (x, y))

    if len(headers) == 0:
      return 0, []

    def arc_header_sort(a, b):
      if a[0] != b[0]:
        return cmp(a[0], b[0])

      if a[1][0].lower() != b[1][0].lower():
        return cmp(a[1][0].lower(), b[1][0].lower())

      return cmp(a[1][1].lower(), b[1][1].lower())

    headers.sort(arc_header_sort)
    headers.reverse()
    return headers[0][0], headers

  #: Sign an RFC822 message and return the list of ARC set header lines
  #:
  #: The include_headers option gives full control over which header fields
  #: are signed for the ARC-Message-Signature.  Note that signing a header
  #: field that doesn't exist prevents
  #: that field from being added without breaking the signature.  Repeated
  #: fields (such as Received) can be signed multiple times.  Instances
  #: of the field are signed from bottom to top.  Signing a header field more
  #: times than are currently present prevents additional instances
  #: from being added without breaking the signature.
  #:
  #: The default include_headers for this method differs from the backward
  #: compatible sign function, which signs all headers not
  #: in should_not_sign.  The default list for this method can be modified
  #: by tweaking should_sign and frozen_sign (or even should_not_sign).
  #: It is only necessary to pass an include_headers list when precise control
  #: is needed.
  #:
  #: @param selector: the DKIM selector value for the signature
  #: @param domain: the DKIM domain value for the signature
  #: @param privkey: a PKCS#1 private key in base64-encoded text form
  #: @param auth_results: RFC 7601 Authentication-Results header value for the message
  #: @param chain_validation_status: CV_Pass, CV_Fail, CV_None
  #: @param include_headers: a list of strings indicating which headers
  #: are to be signed (default rfc4871 recommended headers)
  #: @return: list of ARC set header fields
  #: @raise ARCException: when the message, include_headers, or key are badly
  #: formed.
  def sign(self, selector, domain, privkey, auth_results, chain_validation_status,
        include_headers=None):
    try:
        pk = parse_pem_private_key(privkey)
    except UnparsableKeyError as e:
        raise KeyFormatError(str(e))

    max_instance, arc_headers_w_instance = self.sorted_arc_headers()
    instance = 1
    if len(arc_headers_w_instance) != 0:
        instance = max_instance + 1

    arc_headers = [y for x,y in arc_headers_w_instance]

    if instance == 1 and chain_validation_status != CV_None:
        raise ParameterError("No existing chain found on message, cv should be none")
    elif instance != 1 and chain_validation_status == CV_None:
      raise ParameterError("cv=none not allowed on instance %d" % instance)

    new_arc_set = []
    aar_value = b"i=%d; %s" % (instance, auth_results)
    if aar_value[-1] != b'\n': aar_value += '\r\n'
    new_arc_set.append(b"ARC-Authentication-Results: " + aar_value)
    self.headers.insert(0, (b"arc-authentication-results", aar_value))
    arc_headers.insert(0, (b"ARC-Authentication-Results", aar_value))

    # Compute ARC-Message-Signature

    canon_policy = CanonicalizationPolicy.from_c_value(b'relaxed/relaxed')
    headers = canon_policy.canonicalize_headers(self.headers)

    if include_headers is None:
        include_headers = self.default_sign_headers()

    # rfc4871 says FROM is required
    if b'from' not in ( x.lower() for x in include_headers ):
        raise ParameterError("The From header field MUST be signed")

    if b'arc-authentication-results' not in ( x.lower() for x in include_headers ):
        include_headers.append(b'arc-authentication-results')

    # raise exception for any SHOULD_NOT headers, call can modify
    # SHOULD_NOT if really needed.
    for x in include_headers:
        if x.lower() in self.should_not_sign:
            raise ParameterError("The %s header field SHOULD NOT be signed"%x)

    hasher = HASH_ALGORITHMS[self.signature_algorithm]
    h = HashThrough(hasher())
    h.update(self.body)
    bodyhash = base64.b64encode(h.digest())

    ams_fields = [x for x in [
        (b'i', str(instance).encode('ascii')),
        (b'a', self.signature_algorithm),
        (b'd', domain),
        (b's', selector),
        (b't', str(int(time.time())).encode('ascii')),
        (b'h', b" : ".join(include_headers)),
        (b'bh', bodyhash),
        # Force b= to fold onto it's own line so that refolding after
        # adding sig doesn't change whitespace for previous tags.
        (b'b', b'0'*60),
    ] if x]
    include_headers = [x.lower() for x in include_headers]
    # record what verify should extract
    self.include_headers = tuple(include_headers)

    ams_value = fold(b"; ".join(b"=".join(x) for x in ams_fields))
    ams_value = RE_BTAG.sub(b'\\1',ams_value)
    ams_header = (b'ARC-Message-Signature', b' ' + ams_value)
    h = HashThrough(hasher())
    sig = dict(ams_fields)
    self.signed_headers = hash_headers(
        h, canon_policy, headers, include_headers, ams_header,sig)
    self.logger.debug("ams sign headers: %r" % self.signed_headers)
    self.logger.debug("ams hashed: %r" % h.hashed())

    try:
        sig2 = RSASSA_PKCS1_v1_5_sign(h, pk)
    except DigestTooLargeError:
        raise ParameterError("digest too large for modulus")
    # Folding b= is explicity allowed, but yahoo and live.com are broken
    #ams_value += base64.b64encode(bytes(sig2))
    # Instead of leaving unfolded (which lets an MTA fold it later and still
    # breaks yahoo and live.com), we change the default signing mode to
    # relaxed/simple (for broken receivers), and fold now.
    ams_value = fold(ams_value + base64.b64encode(bytes(sig2))) + "\r\n"

    new_arc_set.append(b"ARC-Message-Signature: " + ams_value)
    self.headers.insert(0, (b"ARC-Message-Signature", ams_value))
    arc_headers.insert(0, (b"ARC-Message-Signature", ams_value))

    # Compute ARC-Seal

    as_fields = [x for x in [
        (b'i', str(instance).encode('ascii')),
        (b'cv', chain_validation_status),
        (b'a', self.signature_algorithm),
        (b'd', domain),
        (b's', selector),
        (b't', str(int(time.time())).encode('ascii')),
        # Force b= to fold onto it's own line so that refolding after
        # adding sig doesn't change whitespace for previous tags.
        (b'b', b'0'*60),
    ] if x]
    as_include_headers = [x[0].lower() for x in arc_headers]
    as_include_headers.reverse()
    as_headers = canon_policy.canonicalize_headers(arc_headers)

    as_value = fold(b"; ".join(b"=".join(x) for x in as_fields))
    as_value = RE_BTAG.sub(b'\\1',as_value)
    as_header = (b'ARC-Seal', b' ' + as_value)
    h = HashThrough(hasher())
    sig = dict(as_fields)
    as_signed_headers = hash_headers(
        h, canon_policy, as_headers, as_include_headers, as_header,sig)
    self.logger.debug("arc-seal sign headers: %r" % as_signed_headers)
    self.logger.debug("arc-seal hashed: %r" % h.hashed())

    try:
        sig2 = RSASSA_PKCS1_v1_5_sign(h, pk)
    except DigestTooLargeError:
        raise ParameterError("digest too large for modulus")
    # Folding b= is explicity allowed, but yahoo and live.com are broken
    #as_value += base64.b64encode(bytes(sig2))
    # Instead of leaving unfolded (which lets an MTA fold it later and still
    # breaks yahoo and live.com), we change the default signing mode to
    # relaxed/simple (for broken receivers), and fold now.
    as_value = fold(as_value + base64.b64encode(bytes(sig2))) + b"\r\n"

    new_arc_set.append(b"ARC-Seal: " + as_value)
    self.headers.insert(0, (b"ARC-Seal", as_value))
    arc_headers.insert(0, (b"ARC-Seal", as_value))

    new_arc_set.reverse()

    return new_arc_set

  #: Verify an ARC set.
  #: @type instance: int
  #: @param instance: which ARC set to verify, based on i= instance.
  #: @type dnsfunc: callable
  #: @param dnsfunc: an optional function to lookup TXT resource records
  #: for a DNS domain.  The default uses dnspython or pydns.
  #: @return: True if signature verifies or False otherwise
  #: @return: three-tuple of (CV Result (CV_Pass, CV_Fail or CV_None), list of
  #: result dictionaries, result reason)
  #: @raise ARCException: when the message, signature, or key are badly formed
  def verify(self,dnsfunc=get_txt):
    result_data = []
    max_instance, arc_headers_w_instance = self.sorted_arc_headers()
    if max_instance == 0:
        return CV_None, result_data, "Message is not ARC signed"
    for instance in range(max_instance, 0, -1):
        try:
            result = self.verify_instance(arc_headers_w_instance, instance, dnsfunc=dnsfunc)
            result_data.append(result)
        except ARCException as e:
            self.logger.error("%s" % e)
            return CV_Fail, result_data, "%s" % e

    # Most recent instance must ams-validate
    if not result_data[0]['ams-valid']:
        return CV_Fail, result_data, "Most recent ARC-Message-Signature did not validate"
    for result in result_data:
      if not result['as-valid']:
        return CV_Fail, result_data, "ARC-Seal[%d] did not validate" % result['instance']
      if result['cv'] == CV_Fail:
        return CV_Fail, result_data, "ARC-Seal[%d] reported failure" % result['instance']
      elif (result['instance'] == 1) and (result['cv'] != CV_None):
        return CV_Fail, result_data, "ARC-Seal[%d] reported invalid status %s" % (result['instance'], result['cv'])
      elif (result['instance'] != 1) and (result['cv'] == CV_None):
        return CV_Fail, result_data, "ARC-Seal[%d] reported invalid status %s" % (result['instance'], result['cv'])
    return CV_Pass, result_data, "success"

  def load_pk_from_dns(self, name, dnsfunc=get_txt):
    s = dnsfunc(name)
    if not s:
        raise KeyFormatError("missing public key: %s"%name)
    try:
        if type(s) is str:
          s = s.encode('ascii')
        pub = parse_tag_value(s)
    except InvalidTagValueList as e:
        raise KeyFormatError(e)
    try:
        pk = parse_public_key(base64.b64decode(pub[b'p']))
        keysize = bitsize(pk['modulus'])
    except KeyError:
        raise KeyFormatError("incomplete public key: %s" % s)
    except (TypeError,UnparsableKeyError) as e:
        raise KeyFormatError("could not parse public key (%s): %s" % (pub[b'p'],e))
    return pk, keysize

  #: Verify an ARC set.
  #: @type arc_headers_w_instance: list
  #: @param arc_headers_w_instance: list of tuples, (instance, (name, value)) of
  #: ARC headers
  #: @type instance: int
  #: @param instance: which ARC set to verify, based on i= instance.
  #: @type dnsfunc: callable
  #: @param dnsfunc: an optional function to lookup TXT resource records
  #: for a DNS domain.  The default uses dnspython or pydns.
  #: @return: True if signature verifies or False otherwise
  #: @raise ARCException: when the message, signature, or key are badly formed
  def verify_instance(self,arc_headers_w_instance,instance,dnsfunc=get_txt):
    if (instance == 0) or (len(arc_headers_w_instance) == 0):
        raise ParameterError("request to verify instance %d not present" % (instance))

    aar_value = None
    ams_value = None
    as_value = None
    arc_headers = []
    output = { 'instance': instance }

    for i, arc_header in arc_headers_w_instance:
      if i > instance: continue
      arc_headers.append(arc_header)
      if i == instance:
        if arc_header[0].lower() == b"arc-authentication-results":
          if aar_value is not None:
            raise MessageFormatError("Duplicate ARC-Authentication-Results for instance %d" % instance)
          aar_value = arc_header[1]
        elif arc_header[0].lower() == b"arc-message-signature":
          if ams_value is not None:
            raise MessageFormatError("Duplicate ARC-Message-Signature for instance %d" % instance)
          ams_value = arc_header[1]
        elif arc_header[0].lower() == b"arc-seal":
          if as_value is not None:
            raise MessageFormatError("Duplicate ARC-Seal for instance %d" % instance)
          as_value = arc_header[1]

    if (aar_value is None) or (ams_value is None) or (as_value is None):
        raise MessageFormatError("Incomplete ARC set for instance %d" % instance)

    output['aar-value'] = aar_value

    # Validate Arc-Message-Signature
    try:
        sig = parse_tag_value(ams_value)
    except InvalidTagValueList as e:
        raise MessageFormatError(e)

    logger = self.logger
    logger.debug("ams sig[%d]: %r" % (instance, sig))

    validate_arc_signature_fields(sig)
    output['ams-domain'] = sig[b'd']
    output['ams-selector'] = sig[b's']

    # TODO(blong): only hash the body once per algorithm
    try:
        hasher = HASH_ALGORITHMS[sig[b'a']]
    except KeyError as e:
        raise MessageFormatError("unknown signature algorithm: %s" % e.args[0])

    h = hasher()
    h.update(self.body)
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
    pk, keysize = self.load_pk_from_dns(name, dnsfunc)
    output['ams-keysize'] = keysize
    include_headers = [x.lower() for x in re.split(br"\s*:\s*", sig[b'h'])]
    # address bug#644046 by including any additional From header
    # fields when verifying.  Since there should be only one From header,
    # this shouldn't break any legitimate messages.  This could be
    # generalized to check for extras of other singleton headers.
    if b'from' in include_headers:
      include_headers.append(b'from')
    h = HashThrough(hasher())
    canon_policy = CanonicalizationPolicy.from_c_value(b'relaxed/relaxed')
    ams_header = (b'ARC-Message-Signature', b' ' + ams_value)
    hash_headers(h, canon_policy, self.headers, include_headers, ams_header, sig)
    logger.debug("ams hashed: %r" % h.hashed())
    ams_valid = False
    try:
        signature = base64.b64decode(re.sub(br"\s+", b"", sig[b'b']))
        ams_valid = RSASSA_PKCS1_v1_5_verify(h, signature, pk)
        if ams_valid and keysize < self.minkey:
          raise KeyFormatError("public key too small: %d" % keysize)
    except (TypeError,DigestTooLargeError) as e:
        raise KeyFormatError("digest too large for modulus: %s"%e)
    output['ams-valid'] = ams_valid

    # Validate Arc-Seal
    try:
        sig = parse_tag_value(as_value)
    except InvalidTagValueList as e:
        raise MessageFormatError(e)

    logger.debug("as sig[%d]: %r" % (instance, sig))

    validate_arc_seal_fields(sig)
    output['as-domain'] = sig[b'd']
    output['as-selector'] = sig[b's']
    output['cv'] = sig[b'cv']

    try:
        hasher = HASH_ALGORITHMS[sig[b'a']]
    except KeyError as e:
        raise MessageFormatError("unknown signature algorithm: %s" % e.args[0])

    name = sig[b's'] + b"._domainkey." + sig[b'd'] + b"."
    pk, keysize = self.load_pk_from_dns(name, dnsfunc)
    output['as-keysize'] = keysize
    as_include_headers = [x[0].lower() for x in arc_headers]
    as_include_headers.reverse()
    as_header = (b'ARC-Seal', b' ' + as_value)
    h = HashThrough(hasher())
    signed_headers = hash_headers(
        h, canon_policy, arc_headers, as_include_headers[:-1], as_header, sig)
    logger.debug("as hashed: %r" % h.hashed())
    as_valid = False
    try:
        signature = base64.b64decode(re.sub(br"\s+", b"", sig[b'b']))
        as_valid = RSASSA_PKCS1_v1_5_verify(h, signature, pk)
        if as_valid and keysize < self.minkey:
          raise KeyFormatError("public key too small: %d" % keysize)
    except (TypeError,DigestTooLargeError) as e:
        raise KeyFormatError("digest too large for modulus: %s"%e)
    output['as-valid'] = as_valid
    return output

def sign(message, selector, domain, privkey,
         auth_results, chain_validation_status,
         signature_algorithm=b'rsa-sha256',
         include_headers=None, logger=None):
    """Sign an RFC822 message and return the ARC set header lines for the next instance
    @param message: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param selector: the DKIM selector value for the signature
    @param domain: the DKIM domain value for the signature
    @param privkey: a PKCS#1 private key in base64-encoded text form
    @param auth_results: the RFC 7601 authentication-results header field value for this instance
    @param chain_validation_status: the validation status of the existing chain on the message (P (pass), F (fail)) or N (none) for no existing chain
    @param signature_algorithm: the signing algorithm to use when signing
    @param include_headers: a list of strings indicating which headers are to be signed (default all headers not listed as SHOULD NOT sign)
    @param logger: a logger to which debug info will be written (default None)
    @return: A list containing the ARC set of header fields for the next instance
    @raise ARCException: when the message, include_headers, or key are badly formed.
    """
    a = ARC(message,logger=logger,signature_algorithm=signature_algorithm)
    if not include_headers:
        include_headers = a.default_sign_headers()
    return a.sign(selector, domain, privkey, auth_results, chain_validation_status, include_headers=include_headers)

def verify(message, logger=None, dnsfunc=get_txt, minkey=1024):
    """Verify the ARC chain on an RFC822 formatted message.
    @param message: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param logger: a logger to which debug info will be written (default None)
    @param dnsfunc: an optional function to lookup TXT resource records
    @param minkey: the minimum key size to accept
    @return: three-tuple of (CV Result (CV_Pass, CV_Fail or CV_None), list of
    result dictionaries, result reason)
    """
    a = ARC(message,logger=logger,minkey=minkey)
    try:
        return a.verify(dnsfunc=dnsfunc)
    except ARCException as x:
        if logger is not None:
            logger.error("%s" % x)
        return CV_Fail, [], "%s" % x
