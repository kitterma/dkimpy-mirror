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
#
# This has been modified from the original software.
# Copyright (c) 2016, 2017, 2018, 2019 Scott Kitterman <scott@kitterman.com>
#
# This has been modified from the original software.
# Copyright (c) 2017 Valimail Inc
# Contact: Gene Shuman <gene@valimail.com>

import asyncio
import aiodns
import base64
import dkim
import re

__all__ = [
    'get_txt_async',
    'load_pk_from_dns_async',
    'verify_async'
    ]


async def get_txt_async(name, timeout=5):
    """Return a TXT record associated with a DNS name in an asnyc loop. For
    DKIM we can assume there is only one."""

    # Note: This will use the existing loop or create one if needed
    loop = asyncio.get_event_loop()
    resolver = aiodns.DNSResolver(loop=loop, timeout=timeout)

    async def query(name, qtype):
        return await resolver.query(name, qtype)

    #q = query(name, 'TXT')
    try:
        result = await query(name, 'TXT')
    except aiodns.error.DNSError:
        result = None

    if result:
        return result[0].text
    else:
        return None


async def load_pk_from_dns_async(name, dnsfunc, timeout=5):
  s = await dnsfunc(name, timeout=timeout)
  pk, keysize, ktag, seqtlsrpt = dkim.evaluate_pk(name, s)
  return pk, keysize, ktag, seqtlsrpt

class DKIM(dkim.DKIM):
  #: Sign an RFC822 message and return the DKIM-Signature header line.
  #:
  #: The include_headers option gives full control over which header fields
  #: are signed.  Note that signing a header field that doesn't exist prevents
  #: that field from being added without breaking the signature.  Repeated
  #: fields (such as Received) can be signed multiple times.  Instances
  #: of the field are signed from bottom to top.  Signing a header field more
  #: times than are currently present prevents additional instances
  #: from being added without breaking the signature.
  #:
  #: The length option allows the message body to be appended to by MTAs
  #: enroute (e.g. mailing lists that append unsubscribe information)
  #: without breaking the signature.
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
  #: @param identity: the DKIM identity value for the signature
  #: (default "@"+domain)
  #: @param canonicalize: the canonicalization algorithms to use
  #: (default (Simple, Simple))
  #: @param include_headers: a list of strings indicating which headers
  #: are to be signed (default rfc4871 recommended headers)
  #: @param length: true if the l= tag should be included to indicate
  #: body length signed (default False).
  #: @return: DKIM-Signature header field terminated by '\r\n'
  #: @raise DKIMException: when the message, include_headers, or key are badly
  #: formed.

  # Abstract helper method to verify a signed header
  #: @param sig: List of (key, value) tuples containing tag=values of the header
  #: @param include_headers: headers to validate b= signature against
  #: @param sig_header: (header_name, header_value)
  #: @param dnsfunc: interface to dns
  async def verify_sig(self, sig, include_headers, sig_header, dnsfunc):
    name = sig[b's'] + b"._domainkey." + sig[b'd'] + b"."
    try:
      pk, self.keysize, ktag, self.seqtlsrpt = await load_pk_from_dns_async(name, dnsfunc,
              timeout=self.timeout)
    except dkim.KeyFormatError as e:
      self.logger.error("%s" % e)
      return False

    # RFC 8460 MAY ignore signatures without tlsrpt Service Type
    if self.tlsrpt == 'strict' and not self.seqtlsrpt:
        raise ValidationError("Message is tlsrpt and Service Type is not tlsrpt")

    # Inferred requirement from both RFC 8460 and RFC 6376
    if not self.tlsrpt and self.seqtlsrpt:
        raise ValidationError("Message is not tlsrpt and Service Type is tlsrpt")

    try:
        canon_policy = dkim.CanonicalizationPolicy.from_c_value(sig.get(b'c', b'simple/simple'))
    except dkim.InvalidCanonicalizationPolicyError as e:
        raise dkim.MessageFormatError("invalid c= value: %s" % e.args[0])

    hasher = dkim.HASH_ALGORITHMS[sig[b'a']]

    # validate body if present
    if b'bh' in sig:
      h = dkim.HashThrough(hasher(), self.debug_content)

      body = canon_policy.canonicalize_body(self.body)
      if b'l' in sig and not self.tlsrpt:
        body = body[:int(sig[b'l'])]
      h.update(body)
      if self.debug_content:
          self.logger.debug("body hashed: %r" % h.hashed())
      bodyhash = h.digest()

      self.logger.debug("bh: %s" % base64.b64encode(bodyhash))
      try:
          bh = base64.b64decode(re.sub(br"\s+", b"", sig[b'bh']))
      except TypeError as e:
          raise dkim.MessageFormatError(str(e))
      if bodyhash != bh:
          raise dkim.ValidationError(
              "body hash mismatch (got %s, expected %s)" %
              (base64.b64encode(bodyhash), sig[b'bh']))

    # address bug#644046 by including any additional From header
    # fields when verifying.  Since there should be only one From header,
    # this shouldn't break any legitimate messages.  This could be
    # generalized to check for extras of other singleton headers.
    if b'from' in include_headers:
      include_headers.append(b'from')
    h = dkim.HashThrough(hasher(), self.debug_content)

    headers = canon_policy.canonicalize_headers(self.headers)
    self.signed_headers = dkim.hash_headers(
        h, canon_policy, headers, include_headers, sig_header, sig)
    if self.debug_content:
        self.logger.debug("signed for %s: %r" % (sig_header[0], h.hashed()))
    signature = base64.b64decode(re.sub(br"\s+", b"", sig[b'b']))
    if ktag == b'rsa':
        try:
            res = dkim.RSASSA_PKCS1_v1_5_verify(h, signature, pk)
            self.logger.debug("%s valid: %s" % (sig_header[0], res))
            if res and self.keysize < self.minkey:
                raise dkim.KeyFormatError("public key too small: %d" % self.keysize)
            return res
        except (TypeError,dkim.DigestTooLargeError) as e:
            raise dkim.KeyFormatError("digest too large for modulus: %s"%e)
    elif ktag == b'ed25519':
        try:
            pk.verify(h.digest(), signature)
            self.logger.debug("%s valid" % (sig_header[0]))
            return True
        except (nacl.exceptions.BadSignatureError) as e:
            return False
    else:
        raise dkim.UnknownKeyTypeError(ktag)

  async def verify(self,idx=0,dnsfunc=get_txt_async):
    sigheaders = [(x,y) for x,y in self.headers if x.lower() == b"dkim-signature"]
    if len(sigheaders) <= idx:
        return False

    # By default, we validate the first DKIM-Signature line found.
    try:
        sig = dkim.parse_tag_value(sigheaders[idx][1])
        self.signature_fields = sig
    except dkim.InvalidTagValueList as e:
        raise dkim.MessageFormatError(e)

    self.logger.debug("sig: %r" % sig)

    dkim.validate_signature_fields(sig)
    self.domain = sig[b'd']
    self.selector = sig[b's']

    include_headers = [x.lower() for x in re.split(br"\s*:\s*", sig[b'h'])]
    self.include_headers = tuple(include_headers)

    return await self.verify_sig(sig, include_headers, sigheaders[idx], dnsfunc)


async def verify_async(message, logger=None, dnsfunc=None, minkey=1024,
        timeout=5, tlsrpt=False):
    """Verify the first (topmost) DKIM signature on an RFC822 formatted message in an asyncio contxt.
    @param message: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param logger: a logger to which debug info will be written (default None)
    @param timeout: number of seconds for DNS lookup timeout (default = 5)
    @param tlsrpt: message is an RFC 8460 TLS report (default False)
    False: Not a tlsrpt, True: Is a tlsrpt, 'strict': tlsrpt, invalid if
    service type is missing. For signing, if True, length is never used.
    @return: True if signature verifies or False otherwise
    """
    # type: (bytes, any, function, int) -> bool
    # Note: This will use the existing loop or create one if needed
    loop = asyncio.get_event_loop()
    if not dnsfunc:
        dnsfunc=get_txt_async
    d = DKIM(message,logger=logger,minkey=minkey,timeout=timeout,tlsrpt=tlsrpt)
    try:
        return await d.verify(dnsfunc=dnsfunc)
    except dkim.DKIMException as x:
        if logger is not None:
            logger.error("%s" % x)
        return False
