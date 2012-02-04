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

import os.path
import unittest

import dkim


def read_test_data(filename):
    """Get the content of the given test data file.

    The files live in dkim/tests/data.
    """
    path = os.path.join(os.path.dirname(__file__), 'data', filename)
    with open(path, 'rb') as f:
        return f.read()


class TestFold(unittest.TestCase):

    def test_short_line(self):
        self.assertEqual(
            b"foo", dkim.fold(b"foo"))

    def test_long_line(self):
        # The function is terribly broken, not passing even this simple
        # test.
        self.assertEqual(
            b"foo" * 24 + b"\r\n foo", dkim.fold(b"foo" * 25))


class TestSignAndVerify(unittest.TestCase):
    """End-to-end signature and verification tests."""

    def setUp(self):
        self.message = read_test_data("test.message")
        self.key = read_test_data("test.private")

    def dnsfunc(self, domain):
        try:
            domain = domain.decode('ascii')
        except UnicodeDecodeError:
            return None
        self.assertEqual('test._domainkey.example.com.', domain)
        return read_test_data("test.txt")

    def test_verifies(self):
        # A message verifies after being signed.
        for header_algo in (b"simple", b"relaxed"):
            for body_algo in (b"simple", b"relaxed"):
                sig = dkim.sign(
                    self.message, b"test", b"example.com", self.key,
                    canonicalize=(header_algo, body_algo))
                res = dkim.verify(sig + self.message, dnsfunc=self.dnsfunc)
                self.assertTrue(res)

    def test_altered_body_fails(self):
        # An altered body fails verification.
        for header_algo in (b"simple", b"relaxed"):
            for body_algo in (b"simple", b"relaxed"):
                sig = dkim.sign(
                    self.message, b"test", b"example.com", self.key)
                res = dkim.verify(
                    sig + self.message + b"foo", dnsfunc=self.dnsfunc)
                self.assertFalse(res)

    def test_badly_encoded_domain_fails(self):
        # Domains should be ASCII. Bad ASCII causes verification to fail.
        sig = dkim.sign(self.message, b"test", b"example.com\xe9", self.key)
        res = dkim.verify(sig + self.message, dnsfunc=self.dnsfunc)
        self.assertFalse(res)

    def test_dkim_dignature_canonicalization(self):
      # <https://bugs.launchpad.net/ubuntu/+source/pydkim/+bug/587783>
      # Relaxed-mode header signing is wrong
      sample_msg = """\
From: mbp@canonical.com
To: scottk@example.com
Subject: this is my
    test message
""".replace('\n', '\r\n')

      sample_privkey = """\
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANmBe10IgY+u7h3enWTukkqtUD5PR52Tb/mPfjC0QJTocVBq6Za/
PlzfV+Py92VaCak19F4WrbVTK5Gg5tW220MCAwEAAQJAYFUKsD+uMlcFu1D3YNaR
EGYGXjJ6w32jYGJ/P072M3yWOq2S1dvDthI3nRT8MFjZ1wHDAYHrSpfDNJ3v2fvZ
cQIhAPgRPmVYn+TGd59asiqG1SZqh+p+CRYHW7B8BsicG5t3AiEA4HYNOohlgWan
8tKgqLJgUdPFbaHZO1nDyBgvV8hvWZUCIQDDdCq6hYKuKeYUy8w3j7cgJq3ih922
2qNWwdJCfCWQbwIgTY0cBvQnNe0067WQIpj2pG7pkHZR6qqZ9SE+AjNTHX0CIQCI
Mgq55Y9MCq5wqzy141rnxrJxTwK9ABo3IAFMWEov3g==
-----END RSA PRIVATE KEY-----
"""

      sample_pubkey = """\
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANmBe10IgY+u7h3enWTukkqtUD5PR52T
b/mPfjC0QJTocVBq6Za/PlzfV+Py92VaCak19F4WrbVTK5Gg5tW220MCAwEAAQ==
-----END PUBLIC KEY-----
"""

      sample_dns = """\
k=rsa; \
p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANmBe10IgY+u7h3enWTukkqtUD5PR52T\
b/mPfjC0QJTocVBq6Za/PlzfV+Py92VaCak19F4WrbVTK5Gg5tW220MCAwEAAQ=="""

      _dns_responses = {'example._domainkey.canonical.com.': sample_dns}
      for header_mode in [dkim.Relaxed, dkim.Simple]:

        dkim_header = dkim.sign(sample_msg, 'example', 'canonical.com',
            sample_privkey, canonicalize=(header_mode, dkim.Relaxed))
        signed = dkim_header + sample_msg

        result = dkim.verify(signed,dnsfunc=lambda x: _dns_responses[x])
        self.assertTrue(result)

    def test_extra_headers(self):
        # <https://bugs.launchpad.net/dkimpy/+bug/737311>
        # extra headers above From caused failure
        #message = read_test_data("test_extra.message")
        message = read_test_data("message.mbox")
        for header_algo in (b"simple", b"relaxed"):
            for body_algo in (b"simple", b"relaxed"):
                d = dkim.DKIM(message)
                # bug requires a repeated header to manifest
                d.should_not_sign.remove('received')
                sig = d.sign(b"test", b"example.com", self.key,
                    include_headers=d.all_sign_headers(),
                    canonicalize=(header_algo, body_algo))
                dv = dkim.DKIM(sig + message)
                res = dv.verify(dnsfunc=self.dnsfunc)
                self.assertEquals(d.include_headers,dv.include_headers)
                s = dkim.select_headers(d.headers,d.include_headers)
                sv = dkim.select_headers(dv.headers,dv.include_headers)
                self.assertEquals(s,sv)
                self.assertTrue(res)

    def test_multiple_from_fails(self):
        # <https://bugs.launchpad.net/dkimpy/+bug/644046>
        # additional From header fields should cause verify failure
        hfrom = b'From: "Resident Evil" <sales@spammer.com>\r\n'
        h,b = self.message.split(b'\n\n',1)
        for header_algo in (b"simple", b"relaxed"):
            for body_algo in (b"simple", b"relaxed"):
                sig = dkim.sign(
                    self.message, b"test", b"example.com", self.key)
                # adding an unknown header still verifies
                h1 = h+b'\r\n'+b'X-Foo: bar'
                message = b'\n\n'.join((h1,b))
                res = dkim.verify(sig+message, dnsfunc=self.dnsfunc)
                self.assertTrue(res)
                # adding extra from at end should not verify
                h1 = h+b'\r\n'+hfrom.strip()
                message = b'\n\n'.join((h1,b))
                res = dkim.verify(sig+message, dnsfunc=self.dnsfunc)
                self.assertFalse(res)
                # add extra from in front should not verify either
                h1 = hfrom+h
                message = b'\n\n'.join((h1,b))
                res = dkim.verify(sig+message, dnsfunc=self.dnsfunc)
                self.assertFalse(res)

def test_suite():
    from unittest import TestLoader
    return TestLoader().loadTestsFromName(__name__)
