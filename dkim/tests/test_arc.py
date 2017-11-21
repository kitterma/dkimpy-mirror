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
#
# This has been modified from the original software.
# Copyright (c) 2016 Google, Inc.
# Contact: Brandon Long <blong@google.com>

import os.path
import unittest
import time

import dkim


def read_test_data(filename):
    """Get the content of the given test data file.
    """
    path = os.path.join(os.path.dirname(__file__), 'data', filename)
    with open(path, 'rb') as f:
        return f.read()


class TestSignAndVerify(unittest.TestCase):
    """End-to-end signature and verification tests."""

    def setUp(self):
        self.message = read_test_data("test.message")
        self.key = read_test_data("test.private")

    def dnsfunc(self, domain):
        sample_dns = """\
k=rsa; \
p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANmBe10IgY+u7h3enWTukkqtUD5PR52T\
b/mPfjC0QJTocVBq6Za/PlzfV+Py92VaCak19F4WrbVTK5Gg5tW220MCAwEAAQ=="""

        _dns_responses = {
          'example._domainkey.canonical.com.': sample_dns,
          'test._domainkey.example.com.': read_test_data("test.txt"),
          # dnsfunc returns empty if no txt record
          'missing._domainkey.example.com.': '',
          '20120113._domainkey.gmail.com.': """k=rsa; \
p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Kd87/UeJjenpabgbFwh\
+eBCsSTrqmwIYYvywlbhbqoo2DymndFkbjOVIPIldNs/m40KF+yzMn1skyoxcTUGCQ\
s8g3FgD2Ap3ZB5DekAo5wMmk4wimDO+U8QzI3SD07y2+07wlNWwIt8svnxgdxGkVbb\
hzY8i+RQ9DpSVpPbF7ykQxtKXkv/ahW3KjViiAH+ghvvIhkx4xYSIc9oSwVmAl5Oct\
MEeWUwg8Istjqz8BZeTWbf41fbNhte7Y+YqZOwq1Sd0DbvYAD9NOZK9vlfuac0598H\
Y+vtSBczUiKERHv1yRbcaQtZFh5wtiRrN04BLUTD21MycBX5jYchHjPY/wIDAQAB"""
        }
        try:
            domain = domain.decode('ascii')
        except UnicodeDecodeError:
            return None
        self.assertTrue(domain in _dns_responses,domain)
        return _dns_responses[domain]

    def test_signs_and_verifies(self):
        # A message verifies after being signed.
        sig_lines = dkim.arc_sign(
            self.message, b"test", b"example.com", self.key, b"lists.example.org", timestamp="12345")

        expected_sig = [b'ARC-Seal: i=1; cv=none; a=rsa-sha256; d=example.com; s=test; t=12345; \r\n b=3jOfBfTKcq+3r3Xv158DybT4mWFxrGcop+cgyLUX2ETCMHqNXYwGx2h+NY46tr\r\n k0Lg6R8i+560+KC8PLcCURYYJNJUHLHPIifhddy1aMNL9l4CoI+Oz+rocd2IZeb/\r\n I9V5amOUOWnAlOvyrSt0XfzLJRTS8qJW3Is1CRkkgyLoI=\r\n', b'ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; \r\n d=example.com; s=test; t=12345; h=message-id : \r\n date : from : to : subject : date : from : \r\n subject; \r\n bh=wE7NXSkgnx9PGiavN4OZhJztvkqPDlemV3OGuEnLwNo=; \r\n b=Bj/AEKhmzMbltWXrfLA8UZNp6/5cj8/IzqbgQec4vGobDZRsa\r\n C0YIPM4tcqK2uTS62kwh40cndXTDsCppvRsBy1sIO3eRNyuLUOh\r\n 0XGrz0AdLQMv+IOdyQqZfMVkq8DuQ4Qdl7ee99uYf3D8S+L7GuD\r\n wJSk7dyH+P2BKxz2nyB0=\r\n', b'ARC-Authentication-Results: i=1; lists.example.org; arc=none;\r\n  spf=pass smtp.mfrom=jqd@d1.example;\r\n  dkim=pass (1024-bit key) header.i=@d1.example;\r\n  dmarc=pass\r\n']

        self.assertEquals(expected_sig, sig_lines)

        (cv, res, reason) = dkim.arc_verify(b''.join(sig_lines) + self.message, dnsfunc=self.dnsfunc)
        self.assertEquals(cv, dkim.CV_Pass)

def test_suite():
    from unittest import TestLoader
    return TestLoader().loadTestsFromName(__name__)
