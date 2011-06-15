
# Demonstrate
# <https://bugs.edge.launchpad.net/ubuntu/+source/pydkim/+bug/587783>
# Relaxed-mode header signing is wrong

import sys
import dkim
import unittest

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


class SignTestCase(unittest.TestCase):

  def testsign(self):
    for header_mode in [dkim.Relaxed, dkim.Simple]:

      dkim_header = dkim.sign(sample_msg, 'example', 'canonical.com',
          sample_privkey, canonicalize=(header_mode, dkim.Relaxed))
      signed = dkim_header + sample_msg

      result = dkim.verify(signed,dnsfunc=lambda x: _dns_responses[x])
      self.assertTrue(result)

def suite(): 
  s = unittest.makeSuite(SignTestCase,'test')
  return s

if __name__ == '__main__':
  unittest.TextTestRunner().run(suite())
