#!/usr/bin/python
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
# Copyright (c) 2016 Google, Inc.
# Contact: Brandon Long <blong@google.com>

"""Generates new domainkeys pairs.

Sample usage:

   dknewkey.py <keyname>
"""


import os
import subprocess
import sys
import tempfile

# how strong are our keys?
BITS_REQUIRED = 2048

# what openssl binary do we use to do key manipulation?
OPENSSL_BINARY = '/usr/bin/openssl'

def GenKeys(private_key_file):
  """ Generates a suitable private key.  Output is unprotected.
  You should encrypt your keys.
  """
  print >> sys.stderr, 'generating ' + private_key_file
  subprocess.check_call([OPENSSL_BINARY, 'genrsa', '-out', private_key_file,
                         str(BITS_REQUIRED)])


def ExtractDnsPublicKey(private_key_file, dns_file):
  """ Given a key, extract the bit we should place in DNS.
  """
  print >> sys.stderr, 'extracting ' + private_key_file
  working_file = tempfile.NamedTemporaryFile(delete=False).name
  subprocess.check_call([OPENSSL_BINARY, 'rsa', '-in', private_key_file,
                         '-out', working_file, '-pubout', '-outform', 'PEM'])
  cmd = 'grep -v ^-- %s | tr -d \'\\n\'' % working_file
  try:
    output = subprocess.check_output(cmd, shell=True)
  finally:
    os.unlink(working_file)
  dns_fp = open(dns_file, "w+")
  print >> sys.stderr, 'writing ' + dns_file
  print >> dns_fp, "k=rsa; p=%s" % output
  dns_fp.close()


def main(argv):
  if len(argv) != 2:
    print >> sys.stderr, '%s: <keyname>' % argv[0]
    sys.exit(1)

  key_name = argv[1]
  private_key_file = key_name + '.key'
  dns_file = key_name + '.dns'

  GenKeys(private_key_file)
  ExtractDnsPublicKey(private_key_file, dns_file)


if __name__ == '__main__':
  main(sys.argv)
