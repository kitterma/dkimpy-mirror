#!/usr/bin/env python

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

from __future__ import print_function

import sys
import argparse

import dkim

# Backward compatibility hack because argparse doesn't support optional
# positional arguments
arguments=['--'+arg if arg[:8] == 'identity' else arg for arg in sys.argv[1:]]
parser = argparse.ArgumentParser(description='Produce DKIM signature for email messages.')
parser.add_argument('selector', action="store")
parser.add_argument('domain', action="store")
parser.add_argument('privatekeyfile', action="store")
parser.add_argument('--hcanon', choices=['simple', 'relaxed'], default='relaxed', type=bytes, help='Header canonicalization algorithm: default=relaxed')
parser.add_argument('--bcanon', choices=['simple', 'relaxed'], default='simple', type=bytes, help='Body canonicalization algorithm: default=simple')
parser.add_argument('--identity', help='Optional value for i= tag.')
args=parser.parse_args(arguments)

if sys.version_info[0] >= 3:
    # Make sys.stdin and stdout binary streams.
    sys.stdin = sys.stdin.detach()
    sys.stdout = sys.stdout.detach()

message = sys.stdin.read()
try:
    sig = dkim.sign(message, args.selector, args.domain, open(args.privatekeyfile, "rb").read(), identity = args.identity, canonicalize=(args.hcanon, args.bcanon))
    sys.stdout.write(sig)
    sys.stdout.write(message)
except Exception as e:
    print(e, file=sys.stderr)
    sys.stdout.write(message)
