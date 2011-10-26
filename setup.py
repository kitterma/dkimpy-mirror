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
# Copyright (c) 2011 Scott Kitterman <scott@kitterman.com>

from distutils.core import setup
import os

version = "0.5"

setup(
    name = "pydkim",
    version = version,
    description = "DKIM (DomainKeys Identified Mail)",
    long_description =
    """pydkim is a Python library that implements DKIM (DomainKeys
Identified Mail) email signing and verification.""",
    author = "Greg Hewgill",
    author_email = "greg@hewgill.com",
    url = "http://hewgill.com/pydkim/",
    license = "BSD-like",
    packages = ["dkim"],
    scripts = ["dkimsign.py", "dkimverify.py"],
    data_files = [(os.path.join('share', 'man', 'man1'),
        ['man/dkimsign.1']), (os.path.join('share', 'man', 'man1'),
        ['man/dkimverify.1'])],
)

if os.name != 'posix':
    data_files = ''
