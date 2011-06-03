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

import re


class Simple:
    """Class that represents the "simple" canonicalization algorithm."""

    name = b"simple"

    @staticmethod
    def canonicalize_headers(headers):
        # No changes to headers.
        return headers

    @staticmethod
    def canonicalize_body(body):
        # Ignore all empty lines at the end of the message body.
        return re.sub(b"(\r\n)*$", b"\r\n", body)


class Relaxed:
    """Class that represents the "relaxed" canonicalization algorithm."""

    name = b"relaxed"

    @staticmethod
    def canonicalize_headers(headers):
        # Convert all header field names to lowercase.
        # Unfold all header lines.
        # Compress WSP to single space.
        # Remove all WSP at the start or end of the field value (strip).
        return [
            (x[0].lower(),
             re.sub(br"\s+", b" ", re.sub(b"\r\n", b"", x[1])).strip()
             + b"\r\n")
            for x in headers]

    @staticmethod
    def canonicalize_body(body):
        # Remove all trailing WSP at end of lines.
        removed_trailing_wsp = re.sub(b"[\\x09\\x20]+\r\n", b"\r\n", body)
        # Compress non-line-ending WSP to single space.
        compressed_wsp = re.sub(br"[\x09\x20]+", b" ", removed_trailing_wsp)
        # Ignore all empty lines at the end of the message body.
        removed_trailing_lines = re.sub(b"(\r\n)*$", b"\r\n", compressed_wsp)
        return removed_trailing_lines


algorithms = dict((c.name, c) for c in (Simple, Relaxed))
