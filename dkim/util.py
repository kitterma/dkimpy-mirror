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

__all__ = [
    'DuplicateTag',
    'InvalidTagSpec',
    'InvalidTagValueList',
    'parse_tag_value',
    ]


class InvalidTagValueList(Exception):
    pass


class DuplicateTag(InvalidTagValueList):
    pass


class InvalidTagSpec(InvalidTagValueList):
    pass


def parse_tag_value(tag_list):
    """Parse a DKIM Tag=Value list.

    Interprets the syntax specified by RFC4871 section 3.2.
    Assumes that folding whitespace is already unfolded.

    @param tag_list: A string containing a DKIM Tag=Value list.
    """
    tags = {}
    tag_specs = tag_list.split(';')
    # Trailing semicolons are valid.
    if not tag_specs[-1]:
        tag_specs.pop()
    for tag_spec in tag_specs:
        try:
            key, value = tag_spec.split('=', 1)
        except ValueError:
            raise InvalidTagSpec(tag_spec)
        if key.strip() in tags:
            raise DuplicateTag(key.strip())
        tags[key.strip()] = value.strip()
    return tags
