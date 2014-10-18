# Python Security Project (PySec) and its related class files.
#
# PySec is a set of tools for secure application development under Linux
#
# Copyright 2014 PySec development team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# -*- coding: ascii -*-
"""Various utilities for strings manipulation."""
from pysec import lang
from pysec.utils import xrange, eq


def erepr(s):
    """Return a escaped string, like repr, without quotes"""
    return str(s).encode('string_escape')


def single_byte_xor(s, xor):
    xor = int(xor)
    if xor < 0 or xor > 255:
        raise ValueError(lang.STR_WRONG_BYTE)
    return ''.join(chr(ord(ch) ^ xor) for ch in str(s))


def common_iprefix(*strings):
    """Return the length of the common prefix of strings"""
    i = 0
    for i in xrange(0, min(len(s) for s in strings)):
        if not eq(*(s[i] for s in strings)):
            return i
    return i


def common_prefix(*strings):
    """Return the common prefix of strings"""
    return '' if not strings else strings[0][:common_iprefix(*strings)]


def common_isuffix(*strings):
    """Return the length of the common suffix of strings"""
    i = -1
    for i in xrange(0, min(len(s) for s in strings)):
        if not eq(*(s[len(s) - i - 1] for s in strings)):
            return i
    return i + 1


def common_suffix(*strings):
    """Return the common prefix of strings"""
    return strings[0][len(strings[0]) - common_isuffix(*strings):] \
           if strings else ''


def split_newlines(string):
    """Generator of lines in *string* ending with '\r\n', '\n', '\n'"""
    newline_chars = 0
    line_start = 0
    for i in xrange(0, len(string)):
        if string[i] in ('\r', '\n'):
            if not newline_chars:
                yield string[line_start:i]
                newline_chars = 1
        else:
            if newline_chars:
                line_start = i
                newline_chars = 0
    if not newline_chars:
        yield string[line_start:]


def only_printable(string):
    """Remove all not printable characters from *string*"""
    return ''.join(ch for ch in string if 32 <= ord(ch) <= 126)


def only_visible(string):
    """Remove all not visible characters from *string*"""
    return ''.join(ch for ch in string if 33 <= ord(ch) <= 126)

