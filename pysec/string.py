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


def erepr(s):
    """Return a escaped string, like repr, without quotes"""
    return str(s).encode('string_escape')


def single_byte_xor(s, xor):
    xor = int(xor)
    if xor < 0 or xor > 255:
        raise ValueError(lang.STR_INVALID_BYTE_INT)
    return ''.join(chr(ord(ch) ^ xor) for ch in str(s))

