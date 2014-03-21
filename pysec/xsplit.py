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
"""Splitters for sequence-like objects to improve memory usage and speed"""


def xsplit(val, sep, keep_sep=0, start=0, stop=None, find=None):
    """Make an iterator that returns subsequences of the val (sequence-like
    object), breaking at sep and using find function, to search sep, from start
    to stop indices of val.

    If find is None, it use val.find function to search sep."""
    return (val[a:b] for a, b
            in xbounds(val, sep, keep_sep, start, stop, find))


def xbounds(val, sep, keep_sep=0, start=0, stop=None, find=None):
    """Make an iterator that returns bounds of the val (sequence-like object),
    breaking at sep and using find function, to search sep, from start to stop
    indices of val.

    If find is None, it use val.find function to search sep."""
    if stop is None:
        stop = len(val)
    if find is None:
        find = val.find
    else:
        _find = find
        find = lambda sep, start, stop: _find(val, sep, start, stop)
    start, stop, _ = slice(start, stop).indices(len(val))
    lsep = len(sep)
    while start < stop:
        chunk_end = find(sep, start, stop)
        if chunk_end < 0 or chunk_end is None:
            chunk_end = stop
            yield start, chunk_end
        else:
            yield start, chunk_end + lsep if keep_sep else chunk_end
        start = chunk_end + lsep


def xlines(text, eol='\n', keep_eol=0, start=0, stop=None, find=None):
    """Specialized xsplit generator for string splitting"""
    return xsplit(text, eol, keep_eol, start, stop, find)
