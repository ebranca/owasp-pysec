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
from itertools import islice
from zlib import adler32

from pysec.utils import xrange


__all__ = 'knp', 'knp_first', 'knp_find', 'rk', 'rk_first', 'rk_find'


def knp(source, pattern, start=0, stop=None):
    """Yields all occurrences of pattern in source[start:stop]"""
    shifts = [1] * (len(pattern) + 1)
    shift = 1
    for pos in xrange(0, len(pattern)):
        while pattern[pos] != pattern[pos - shift] and shift <= pos:
            shift += shifts[pos - shift]
        shifts[pos + 1] = shift
    # search pattern
    mlen = 0
    plen = len(pattern)
    for sub in islice(source, start, stop):
        while mlen == plen or mlen >= 0 and pattern[mlen] != sub:
            sl = shifts[mlen]
            start += sl
            mlen -= sl
        mlen += 1
        if mlen == plen:
            yield start


def knp_first(source, pattern, start=0, stop=None):
    """Return the index of the first occurrence of pattern in 
    source[start:stop]"""
    try:
        return knp(source, pattern, start, stop).next()
    except StopIteration:
        return -1


def knp_find(source, pattern, start=0, stop=None):
    """Returns a true value if find the pattern in source"""
    for _ in knp(source, pattern, start, stop):
        return 1
    return 0


def rk(source, pattern, start=0, stop=None, checksum=adler32):
    """Return a generator that yields all oocurrencies of pattern in
    source[start:stop] using the Rabin-Karp algorithm.
    hasher is a callable that returns the object checksum."""
    if stop is None:
        stop = len(source)
    src_len = stop - start
    pat_len = len(pattern)
    pat_checksum = checksum(pattern)
    if pat_len > src_len or start > stop:
        return iter(())
    return (i for i in xrange(start, src_len - pat_len + 1)
            if checksum(source[i:i + pat_len]) == pat_checksum and
               source[i:i + pat_len] == pattern)


def rk_first(source, pattern, start=0, stop=None, checksum=adler32):
    """Return the index of the first occurrence of pattern in 
    source[start:stop] using the Rabin-Karp algorithm.
    hasher is a callable that returns the object checksum."""
    try:
        return rk(source, pattern, start, stop, checksum).next()
    except StopIteration:
        return -1


def rk_find(source, pattern, start=0, stop=None, checksum=adler32):
    """Return a true value if find the pattern in source"""
    """Return a true value if pattern is present in source[start:stop] using
    the Rabin-Karp algorithm.
    hasher is a callable that returns the object checksum."""
    for _ in rk(source, pattern, start, stop, checksum):
        return 1
    return 0

