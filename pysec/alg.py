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
from itertools import islice


def knp(source, pattern, start, stop):
    """Yields all oocurrencies of pattern in source[start:stop]"""
    shifts = [1] * (len(pattern) + 1)
    shift = 1
    for pos in range(len(pattern)):
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


def knp_find(source, pattern, start, stop):
    """Returns a true value if find the pattern in source"""
    for index in knp(source, pattern, start, stop):
        return index
    return -1
