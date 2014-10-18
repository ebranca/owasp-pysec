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
import math

from pysec.core import Dict
from pysec import lang

__all__ = 'Entropy', 'ent_bytes'


class Entropy(Dict):

    def __init__(self, *symbols, **freqs):
        super(Entropy, self).__init__((sym, 0) for sym in symbols)
        count = 0
        for sym, freq in freqs.iteritems():
            freq = int(freq)
            if freq < 0:
                raise ValueError(lang.ENT_NEGATIVE_FREQ % freq)
            self[sym] = freq
            count += freq
        self.count = count

    def increment(self, symbol):
        self[symbol] += 1
        return self[symbol]

    def __setitem__(self, symbol, freq):
        old_freq = self[symbol]
        freq = int(freq)
        if freq < 0:
            raise ValueError(lang.ENT_NEGATIVE_FREQ % freq)
        super(Entropy, self).__setitem__(symbol, freq)
        self.count += freq - old_freq

    def __delitem__(self, symbol):
        self[symbol] = 0

    def __float__(self):
        return self.entropy()

    def entropy(self, base=2):
        h = 0
        base = int(base)
        if base < 2:
            raise ValueError(lang.ENT_NEGATIVE_BASE % base)
        count = self.count
        for value in self.iteritems():
            if not value:
                continue
            p_i = float(value) / count
            h -= p_i * math.log(p_i, base)
        return h

    def iterincrement(self, *values):
        for val in values:
            self.increment(val)

    def clone(self):
        return Entropy(**self)


BYTES = ''.join(chr(ch) for ch in xrange(256))


def ent_bytes(bytes, base=2):
    ent = Entropy(*BYTES)
    for byte in bytes:
        if isinstance(byte, int):
            byte = chr(byte)
        else:
            byte = str(byte)
            if len(byte) != 1:
                raise ValueError(lang.ENT_WRONG_BYTE % byte)
        ent.increment(byte)
    return ent.entropy(base)

