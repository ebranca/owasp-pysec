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
from pysec.kv import HardKV


class RotationKV(HardKV):

    def __init__(self, maker, maxsize, maxfiles, *files):
        maxsize = int(maxsize)
        if maxsize <= 0:
            raise ValueError("maxsize is not positive: %r" % maxsize)
        maxfiles = int(maxfiles)
        if maxfiles <= 0:
            raise ValueError("maxfiles is not positive: %r" % maxfiles)
        self.maxsize = maxsize
        self.maxfiles = maxfiles
        self.maker = maker
        self._kvs = []

    def __len__(self):
        return sum(len(kv) for kv in self._kvs)

    def __getitem__(self, key):
        raise NotImplementedError

    def __setitem__(self, key, value):
        raise NotImplementedError

    def __delitem__(self, key):
        raise NotImplementedError

    def __contains__(self, key):
        raise NotImplementedError

    def __iter__(self):
        raise NotImplementedError

    def __str__(self):
        raise NotImplementedError

    def __repr__(self):
        raise NotImplementedError

    def size(self):
        raise NotImplementedError

    def clear(self):
        raise NotImplementedError

    def copy(self):
        raise NotImplementedError

    @classmethod
    def fromkeys(seq, value=None):
        raise NotImplementedError

    def get(self, key, default=None):
        raise NotImplementedError

    def has_key(self, key):
        raise NotImplementedError

    def items(self):
        raise NotImplementedError

    def iteritems(self):
        raise NotImplementedError

    def values(self):
        raise NotImplementedError

    def itervalues(self):
        raise NotImplementedError

    def keys(self):
        raise NotImplementedError

    def iterkeys(self):
        raise NotImplementedError

    def pop(self, key):
        raise NotImplementedError

    def popitem(self):
        raise NotImplementedError

    def setdefault(self, key, default=None):
        raise NotImplementedError

    def update(self, **other):
        raise NotImplementedError

    def cas(self, key, oval, nval):
        raise NotImplementedError
