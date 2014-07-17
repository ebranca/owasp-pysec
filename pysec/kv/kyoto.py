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
import os
import kyotocabinet as kyoto
from pysec import log, kv


__name__ = 'pysec.kv.kyoto'


log.register_actions('KYOTOKV_NEW', 'KYOTOKV_SET', 'KYOTOKV_GET',
                     'KYOTOKV_DEL', 'KYOTOKV_CLEAR', 'KYOTOKV_POP',
                     'KYOTOKV_UPDATE', 'KYOTOKV_CLOSE')


_OPEN_MODE = kyoto.DB.OWRITER | kyoto.DB.OREADER | kyoto.DB.OCREATE


class KyotoKV(kv.HardKV):

    @log.wrap(log.actions.KYOTOKV_NEW, fields=('path',), lib=__name__)
    def __init__(self, path, parse=lambda v: v, unparse=lambda v: v):
        self.fk = kyoto.DB()
        if not self.fk.open(path, _OPEN_MODE):
            raise self.fk.error()
        self.parse = parse
        self.unparse = unparse

    @log.wrap(log.actions.KYOTOKV_CLOSE, lib=__name__)
    def close(self):
        self.fk.close()

    def __del__(self):
        self.close()

    def __len__(self):
        count = self.fk.count()
        if count < 0:
            raise self.fk.error()
        return count

    @log.wrap(log.actions.KYOTOKV_GET, fields=('key',), lib=__name__)
    def __getitem__(self, key):
        value = self.fk.get(self.parse(key))
        if value is None:
            raise self.fk.error()
        return self.unparse(value)

    @log.wrap(log.actions.KYOTOKV_SET, fields=('key', 'value'), lib=__name__)
    def __setitem__(self, key, value):
        if not self.fk.set(self.parse(key), self.parse(value)):
            raise self.fk.error()

    @log.wrap(log.actions.KYOTOKV_DEL, fields=('key',), lib=__name__)
    def __delitem__(self, key):
        if not self.fk.remove(self.parse(key)):
            raise self.fk.error()

    def __contains__(self, key):
        return self.fk.check(self.parse(key)) >= 0

    def __iter__(self):
        for key, _ in self.iteritems():
            yield key

    def __str__(self):
        return '<KyotoKV %s>' % hex(id(self))

    def __repr__(self):
        return '{%s}' % ', '.join('%r: %r' % (k, v)
                                  for k, v in self.iteritems())

    def size(self):
        return os.stat(self.fk.path()).st_size

    @log.wrap(log.actions.KYOTOKV_CLEAR, lib=__name__)
    def clear(self):
        self.fk.clear()

    def copy(self):
        raise NotImplementedError

    @classmethod
    def fromkeys(seq, value=None):
        raise NotImplementedError

    @log.wrap(log.actions.KYOTOKV_GET, fields=('key',), lib=__name__)
    def get(self, key, default=None):
        value = self.fk.get(self.parse(key))
        return default if value is None else self.unparse(value)

    def has_key(self, key):
        return key in self

    def items(self):
        return list(self.iteritems())

    def iteritems(self):
        unparse = self.unparse
        try:
            cursor = self.fk.cursor()
            cursor.jump()
            while 1:
                record = cursor.get(1)
                if record is None:
                    break
                yield unparse(record[0]), unparse(record[1])
        finally:
            cursor.disable()

    def values(self):
        return list(self.itervalues())

    def itervalues(self):
        return (value for _, value in self.iteritems())

    def keys(self):
        return list(self)

    def iterkeys(self):
        return iter(self)

    @log.wrap(log.actions.KYOTOKV_POP, fields=('key',), lib=__name__)
    def pop(self, key):
        value = self[key]
        self.fk.remove(self.parse(key))
        return value

    @log.wrap(log.actions.KYOTOKV_POP, lib=__name__)
    def popitem(self):
        item = self.fk.shift()
        if item is None:
            raise KeyError("popitem(): dictionary is empty")
        return self.unparse(item[0]), self.unparse(item[1])

    def setdefault(self, key, default=None):
        key = self.parse(key)
        return self[key] if self.fk.add(key, self.parse(default)) else default

    @log.wrap(log.actions.KYOTOKV_UPDATE, lib=__name__)
    def update(self, **other):
        parse = self.parse
        self.fk.set_bulks(((parse(k), parse(v))
                          for k, v in other.iteritems()), 1)

    def cas(self, key, oval, nval):
        if not self.fk.cas(self.parse(key), self.parse(oval),
                           self.parse(nval)):
            raise self.fk.error()
