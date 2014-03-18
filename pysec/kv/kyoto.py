import os
import kv
import kyotocabinet as kyoto


_OPEN_MODE = kyoto.DB.OWRITER | kyoto.DB.OREADER | kyoto.DB.OCREATE


class KyotoKV(kv.HardKV):

    def __init__(self, path, parse=lambda v: v, unparse=lambda v: v):
        self.fk = kyoto.DB()
        if not self.fk.open(path, _OPEN_MODE):
             raise self.fk.error()
        self.parse = parse
        self.unparse = unparse

    def close(self):
        self.fk.close()

    def __del__(self):
        self.close()

    def __len__(self):
        count = self.fk.count()
        if count < 0:
            raise self.fk.error()
        return count

    def __getitem__(self, key):
        value = self.fk.get(self.parse(key))
        if value is None:
            raise self.fk.error()
        return self.unparse(value)

    def __setitem__(self, key, value):
        if not self.fk.set(self.parse(key), self.parse(value)):
            raise self.fk.error()

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
        return '{%s}' % ', '.join('%r: %r' % (k, v) for k, v in self.iteritems())

    def size(self):
        return os.stat(self.fk.path()).st_size

    def clear(self):
        self.fk.clear()

    def copy(self):
        raise NotImplementedError

    @classmethod
    def fromkeys(seq, value=None):
        raise NotImplementedError

    def get(self, key, default=None):
        value = self.fk.get(self.parse(key))
        return default if value is None else self.unparse(value)

    def has_key(self, key):
        return key in self

    def items(self):
        return list(self.iteritems())

    def iteritems(self):
        parse = self.parse
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
        unparse = self.unparse
        return (value for _, value in self.iteritems())

    def keys(self):
        return list(self)

    def iterkeys(self):
        return iter(self)

    def pop(self, key):
        value = self[key]
        self.fk.remove(self.parse(key))
        return value

    def popitem(self):
        item = self.fk.shift()
        if item is None:
             raise KeyError("popitem(): dictionary is empty")
        return self.unparse(item[0]), self.unparse(item[1])

    def setdefault(self, key, default=None):
        key = self.parse(key)
        return self[key] if self.fk.add(key, self.parse(default)) else default

    def update(self, **other):
        parse = self.parse
        self.fk.set_bulks(((parse(k), parse(v)) for k, v in other.iteritems()), 1)

    def cas(self, key, oval, nval):
        if not self.fk.cas(self.parse(key), self.parse(oval), self.parse(nval)):
            raise self.fk.error()
