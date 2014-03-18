from kv import HardKV


class RotationKV(HardKV):

    def __init__(self, maker, maxsize, maxfiles, *files):
        maxsize = int(maxsize)
        if maxsize <= 0:
            raise ValueError("maxsize is not a positive integer: %r" % maxsize)
        maxfiles = int(maxfiles)
        if maxfiles <= 0:
            raise ValueError("maxfiles is not a positive integer: %r" % maxfiles)
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
