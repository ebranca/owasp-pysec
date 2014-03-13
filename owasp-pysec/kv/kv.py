from types import DictType


class KV(DictType):
    pass


class SoftKV(KV):
     pass


class HardKV(KV):

    def size(self):
        """Get the amount of occupied memory"""
        raise NotImplementedError

    def close(self):
        """Close persistent object"""
        raise NotImplementedError


_NO_KEY = object()


class HybridKV(HardKV, SoftKV):

    def __init__(self, soft_cls, hard_cls, soft_args=(), soft_kwargs=None, hard_args=(), hard_kwargs=None):
        self.soft = soft_cls(*soft_args, **({} if soft_kwargs is None else soft_kwargs))
        self.hard = hard_cls(*hard_args, **({} if hard_kwargs is None else hard_kwargs))

    def refresh(self):
        raise NotImplementedError

    def get(self, key, default=None):
        value = self.soft.get(key, _NO_KEY)
        return self.hard.get(key, default) if value is _NO_KEY else value

    def __getitem__(self, key):
        value = self.soft.get(key, _NO_KEY)
        return self.hard.get[key] if value is _NO_KEY else value
