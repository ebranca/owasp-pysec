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
from types import DictType
from pysec.core import Object


__all__ = 'KV', 'SoftKV', 'HardKV', 'HybridKV'



class KV(Object, DictType):
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

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return 0


_NO_KEY = Object()


class HybridKV(HardKV, SoftKV):

    def __init__(self, soft_cls, hard_cls, soft_args=(), soft_kwargs=None,
                 hard_args=(), hard_kwargs=None):
        self.soft = soft_cls(*soft_args,
                             **({} if soft_kwargs is None else soft_kwargs))
        self.hard = hard_cls(*hard_args,
                             **({} if hard_kwargs is None else hard_kwargs))

    def refresh(self):
        raise NotImplementedError

    def get(self, key, default=None):
        value = self.soft.get(key, _NO_KEY)
        return self.hard.get(key, default) if value is _NO_KEY else value

    def __getitem__(self, key):
        value = self.soft.get(key, _NO_KEY)
        return self.hard.get[key] if value is _NO_KEY else value

