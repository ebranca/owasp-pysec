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
""""""
import string
import types

from pysec.core import Object
from pysec import strings
from pysec.xsplit import xsplit


class Filter(Object):

    def __init__(self, filt):
        self.filter = filt

    def __ror__(self, obj):
        filt = self.filter
        if isinstance(obj, types.GeneratorType) or hasattr(obj, '__iter__'):
            return (el for el in obj if filt(el))
        else:
            raise TypeError("TypeError: left operand must be a generator or a iterable, not %r" % type(obj))


only_true = Filter(bool)
only_false = Filter(lambda e: not e)

longer_than = lambda l: Filter(lambda e: len(e) > l)
shorter_than = lambda l: Filter(lambda e: len(e) < l)
as_long_as = lambda l: Filter(lambda e: len(e) == l)

eq = lambda v: Filter(lambda e: e == v)
eq_n = lambda i, v: Filter(lambda e: e[i] == v)


def contains(*elements):
    return Filter(lambda t: any((e in t) for e in elements))


def not_contains(*elements):
    return Filter(lambda t: all((e not in t) for e in elements))


class Parser(Object):

    def __init__(self, parser):
        self.parse = parser

    def __ror__(self, obj):
        parse = self.parse
        if isinstance(obj, types.GeneratorType) or hasattr(obj, '__iter__'):
            return (parse(el) for el in obj)
        else:
            raise TypeError("TypeError: left operand must be a generator or a iterable, not %r" % type(obj))


none = Parser(lambda e: e)
to_str = Parser(str)
to_repr = Parser(repr)
to_erepr = Parser(strings.erepr)
to_len = Parser(len)

split = lambda sep: Parser(lambda val: tuple(xsplit(val, sep)))

strip = lambda sep: Parser(string.strip)

