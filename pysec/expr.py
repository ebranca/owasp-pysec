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
"""Module with utilities to create expression objects.

Example:
    from pysec.expr import *

    x = variable()
    expr = x * 2
    expr.compute(x=2)
    # 4
    expr = x * 100 + 1 < 12 * y
    expr.compute(x=-1, y=10)
    # True
    expr.compute(x=1, y=1)
    # False

"""
import inspect
import operator

from pysec.core import Object
from pysec import lang
from pysec.path import match_path as _match_path


__all__ = 'Expression', 'var', 'const'


# TODO - method to get a representation of the expression


class Expression(Object):
    """Expression represents a expression.
    If *func* is None, *values* will be the value of the expression.
    If *func* is not None, *values* must be a tuple to pass to *func* as
    arguments.
    """

    def __init__(self, values, func=None):
        self.values = values
        self.func = func

    def compute(self, **kwds):
        values = self.values
        func = self.func
        if func is None:
            return values.compute(**kwds) if isinstance(values, Expression) else values
        elif isinstance(values, dict):
            return func(**{attr:(val.compute(**kwds) if isinstance(val, Expression) else val) for attr, val in values.iteritems()})
        else:
            return func(*tuple((val.compute(**kwds) if isinstance(val, Expression) else val) for val in values))

    def __lt__(self, other):
        return Expression((self, other), operator.lt)

    def __le__(self, other):
        return Expression((self, other), operator.le)

    def __eq__(self, other):
        return Expression((self, other), operator.eq)

    def __ne__(self, other):
        return Expression((self, other), operator.ne)

    def __ge__(self, other):
        return Expression((self, other), operator.ge)

    def __gt__(self, other):
        return Expression((self, other), operator.gt)

    def __not__(self, other):
        return Expression((self, other), operator.not_)

    def __bool__(self):
        return Expression((self,), operator.truth)

    def __abs__(self):
        return Expression((self,), operator.abs)

    def __add__(self, other):
        return Expression((self, other), operator.add)

    def __and__(self, other):
        return Expression((self, other), operator.and_)

    def __div__(self, other):
        return Expression((self, other), operator.div)

    def __floordiv__(self, other):
        return Expression((self, other), operator.floordiv)

    def __index__(self):
        return Expression((self,), operator.__index__)

    def __invert__(self):
        return Expression((self,), operator.invert)

    def __inv__(self):
        return Expression((self,), operator.invert)

    def __lshift__(self, other):
        return Expression((self, other), operator.lshift)

    def __mod__(self, other):
        return Expression((self, other), operator.mod)

    def __mul__(self, other):
        return Expression((self, other), operator.mul)

    def __neg__(self):
        return Expression(self, operator.neg)

    def __or__(self, other):
        return Expression((self, other), operator.or_)

    def __pos__(self):
        return Expression(self, operator.pos)

    def __pow__(self, other):
        return Expression((self, other), operator.pow)

    def __rshift__(self, other):
        return Expression((self, other), operator.rshift)

    def __sub__(self, other):
        return Expression((self, other), operator.sub)

    def __truediv__(self, other):
        return Expression((self, other), operator.truediv)

    def __xor__(self, other):
        return Expression((self, other), operator.xor)

    def __concat__(self, other):
        return Expression((self, other), operator.concat)

    def __contains__(self, other):
        return Expression((self, other), operator.contains)

    def __delitem__(self, key):
        return Expression((self, key), operator.delitem)

    def __delslice__(self, key):
        return Expression((self, key), operator.delslice)

    def __getitem__(self, key):
        return Expression((self, key), operator.getitem)

    def __getslice__(self, key):
        return Expression((self, key), operator.getslice)

    def __repeat__(self):
        return Expression(self, operator.repeat)

    def __setitem__(self, key, value):
        return Expression((self, key, value), operator.setitem)

    def __setslice__(self, key, value):
        return Expression((self, key, value), operator.setslice)

    def __iadd__(self, other):
        return Expression((self, other), operator.iadd)

    def __iand__(self, other):
        return Expression((self, other), operator.iand)

    def __iconcat__(self, other):
        return Expression((self, other), operator.concat)

    def __idiv__(self, other):
        return Expression((self, other), operator.idiv)

    def __ifloordiv__(self, other):
        return Expression((self, other), operator.ifloordiv)

    def __ilshift__(self, other):
        return Expression((self, other), operator.ilshift)

    def __imod__(self, other):
        return Expression((self, other), operator.imod)

    def __imul__(self, other):
        return Expression((self, other), operator.imul)

    def __ior__(self, other):
        return Expression((self, other), operator.ior)

    def __ipow__(self, other):
        return Expression((self, other), operator.ipow)

    def __irepeat__(self, other):
        return Expression((self, other), operator.irepeat)

    def __irshift__(self, other):
        return Expression((self, other), operator.irshift)

    def __isub__(self, other):
        return Expression((self, other), operator.isub)

    def __itruediv__(self, other):
        return Expression((self, other), operator.itruediv)

    def __ixor__(self, other):
        return Expression((self, other), operator.ixor)

    def __getattr__(self, attr):
        return Expression((self,), operator.attrgetter(attr))

    def __call__(self, *args, **kwds):
        return Expression((self, args, kwds), apply)


class Variable(Expression):

    def __init__(self, name):
        self.name = str(name)
        def _func(*_):
            return self.name
        self.func = _func

    def compute(self, **kwds):
        return kwds[self.name]


class FunctionMaker(Object):

    def __init__(self, func):
        self.func = func

    def __call__(self, *args, **kwds):
        kwds = inspect.getcallargs(self.func, *args, **kwds)
        return Expression(kwds, self.func)


class VarMaker(Object):

    def __getattr__(self, name):
        name = str(name)
        if name[:1].isalpha() and ((not name[1:]) or name[1:].isalnum()):
            return Variable(name)
        raise ValueError(lang.EXPR_WRONG_VAR_NAME % name)

        
var = VarMaker()
const = lambda val: Expression(val, None)


# utilities

length = FunctionMaker(lambda v: len(v))
match_path = FunctionMaker(_match_path)

