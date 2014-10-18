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
"""Module to make checkers.

from pysec.expr import var

a, b = var.a, var.b


@check(
    a.__int__,
    a > 1,
    a + b != 10,
    a * b < a / b
)
def foo(a, b):
    ...


@check(
    # first check
    (a > 1,
     a + b != 10,
     a * b < a / b),
     # second check (if first fails)
     # parsers
    a=int,
    b=float
)
def foo(a, b):
    ...
"""
import inspect

from pysec.core import Object, Error
from pysec.expr import Expression
from pysec import lang


NO_CHECK = Object()


class CheckError(Error):
    pass


class CheckRuleError(Error, ValueError):

    def __init__(self, check, values):
        self.check = check
        self.values = values

    def __str__(self):
        return str(self.check)


def check(*rules, **parsers):
    def _check(func):
        def __check(*args, **kwds):
            kwds = inspect.getcallargs(func, *args, **kwds)
            for name, parse in parsers.iteritems():
                kwds[name] = parse(kwds[name])
            for rule in rules:
                if isinstance(rule, Expression):
                    if not rule.compute(**kwds):
                        raise CheckError(rule, kwds)
                elif isinstance(rule, tuple):
                    for rl in rule:
                        if isinstance(rl, Expression):
                            if not rl.compute(**kwds):
                                raise CheckError(rl, kwds)
                        else:
                            raise TypeError(lang.CHECK_WRONG_SUBRULE_TYPE % type(rl))
                else:
                    raise TypeError(lang.CHECK_WRONG_RULE_TYPE % type(rule))
            return func(**kwds)
        return __check
    return _check


def result(*rules):
    def _result(func):
        def __result(*args, **kwds):
            res = func(*args, **kwds)
            for rule in rules:
                if isinstance(rule, Expression):
                    if not rule.compute(x=res):
                        raise CheckError(rule, kwds)
                elif isinstance(rule, tuple):
                    for rl in rule:
                        if isinstance(rl, Expression):
                            if not rl.compute(x=res):
                                raise CheckError(rl, kwds)
                        else:
                            raise TypeError(lang.CHECK_WRONG_SUBRULE_TYPE % type(rl))
                else:
                    raise TypeError(lang.CHECK_WRONG_RULE_TYPE % type(rule))
        return __result
    return _result


class LimitError(CheckRuleError):
    pass


LIMITS = {}


def delimit(limit_name):
    limits = LIMITS.get(limit_name, None)
    def _delimit(func):
        if limits is None:
            return func
        parsers = {}
        in_limits = out_limits = ()
        lit = iter(limits)
        try:
            parsers = lit.next()
            in_limits = lit.next()
            out_limits = lit.next()
        except StopIteration:
            pass
        if not parsers and not in_limits and not out_limits:
            return func
        def __delimit(*args, **kwds):
            kwds = inspect.getcallargs(func, *args, **kwds)
            # parse args
            for name, parse in parsers.iteritems():
                kwds[name] = parse(kwds[name])
            # check args
            for rule in in_limits:
                if isinstance(rule, Expression):
                    if not rule.compute(**kwds):
                        raise LimitError(rule, kwds)
                elif isinstance(rule, tuple):
                    for rl in rule:
                        if isinstance(rl, Expression):
                            if not rl.compute(**kwds):
                                raise LimitError(rl, kwds)
                        else:
                            raise TypeError(lang.CHECK_WRONG_SUBRULE_TYPE % type(rl))
                else:
                    raise TypeError(lang.CHECK_WRONG_RULE_TYPE % type(rule))
            # check result
            res = func(**kwds)
            for rule in out_limits:
                if isinstance(rule, Expression):
                    if not rule.compute(x=res):
                        raise LimitError(rule, kwds)
                elif isinstance(rule, tuple):
                    for rl in rule:
                        if isinstance(rl, Expression):
                            if not rl.compute(x=res):
                                raise LimitError(rl, kwds)
                        else:
                            raise TypeError(lang.CHECK_WRONG_SUBRULE_TYPE % type(rl))
                else:
                    raise TypeError(lang.CHECK_WRONG_RULE_TYPE % type(rule))
            return res
        return __delimit
    return _delimit

