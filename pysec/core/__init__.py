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
from pysec.core import taint

_dict = type({})
_list = type([])
_set = type({1, 2})
_str = type('')
_tuple = type(())



class Object(object):

    __metaclass__ = taint.Taint


class Error(Object, Exception):
    pass


class String(Object, _str):
    pass


class List(Object, _list):
    pass


class Dict(Object, _dict):
    pass


class Set(Object, _set):
    pass


class Tuple(Object, _tuple):
    pass



def all_attrs(obj):
    tp = type(obj)
    return {attr for cls in (getattr(tp, '__mro__', None) or (getattr(tp, '__bases__', ()) + (tp,))) for attr in cls.__dict__ }


NO_OBJ = object()


def is_duck(obj, duck=NO_OBJ, *args):
    if duck is NO_OBJ:
        args = set(args)
    else:
        if args:
            raise ValueError()
        args = all_attrs(duck)
    return all_attrs(obj) == args


def is_superduck(obj, duck=NO_OBJ, *args):
    if duck is NO_OBJ:
        args = set(args)
    else:
        if args:
            raise ValueError()
        args = all_attrs(duck)
    return all_attrs(obj) >= args


def is_subduck(obj, duck=NO_OBJ, *args):
    if duck is NO_OBJ:
        args = set(args)
    else:
        if args:
            raise ValueError()
        args = all_attrs(duck)
    return all_attrs(obj) <= args


def is_int(obj):
    return isinstance(obj, (int, long))


def is_str(obj):
    return isinstance(obj, (_str, String))


def is_dict(obj):
    return isinstance(obj, (_dict, Dict))
