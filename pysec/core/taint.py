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
import types


class Taint(type):

    def __new__(cls, name, bases, attrs):
        if '__tainted__' in attrs:
            raise AttributeError("__taint__ attribute is a special method for Taint metaclass")
        if '__tainttags__' in attrs:
            raise AttributeError("__tainttags__ attribute is a special method for Taint metaclass")
        def taint_dec(func):
            def _taint_dec(*args, **kwds):
                tainted = 0
                tags = []
                for arg in args:
                    tainted = tainted or getattr(arg, '__tainted__', 0)
                    tags.extend(getattr(arg, '__tainttags__', ()))
                for arg in kwds.itervalues():
                    tainted = tainted or getattr(arg, '__tainted__', 0)
                    tags.extend(getattr(arg, '__tainttags__', ()))
                res = func(*args, **kwds)
                res.__tainted__ = tainted
                res.__tags__ = tags
                return res
            return _taint_dec
        newattrs = {key: (taint_dec(val) if isinstance(val, (types.BuiltinMethodType, types.MethodType, types.FunctionType)) else val)
                    for key, val in attrs.iteritems()}
        newattrs['__tainted__'] = 0
        newattrs['__tainttags__'] = []
        return super(Taint, cls).__new__(cls, name, bases, attrs)


def is_tainted(obj):
    return hasattr(obj, '__tainted__') or None


def taint_tags(obj):
    return getattr(obj, '__tainttags__', ())


def taint(obj, *tags):
    if hasattr(obj, '__tainted__') and hasattr(obj, '__tainttags__'):
        obj.__tainted__ = 1
        obj.__tainttags__.extends(str(tag) for tag in tags)
    else:
        raise TypeError("%r is not a taint tracked object" % obj)

