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
"""Traceback utilities."""
import keyword
import tokenize
import sys

from pysec.core import Object
from pysec.xsplit import xlines


NORESULT = object()

SCOPE_BUILTIN = 'builtin'
SCOPE_GLOBAL = 'global'
SCOPE_LOCAL = 'local'


def getvar(name, frame=None):
    """Search a name in local scope, global scope, and in builtins"""
    if frame is None:
        frame = sys._getframe().f_back
    val = frame.f_locals.get(name, NORESULT)
    if val is not NORESULT:
        return SCOPE_LOCAL, val
    val = frame.f_locals.get(name, NORESULT)
    if val is not NORESULT:
        return SCOPE_GLOBAL, val
    builtins = frame.f_globals.get('__builtins__', NORESULT)
    if builtins is not NORESULT:
        if type(builtins) is type({}):
            val = builtins.get(name, NORESULT)
            if val is not NORESULT:
                return SCOPE_BUILTIN, val
        else:
            val = getattr(builtins, name, NORESULT)
            if val is not NORESULT:
                return SCOPE_BUILTIN, val
    return None, None


class StringReadline(Object):

    def __init__(self, text):
        self.lines = xlines(text, eol='\n', keep_eol=1)

    def readline(self):
        try:
            return self.lines.next()
        except StopIteration:
            return ''

NOVAL = object()

def linevars(code, frame=None):
    if frame is None:
        frame = sys._getframe().f_back
    last = None
    parent = None
    prefix = ''
    value = NOVAL
    for tok_type, token, start, end, line in tokenize.generate_tokens(StringReadline(code)):
        if tok_type == tokenize.NEWLINE:
            break
        elif tok_type == tokenize.NAME and token not in keyword.kwlist:
            if last == '.':
                if parent is not NOVAL:
                    value = getattr(parent, token, NOVAL)
                    yield prefix + token, prefix, value
            else:
                where, value = getvar(token, frame)
                yield token, where, value
        elif token == '.':
            prefix = '%s%s.' % (prefix, last)
            parent = value
        else:
            parent = None
            prefix = ''
        last = token


class Hook(Object):

    def __init__(self, formatter, out=sys.stderr):
        self.out = out
        self.formatter = formatter

    def __call__(self, exc_type, exc_val, exc_tb):
        self.handle((exc_type, exc_val, exc_tb))

    def handle(self, info=None):
        self.out.write(self.formatter(info or sys.exc_info()))
        self.out.write('\n')



def reset_exceptook():
    sys.excepthook = sys.__excepthook__

