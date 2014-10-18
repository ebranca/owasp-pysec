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
import dis
import keyword
import opcode
import os
import sys
import tokenize

from pysec.core import Object
from pysec.io import fd
from pysec.strings import erepr
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
    val = frame.f_globals.get(name, NORESULT)
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
    for tok_type, token, start, end, line in tokenize.generate_tokens(StringReadline(code).readline):
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
        self.out.write(self.formatter(*(info or sys.exc_info())))
        self.out.flush()


def set_excepthook(fmt, out=sys.stderr):
    sys.excepthook = Hook(fmt, out)


def reset_excepthook():
    sys.excepthook = sys.__excepthook__


# Utilities to format traceback

# inspired by dis.disassemble() in Python 2.7
def disassemble(co):
    code = co.co_code
    labels = dis.findlabels(code)
    linestarts = dict(dis.findlinestarts(co))
    n = len(code)
    i = 0
    extended_arg = 0
    free = None
    lineno = None
    while i < n:
        c = code[i]
        op = ord(c)
        lineno = linestarts.get(i, lineno)
        is_label = i in labels
        ist = i
        i += 1
        if op >= opcode.HAVE_ARGUMENT:
            oparg = ord(code[i]) + ord(code[i + 1]) * 256 + extended_arg
            extended_arg = 0
            i += 2
            if op == opcode.EXTENDED_ARG:
                extended_arg = oparg * 65536L
            if op in opcode.hasconst:
                arg = co.co_consts[oparg]
            elif op in opcode.hasname:
                arg = co.co_names[oparg]
            elif op in opcode.hasjrel:
                arg = i + oparg
            elif op in opcode.haslocal:
                arg = co.co_varnames[oparg]
            elif op in opcode.hascompare:
                arg = opcode.cmp_op[oparg]
            elif op in opcode.hasfree:
                if free is None:
                    free = co.co_cellvars + co.co_freevars
                arg = free[oparg]
            else:
                arg = NOVAL
        else:
            arg = NOVAL
        yield ist, lineno, is_label, opcode.opname[op], arg


def short_tb(exc_type, exc_value, exc_tb):
    traceback = []
    while exc_tb:
        traceback.append('{%r, %r, %r}' % (exc_tb.tb_frame.f_code.co_filename,
                                           exc_tb.tb_frame.f_code.co_name,
                                           exc_tb.tb_lineno))
        exc_tb = exc_tb.tb_next
    return 'Traceback: %s\nError: %s %r\n' % (' -> '.join(traceback), exc_type.__name__, str(exc_value))


def long_tb(exc_type, exc_value, exc_tb, max_length=80):
    traceback = ['Traceback (most recent call last):']
    lvl = 0
    while exc_tb:
        path = os.path.abspath(exc_tb.tb_frame.f_code.co_filename)
        lineno = exc_tb.tb_lineno - 1
        traceback.append('[%d]' % lvl)
        traceback.append('  Where: %r:%d %r' % (path, lineno+1, exc_tb.tb_frame.f_code.co_name))
        with fd.File.open(path, fd.FO_READEX) as src:
            line = src.get_line(lineno)
        traceback.append('  Line: %r' % line.strip())
        traceback.append('  Variables:')
        for token, where, val in linevars(line.strip(), exc_tb.tb_frame):
            if where is None:
                val = '<undefined>'
            val = repr(val)
            traceback.append('    %r: %s' % (token, '%s...' % val[:max_length] if len(val) > max_length else val))
        exc_tb = exc_tb.tb_next
        lvl += 1
    return '%s\n[ERROR]\n%s: %r\n' % ('\n'.join(traceback), exc_type.__name__, str(exc_value))


def deep_tb(exc_type, exc_value, exc_tb):
    traceback = ['=== Traceback (most recent call last) ===']
    lvl = 0
    while exc_tb:
        path = os.path.abspath(exc_tb.tb_frame.f_code.co_filename)
        lineno = exc_tb.tb_lineno
        traceback.append('[%d]' % lvl)
        traceback.append('  File: %r' % path)
        traceback.append('  Function: %r' % exc_tb.tb_frame.f_code.co_name)
        with fd.File.open(path, fd.FO_READEX) as src:
            line = src.get_line(lineno - 1)
        traceback.append('  Line: (%d) %r' % (lineno, line.strip()))
        traceback.append('  Variables:')
        for token, where, val in linevars(line.strip(), exc_tb.tb_frame):
            if where is None:
                val = '<undefined>'
            else:
                val = '[%s] %r' % (erepr(getattr(type(val), '__name__', type(val))), val)
            traceback.append('    %r: %s' % (token, val))
        traceback.append('  Code:')
        for ist, lineno, label, op, arg in disassemble(exc_tb.tb_frame.f_code):
            prefix = '>> ' if ist == exc_tb.tb_lasti else '   '
            postfix = ' << %s' % exc_type.__name__ if ist == exc_tb.tb_lasti else ''
            if lineno == exc_tb.tb_lineno:
                if arg is NOVAL:
                    traceback.append('  %s%s%s' % (prefix, op, postfix))
                else:
                    traceback.append('  %s%s %r%s' % (prefix, op, arg, postfix))
        exc_tb = exc_tb.tb_next
        lvl += 1
    traceback.append('[ERROR]')
    traceback.append('%s: %r' % (exc_type.__name__, str(exc_value)))
    traceback.append('=========================================\n')
    return '\n'.join(traceback)

