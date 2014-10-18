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
"""PySec is a set of tools for secure application development under Linux"""
import sys

from pysec import config
from pysec import core
from pysec.io import fd
from pysec import lang
from pysec import log
from pysec import tb
from pysec import utils


REMOVE_BUILTINS = 'eval', 'execfile'

Object = core.Object
Error = core.Error


def set_builtins():
    _OPEN_MODES = {
        'r': fd.FO_READEX,
        'w': fd.FO_WRITE,
        'a': fd.FO_APPEND
    }
    def open(path, mode='r'):
        _mode = _OPEN_MODES.get(str(mode), None)
        if _mode is None:
            raise ValueError(lang.WRONG_OPEN_MODE % mode)
        return fd.File.open(path, _mode)
    BUILTINS = {
        # 'dict': core.Dict,
        'file': open,
        'input': raw_input,
        'list': core.List,
        'object': core.Object,
        'open': open,
        # 'set': core.Set,
        # 'str': core.String,
        # 'tuple': core.Tuple,
        'xrange': utils.xrange,
        'range': utils.range
    }
    def not_implemented(name):
        def _not_implemented(*arg, **kwds):
            raise NotImplementedError("builtin %r was disabled by PySec" % name)
        return _not_implemented
    builtins = {}
    for key, value in __builtins__.iteritems():
        builtins[key] = BUILTINS.get(key, None) or \
                        (not_implemented(key) if key in REMOVE_BUILTINS else __builtins__[key])
    __builtins__.clear()
    __builtins__.update(builtins)


def init(name=__name__, fields=None, timer=None, emitter=log.emit_simple, save_actions=None, save_errors=None, hook_tb=tb.long_tb):
    if isinstance(name, tuple):
        name, code = name
        code = log.register_action(str(name), int(code))
    else:
        code = log.register_action(name)
    log.start_root_log(code, fields, timer)
    if emitter:
        log.add_global_emit(emitter)
    sys.path = []
    set_builtins()
    tb.set_excepthook(hook_tb)
    #
    if save_errors:
        log.save_errors(save_errors)
    if save_actions:
        log.save_actions(save_actions)

