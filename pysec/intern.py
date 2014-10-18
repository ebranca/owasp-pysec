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
import sys


FRAME_EXEC = 'exec'
FRAME_MODULE = 'module'
FRAME_CLASS = 'class'
FRAME_FUNCTION = 'function'
FRAME_UNKNOWN = 'unknown'


def get_frame_type(frame=None, get_module=None):
    """Return information about a frame: (frame_type, module)

    *type* could be: FRAME_EXEC, FRAME_MODULE, FRAME_CLASS,
                     FRAME_FUNCTION, FRAME_UNKNOWN

    If *frame* is None, the caller frame will be used.
    If *get_module* is None, the module will be searched in sys.path.
    If *get_module* don't find the module, it must return None.
    """
    if frame is None:
        frame = sys._getframe().f_back
    f_locals = frame.f_locals
    f_globals = frame.f_globals

    same_namespace = f_locals is f_globals
    loc_module = f_locals.get('__module__', None)
    glb_name = f_globals.get('__name__', None)

    same_name = loc_module and glb_name and loc_module == glb_name

    if get_module is None:
        get_module = lambda mod: sys.modules.get(mod, None)
    module = get_module(glb_name)

    if not (module and module.__dict__ is f_globals):
        ftype = FRAME_EXEC
    elif same_namespace and not loc_module:
        ftype = FRAME_MODULE
    elif same_name and not same_namespace:
        ftype = FRAME_CLASS
    elif not same_namespace:
        ftype = FRAME_FUNCTION
    else:
        ftype = FRAME_UNKNOWN
    return ftype

