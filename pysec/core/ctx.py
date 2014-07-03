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

from pysec.core import Object


__all__ = 'Context',


CONTEXTS = {'file', 'cmd', 'html', 'js'}


class Context(Object):

    def __init__(self, name='none', info=None, locs=None):
        name = str(name)
        self.name = name
        self.info = {} if info is None else dict(info)
        CONTEXTS.add(name)

    def __enter__(self):
        frame = sys._getframe().f_back
        contexts = frame.f_locals.setdefault('__ctx__', [])
        contexts.append(self)

    def __exit__(self, exc_type, exc_value, exc_tb):
        sys._getframe().f_back.__ctx__.pop()
        return 0

    def contexts(self):
        frame = sys._getframe().f_back
        while frame:
            ls = frame.f_locals.get('__ctx__', None)
            if ls:
                for ctx in ls:
                    yield ctx
        frame = sys._getframe().f_back

