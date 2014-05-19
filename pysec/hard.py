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
"""Utilities for disk ADT or operation"""
import os.path
import struct

from pysec.io import fd


def hcounter(fpath):
    """Make a file in fpath where store the last state of the counter."""
    fpath = os.path.abspath(fpath)
    with fd.File.open(fpath, fd.FO_WRITE) as fwr:
        if fwr.size:
            with fd.File.open(fpath, fd.FO_READ) as frd:
                index = struct.unpack('!Q', frd[:8])[0]
        else:
            fwr.pwrite('\x00' * 8, 0)
            index = 0
        while 1:
            index += 1
            fwr.pwrite(struct.pack('!Q', index), 0)
            yield index

