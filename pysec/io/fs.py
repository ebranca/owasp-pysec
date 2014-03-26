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
"""Utilities for File System operations"""
from pysec.io import fd


def get_fd_usage():
    """Returns a tuple
        (allocated file handles, vailable file handles, max file handles)
    """
    with fd.File.open('/proc/sys/fs/file-nr', fd.FO_READEX) as fnr:
        line = fnr.readline()
        fields = line.strip().split()
        if len(fields) != 3:
            raise OSError("wrong format of '/proc/sys/fs/file-nr'")
        return tuple(fields)
