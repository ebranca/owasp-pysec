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
"""Utilities for pysec.io functions"""
import os


__all__ = 'filter_by_mtime', 'filter_by_atime', 'filter_by_ctime'


def filter_by_mtime(start, end):
    def _filter_by_mtime(path):
        return start <= os.stat(path).st_mtime <= end
    return _filter_by_mtime


def filter_by_atime(start, end):
    def _filter_by_atime(path):
        return start <= os.stat(path).st_atime <= end
    return _filter_by_atime


def filter_by_ctime(start, end):
    def _filter_by_ctime(path):
        return start <= os.stat(path).st_ctime <= end
    return _filter_by_ctime

