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
from pysec import lang
from pysec.io import fd
from pysec.utils import xrange


BUFSIZE = 4096


def write_and_check(path, size, filler, checksum, padding='\0'):
    original = checksum()
    final = checksum()
    if len(padding) != 1:
        raise ValueError(lang.WRONG_ONE_CHAR_STRING % padding)
    with fd.File.open(path, fd.FO_WRNEW) as fp:
        written = 0
        for data in filler:
            data = str(data)
            data_len = len(data)
            if written + data_len > size:
                data = data[:size-written]
            fp.write(data)
            original.update(data)
            written += data_len
        if written < size:
            for _ in xrange(0, size - written):
                fp.write(padding)
                original.update(padding)
    with fd.File.open(path, fd.FO_READEX) as fp:
        if len(fp) != size:
            return 0
        read = 0
        while read < size:
            chunk = fp.read(BUFSIZE)
            final.update(chunk)
            if not chunk:
                return 0
            read += len(chunk)
        if size % BUFSIZE:
            chunk = fp.read(BUFSIZE)
            final.update(chunk)
        if fp.read(1):
            return 0
    return original.digest() == final.digest()

