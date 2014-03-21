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
import os as _os
import errno as _errno
from tempfile import _get_candidate_names, _set_cloexec, TMP_MAX
import fd


def mkstemp(dir, prefix, suffix):
    dir = _os.path.abspath(dir)
    names = _get_candidate_names()
    for seq in xrange(TMP_MAX):
        name = names.next()
        file = _os.path.join(dir, '%s%s%s' % (prefix, name, suffix))
        fdr = fdw = -1
        try:
            fdr = _os.open(file, _os.O_RDONLY | _os.O_CREAT | _os.O_EXCL, 0600)
            fdw = _os.open(file, _os.O_WRONLY, 0600)
            # _os.unlink(file)
            _set_cloexec(fdr)
            _set_cloexec(fdw)
            return fd.File(fdr), fd.File(fdw)
        except OSError, e:
            if fdr != -1:
                _os.close(fdr)
            if fdw != -1:
                _os.close(fdw)
            if e.errno == _errno.EEXIST:
                # try again
                continue
            raise
    raise IOError(_errno.EEXIST, "No usable temporary file name found")


def mkdtemp(dir, prefix, suffix):
    dir = _os.path.abspath(dir)
    names = _get_candidate_names()
    for seq in xrange(TMP_MAX):
        name = names.next()
        file = _os.path.join(dir, '%s%s%s' % (prefix, name, suffix))
        try:
            _os.mkdir(file, 0700)
            return file
        except OSError, e:
            if e.errno == _errno.EEXIST:
                # try again
                continue
            raise
    raise IOError(_errno.EEXIST, "No usable temporary directory name found")
