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
"""Utilities to create temporary files or directories"""
import os
import errno
import atexit
from tempfile import _get_candidate_names, _set_cloexec, TMP_MAX
from pysec.io import fd
from pysec.io import fcheck




def mkshide(dirpath):
    """Create a file without path"""
    raise NotImplementedError
    # open with O_TMPFILE flag in linux 3.11
    # or open and unlink immediately


def mkstemp(dirpath, prefix='', suffix='', unlink=1, mode=0600):
    """Creates a file in directory *dir* using *prefix* and *suffix* to
    name it:
            (dir)/<prefix><random_string><postfix>
    Returns a couple of files (pysec.io.fd.File):
            (Read_File, Write_File)
    If *unlink* is true registers a unlink function at exit.
    """
    dirpath = os.path.abspath(dirpath)
    mode = int(mode)
    if not fcheck.mode_check(mode):
        raise ValueError("wrong mode: %r" % oct(mode))
    names = _get_candidate_names()
    for _ in xrange(TMP_MAX):
        name = names.next()
        fpath = os.path.join(dirpath, '%s%s%s' % (prefix, name, suffix))
        if unlink:
            atexit.register(os.unlink, fpath)
        fdr = fdw = -1
        try:
            fdr = os.open(fpath, os.O_RDONLY | os.O_CREAT | os.O_EXCL, mode)
            fdw = os.open(fpath, os.O_WRONLY, mode)
            _set_cloexec(fdr)
            _set_cloexec(fdw)
            return fd.File(fdr), fd.File(fdw)
        except OSError, ex:
            if fdr != -1:
                os.close(fdr)
            if fdw != -1:
                os.close(fdw)
            if ex.errno == errno.EEXIST:
                continue
            else:
                try:
                    os.unlink(fpath)
                except IOError:
                    pass
            raise
        except:
            if fdr != -1:
                os.close(fdr)
            if fdw != -1:
                os.close(fdw)
            try:
                os.unlink(fpath)
            except IOError:
                pass
            raise
    raise IOError(errno.EEXIST, "No usable temporary file name found")


def mkdtemp(dirpath, prefix='', suffix='', mode=0700):
    """Creates a directory in directory *dir* using *prefix* and *suffix* to
    name it:
            (dir)/<prefix><random_string><postfix>
    Returns absolute path of directory.
    """
    dirpath = os.path.abspath(dirpath)
    names = _get_candidate_names()
    mode = int(mode)
    if not fcheck.mode_check(mode):
        raise ValueError("wrong mode: %r" % oct(mode))
    for _ in xrange(TMP_MAX):
        name = names.next()
        fpath = os.path.abspath(os.path.join(dirpath, '%s%s%s'
                                % (prefix, name, suffix)))
        try:
            os.mkdir(fpath, mode)
            return fpath
        except OSError, ex:
            if ex.errno == errno.EEXIST:
                # try again
                continue
            raise
    raise IOError(errno.EEXIST, "No usable temporary directory name found")
