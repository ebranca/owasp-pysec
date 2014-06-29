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
"""Module to manage more efficently import of modules"""
# ASCII_LETTERS = <str>
# DIGITS = <str>
# HEXDIGITS = <str>
# ModuleType = <type>
# _CACHE = {(<str>,<tuple>): <module>}
# _FIRST_LETTERS = <str>
# _HASHES = {<str>: <built-in function>}
# _OTHER_LETTERS = <str>
# _TAB = {<str>: <dict>}
# base64 = <module base64>
# fd = <module pysec.io.fd>
# hashlib = <module hashlib>
# imp = <module imp>
# os = <module os>
import imp
import os
import hashlib
import base64
from types import ModuleType

from pysec.core import Object
from pysec.io import fd
from pysec import log
from pysec import lang


__name__ = 'pysec.load'

__all__ = 'load_tab', 'importlib', 'make_line'


# set actions
log.register_actions('LOAD_TAB', 'IMPORT_LIB')


ASCII_LETTERS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
DIGITS = '0123456789'
HEXDIGITS = '0123456789abcdefABCDEF'


_HASHES = {
    # raise NameError: undefined: getattr
    'md5': getattr(hashlib, 'md5'),
    # raise NameError: undefined: getattr
    'sha1': getattr(hashlib, 'sha1'),
    # raise NameError: undefined: getattr
    'sha256': getattr(hashlib, 'sha256'),
    # raise NameError: undefined: getattr
    'sha512': getattr(hashlib, 'sha512'),
}


_FIRST_LETTERS = '_%s' % ASCII_LETTERS
_OTHER_LETTERS = '_%s%s' % (ASCII_LETTERS, DIGITS)


def is_hex(string):
    """Returns True if string is a valid hexadecimal number, otherwise False"""
    # string = <str>
    # ch = <str>
    # return <bool>
    return all(ch in HEXDIGITS for ch in string)


def check_libname(name):
    """Returns True if name is a valid string for a library, other False"""
    # name = <str>
    # ch = <str>
    # return <int>|<bool>
    name = str(name)
    if not name:
        return 0
    return (name[0] in _FIRST_LETTERS and
            all(ch in _OTHER_LETTERS for ch in name[1:]))


def parse_version(version):
    """Parse version string in a tuple, if version is an invalid string
    returns None"""
    # version = <str>
    # vs = <str>
    # return <NoneType>|(*<int>)
    version = str(version).split('.')
    if len(version) != 3:
        return None
    if all(vs.isdigit() for vs in version):
        return tuple(int(vs) for vs in version)
    return None


def parse_hashes(hashes):
    """Parse hashes' string in hashes' dict, if it's invalid returns None"""
    # hashes = <str>
    # _hashes = {<NoneType>: ?}
    # hname = <str>
    # hs_field = <str>
    # hval = <str>
    # return {<str>: <str>}|<NoneType>
    _hashes = {}
    if hashes:
        for hs_field in hashes.split(' '):
            hname, _, hval = hs_field.strip().partition(':')
            hs_field = _HASHES.get(hname, None)
            if hs_field is None:
                return None
            if not is_hex(hval):
                return None
            if hs_field in _hashes:
                return None
            _hashes[hs_field] = hval
    return _hashes


def _hash(path, hs_obj):
    """Calculate the hash of path using hs_obj (a Hash Object)"""
    # path = <str>
    # hs_obj = <HASH object>
    # chunk = <str>
    # fmod = <file>
    # return <NoneType>
    with fd.File.open(path, fd.FO_READEX) as fmod:
        chunk = fmod.read(4096)
        while chunk:
            hs_obj.update(chunk)
            chunk = fmod.read(4096)


def get_hash(path, hs_maker):
    """Calculates the hash of module in path"""
    # path = <str>
    # hs_maker = <function>
    # dirpath = <str>
    # filenames = [<str>]
    # files = [<str>]
    # fname = <str>
    # fpath = <str>
    # hs_mod = <HASH object>
    # return <str>
    hs_mod = hs_maker()
    if os.path.isfile(path):
        files = [path]
    elif os.path.isdir(path):
        files = sorted([os.path.join(dirpath, fname)
                       for dirpath, _, filenames in os.walk(path)
                       for fname in filenames
                       if os.path.isfile(os.path.join(dirpath, fname))])
    else:
        # raise <instance ImportError>
        raise ImportError("invalid file type %r" % path)
    for fpath in files:
        _hash(fpath, hs_mod)
    return hs_mod.hexdigest()


_CACHE = {}
_TAB = {}


class _LazyModule(Object, ModuleType):
    """_LazyModule is a module that instances their attribute in lazy mode"""
    # instance.module = <NoneType>|<module>
    # instance.name = <str>

    def __init__(self, name, version):
        # self = <instance load._LazyModule>
        # name = <str>
        # version = (*<int>)
        # return <NoneType>
        self.name = str(name)
        self.version = version
        self.module = None

    def __getattr__(self, name):
        # self = <instance load._LazyModule>
        # name = <str>
        # return <module>
        # raise NameError: undefined: getattr
        return getattr(self.module or importlib(self.name, self.version), name)

    def __setattr__(self, name, value):
        # self = <instance load._LazyModule>
        # name = <str>
        # value = ?
        # return <NoneType>
        setattr(self.module or importlib(self.name, self.version), name, value)

    def __delattr__(self, name):
        # self = <instance load._LazyModule>
        # name = <str>
        # return <NoneType>
        delattr(self.module or importlib(self.name, self.version), name)


@log.wrap(log.actions.LOAD_TAB, fields=('path',), lib=__name__)
def load_tab(path):
    """Updates internal tab of modules"""
    # path = <str>
    # _tab = {<str>: <dict>}
    # fields = <str>
    # ftab = <instance pysec.io.fd.File>
    # hashes = {<str>: <str>}|<NoneType>
    # line = <str>
    # lineno = <int>
    # mod_vers = {<str>: <dict>}
    # name = <str>
    # version = <NoneType>|(*<int>)
    # return <NoneType>
    path = os.path.abspath(str(path))
    _tab = {}
    with fd.File.open(path, fd.FO_READEX) as ftab:
        for lineno, line in enumerate(ftab.lines()):
            fields = line.strip().split(';')
            # name, version, path, hashes
            if len(fields) != 4:
                # raise <instance ImportError>
                raise ImportError(lang.LOAD_WRONG_FIELDS % lineno)
            name, version, path, hashes = fields
            # name
            if not check_libname(name):
                # raise <instance ImportError>
                raise ImportError(lang.LOAD_WRONG_LIB_NAME % lineno)
            # version
            version = parse_version(version)
            if version is None:
                # raise <instance ImportError>
                raise ImportError(lang.LOAD_WRONG_VERSION_FORMAT % lineno)
            # path
            path = os.path.abspath(base64.b64decode(path))
            # hashes
            hashes = parse_hashes(hashes)
            if hashes is None:
                # raise <instance ImportError>
                raise ImportError(lang.LOAD_WRONG_HASH_FORMAT % lineno)
            # update tab
            mod_vers = _tab.setdefault(name, {})
            if version in mod_vers:
                # raise <instance ImportError>
                raise ImportError(lang.LOAD_DUP_LIB
                                  % (name, version[0], version[1], version[2]))
            mod_vers[version] = {'path': path, 'hash': hashes}
    _TAB.update(_tab)


@log.wrap(log.actions.IMPORT_LIB,
          fields=('name', 'version', 'lazy', '_reload'),
          result='module', lib=__name__)
def importlib(name, version=None, lazy=0, _reload=0):
    """Load a library and return it.
    name        library's name
    version     if it's None it load lastest library, otherwise load the
                version specified
    lazy        if false it returns normal module, otherwise it returns a
                module placeholder and it will be loaded the first time that
                it will be used
    _reload     if false search library in cache and returns it if exists
                otherwise it load it. If _reload is true load library anse save
                it in cache
    """
    # name = <str>
    # version = <NoneType>
    # lazy = <int>
    # _reload = <int>
    # desc = <tuple>
    # fdir = <str>
    # fname = <str>
    # fobj = <file>
    # hs_maker = <function>
    # hval = <str>
    # mod = <NoneType>
    # mod_info = {<function>: <str>}
    # path = <str>
    # vers = <NoneType>
    # return <instance load._LazyModule>
    name = str(name)
    vers = _TAB.get(name, None)
    if vers is None:
        # raise <instance ImportError>
        raise ImportError(lang.LOAD_LIB_NOT_FOUND % name)
    if version is None:
        version = max(vers.iterkeys())
    elif version not in vers:
        # raise <instance ImportError>
        raise ImportError(lang.LOAD_LIB_VER_NOT_FOUND % (name, version))
    if not _reload and (name, version) in _CACHE:
        return _CACHE[(name, version)]
    mod_info = vers.get(version)
    try:
        imp.acquire_lock()
        path = mod_info['path']
        if lazy:
            return _LazyModule(name, path)
        else:
            fdir, fname = os.path.split(path)
            for hs_maker, hval in mod_info['hash'].iteritems():
                if get_hash(path, hs_maker) != hval:
                    # raise <instance ImportError>
                    raise ImportError(lang.LOAD_INVALID_HASH
                                      % (name, version, path, hval))
            # raise <instance ImportError>
            fobj, path, desc = imp.find_module(os.path.splitext(fname)[0],
                                               [fdir])
            # raise <instance ImportError>
            mod = imp.load_module(name, fobj, path, desc)
            _CACHE[(name, version)] = mod
            return mod
    finally:
        imp.release_lock()


def make_line(path, name, version):
    """Makes a complete string for loader's file"""
    # path = <str>
    # name = <str>
    # version = (*<int>)
    # hashes = [<str>]
    # hs_func = <function>
    # hs_name = <str>
    # path64 = <str>
    # vs = <int>
    # return <str>
    path = os.path.abspath(path)
    path64 = base64.b64encode(path)
    name = str(name)
    version = tuple(version)
    hashes = []
    for hs_name, hs_func in _HASHES.iteritems():
        hashes.append('%s:%s' % (hs_name, get_hash(path, hs_func)))
    return '%s;%s;%s;%s' % (str(name), '.'.join(str(vs) for vs in version),
                            path64, ' '.join(hashes))
