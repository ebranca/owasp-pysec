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
"""Module to manage more efficently import of modules"""
import imp
import os
import hashlib
import base64
from types import ModuleType
from pysec.io import fd


ASCII_LETTERS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
DIGITS = '0123456789'
HEXDIGITS = '0123456789abcdefABCDEF'


_HASHES = {
    'md5': getattr(hashlib, 'md5'),
    'sha1': getattr(hashlib, 'sha1'),
    'sha256': getattr(hashlib, 'sha256'),
    'sha512': getattr(hashlib, 'sha512'),
}


_FIRST_LETTERS = '_%s' % ASCII_LETTERS
_OTHER_LETTERS = '_%s%s' % (ASCII_LETTERS, DIGITS)


def is_hex(string):
    """Returns True if string is a valid hexadecimal number, otherwise False"""
    return all(ch in HEXDIGITS for ch in string)


def check_libname(name):
    """Returns True if name is a valid string for a library, other False"""
    name = str(name)
    if not name:
        return 0
    return (name[0] in _FIRST_LETTERS and
            all(ch in _OTHER_LETTERS for ch in name[1:]))


def parse_version(version):
    """Parse versione string in a tuple, if version is an invalid string
    returns None"""
    version = str(version).split('.')
    if len(version) != 3:
        return None
    if all(vs.isdigit() for vs in version):
        return tuple(int(vs) for vs in version)
    return None


def parse_hashes(hashes):
    """Parse hashes's string in hashes's dict, if it's invalid returns None"""
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
    with open(path, 'rb') as fmod:
        chunk = fmod.read(4096)
        while chunk:
            hs_obj.update(chunk)
            chunk = fmod.read(4096)


def get_hash(path, hs_maker):
    """Calculates the hash of module in path"""
    hs_mod = hs_maker()
    if os.path.isfile(path):
        files = [path]
    elif os.path.isdir(path):
        files = sorted([os.path.join(dirpath, fname)
                       for dirpath, _, filenames in os.walk(path)
                       for fname in filenames
                       if os.path.isfile(os.path.join(dirpath, fname))])
    else:
        raise ImportError("invalid file type %r" % path)
    for fpath in files:
        _hash(fpath, hs_mod)
    return hs_mod.hexdigest()


_CACHE = {}
_TAB = {}


class _LazyModule(ModuleType):
    """_LazyModule is a module that instances their attribute in lazy mode"""

    def __init__(self, name, version):
        self.name = str(name)
        self.version = version
        self.module = None

    def __getattr__(self, name):
        return getattr(self.module or importlib(self.name, self.version), name)

    def __setattr__(self, name, value):
        return setattr(self.module or importlib(self.name, self.version),
                       name, value)

    def __delattr__(self, name):
        return delattr(self.module or importlib(self.name, self.version), name)


def load_tab(path):
    """Updates internal tab of modules"""
    path = os.path.abspath(str(path))
    _tab = {}
    with fd.File.open(path, fd.FO_READ) as ftab:
        for lineno, line in enumerate(ftab.lines()):
            fields = line.strip().split(';')
            # name, version, path, hashes
            if len(fields) != 4:
                raise ImportError("wrong number of fields at line %d" % lineno)
            name, version, path, hashes = fields
            # name
            if not check_libname(name):
                raise ImportError("wrong library name at line %d" % lineno)
            # version
            version = parse_version(version)
            if version is None:
                raise ImportError("wrong version format at line %d" % lineno)
            # path
            path = os.path.abspath(base64.b64decode(path))
            # hashes
            hashes = parse_hashes(hashes)
            if hashes is None:
                raise ImportError("wrong hash format at line %d" % lineno)
            # update tab
            mod_vers = _tab.setdefault(name, {})
            if version in mod_vers:
                raise ImportError("duplicated library: %r %d.%d.%d"
                                  % (name, version[0], version[1], version[2]))
            mod_vers[version] = {'path': path, 'hash': hashes}
    _TAB.update(_tab)


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
    name = str(name)
    vers = _TAB.get(name, None)
    if vers is None:
        raise ImportError("library %r not found" % name)
    if version is None:
        version = max(vers.iterkeys())
    elif version not in vers:
        raise ImportError("library %r %r not found" % (name, version))
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
                    raise ImportError("module %r %r in %r don't match hash %r"
                                      % (name, version, path, hval))
            fobj, path, desc = imp.find_module(os.path.splitext(fname)[0],
                                               [fdir])
            mod = imp.load_module(name, fobj, path, desc)
            _CACHE[(name, version)] = mod
            return mod
    finally:
        imp.release_lock()


def make_line(path, name, version):
    """Makes a complete string for loader's file"""
    # name, version, path, hashes
    path = os.path.abspath(path)
    path64 = base64.b64encode(path)
    name = str(name)
    version = tuple(version)
    hashes = []
    for hs_name, hs_func in _HASHES.iteritems():
        hashes.append('%s:%s' % (hs_name, get_hash(path, hs_func)))
    return '%s;%s;%s;%s' % (str(name), '.'.join(str(vs) for vs in version),
                            path64, ' '.join(hashes))
