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
"""Contains FD and FD-like classes for operations with file descriptors"""
import os

from pysec.core import Error, Object, unistd, dirent, fcntl
from pysec.core import stat as pstat
from pysec.core import socket
from pysec.io import fcheck
from pysec.utils import xrange
from pysec import check

import inspect
import stat


class FDError(Error):
    """Generic error for fd module"""

    def __init__(self, fd):
        super(FDError, self).__init__()
        self.fd = int(fd)


class NotReadableFD(FDError):
    """Raise when try to read a no-readable fd"""
    pass


class NotWriteableFD(FDError):
    """Raise when try to write a no-writeable fd"""
    pass


class IncompleteWrite(FDError):
    """Raise when write operation was not successfully
    performed"""

    def __init__(self, fd, size):
        super(IncompleteWrite, self).__init__(fd)
        self.size = int(size)


class WrongFileType(FDError):

    def __init__(self, ftype, fd=None, path=None):
        super(WrongFileType, self).__init__(fd)
        self.ftype = ftype
        self.fd = None if fd is None else int(fd)
        self.path = None if path is None else str(path)


def read_check(func):
    """Decorator to control read permission in reader methods"""
    def _read(fd, *args, **kargs):
        """*func* wrapped with read check"""
        if not fd.flags & fcntl.O_WRONLY:
            return func(fd, *args, **kargs)
        raise NotReadableFD(fd)
    return _read


def write_check(func):
    """Decorator to control write permission in writer methods"""
    def _write(fd, *args, **kargs):
        """*func* wrapped with write check"""
        if fd.flags & fcntl.O_WRONLY or fd.flags & fcntl.O_APPEND:
            return func(fd, *args, **kargs)
        raise NotWriteableFD(fd)
    return _write


class FD(Object):
    """FD represents a File Descriptor"""

    def __init__(self, fd):
        fd = int(fd)
        if fd < 0:
            raise ValueError("wrong fd value")
        self.fd = fd

    def fileno(self):
        """Return file descriptor's int"""
        return int(self.fd)

    def __int__(self):
        """Return file descriptor's int"""
        return int(self.fd)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return 0

    def close(self):
        """Closes file descriptor"""
        unistd.close(self.fd)

    # stat methods
    def stat(self):
        """Returns result of a stat call"""
        return os.fstat(self.fd)

    @property
    def mode(self):
        """Get inode protection mode. See stat()"""
        return os.fstat(self.fd).st_mode

    @property
    def inode(self):
        """Get inode number. See stat()"""
        return os.fstat(self.fd).st_ino

    @property
    def device(self):
        """Get device inode resides on. See stat()"""
        return os.fstat(self.fd).st_dev

    @property
    def nlink(self):
        """Get number of links to the inode. See stat()"""
        return os.fstat(self.fd).st_nlink

    @property
    def uid(self):
        """Get user id of the owner. See stat()"""
        return os.fstat(self.fd).st_uid

    @property
    def gid(self):
        """Get group id of the owner. See stat()"""
        return os.fstat(self.fd).st_gid

    @property
    def size(self):
        """Get size in bytes of a lain file, or amount of data waiting on some
        special files. See stat()"""
        return os.fstat(self.fd).st_size

    @property
    def atime(self):
        """Get last access time. See stat()"""
        return os.fstat(self.fd).st_atime

    @property
    def mtime(self):
        """Get last modification time. See stat()"""
        return os.fstat(self.fd).st_mtime

    @property
    def ctime(self):
        """The *ctime* as reported by the operating system. On some systems
        (like Unix) is the time of the last metadata change, and, on others
        (like Windows), is the creation time (see platform documentation for
        details)."""
        return os.fstat(self.fd).st_ctime

    # fcntl methods
    @property
    def flags(self):
        """Get file descriptor's flags (fcntl.F_GETFL)"""
        return int(fcntl.fcntl(self.fd, fcntl.F_GETFL))

    @flags.setter
    def flags(self, flags):
        """Set file descriptor's flags (fcntl.F_SETFL)"""
        fcntl.fcntl(self.fd, fcntl.F_SETFL, int(flags))

    @property
    def can_read(self):
        return NotImplemented

    @property
    def can_write(self):
        return NotImplemented

    @property
    def can_exec(self):
        return NotImplemented


### Open modes for regular files
# create a new file and raise error if it exists, use read mode
FO_READNEW = 0
# read only and raise error if it doesn't exist
FO_READEX = 1
# create a new file and raise error if it exists, use write mode
FO_WRNEW = 2
# open a existing file in write mode
FO_WREX = 3
# open a existing file in write mode and truncate it
FO_WREXTR = 4
# create a new file and raise error if it exists, use append mode
FO_APNEW = 5
# open a existing file in append mode
FO_APEX = 6
# open a existing file in append mode and truncate it
FO_APEXTR = 7
# open the file in read-only mode, if it doesn't exist create it
FO_READ = 8
# open the file in write-only mode, if it doesn't exist create it
FO_WRITE = 9
# open the file in write-only mode, truncate to zero length or create file for writing
FO_WRITETR = 10
# open the file in append mode, if it doesn't exist create it
FO_APPEND = 11


_FO_NEW_FLAGS = FO_READNEW, FO_WRNEW, FO_APNEW, FO_READ, FO_WRITE, FO_APPEND, FO_WRITETR 


FOFLAGS2OFLAGS = {
    FO_READNEW: fcntl.O_RDONLY | fcntl.O_CREAT | fcntl.O_EXCL,
    FO_READEX:  fcntl.O_RDONLY,
    FO_WRNEW:   fcntl.O_WRONLY | fcntl.O_CREAT | fcntl.O_EXCL,
    FO_WREX:    fcntl.O_WRONLY,
    FO_WREXTR:  fcntl.O_WRONLY | fcntl.O_TRUNC,
    FO_APNEW:   fcntl.O_WRONLY | fcntl.O_APPEND | fcntl.O_CREAT | fcntl.O_EXCL,
    FO_APEX:    fcntl.O_WRONLY | fcntl.O_APPEND,
    FO_APEXTR:  fcntl.O_WRONLY | fcntl.O_APPEND | fcntl.O_TRUNC,
    FO_READ:    fcntl.O_RDONLY | fcntl.O_CREAT,
    FO_WRITE:   fcntl.O_WRONLY | fcntl.O_CREAT,
    FO_WRITETR: fcntl.O_WRONLY | fcntl.O_CREAT | fcntl.O_TRUNC,
    FO_APPEND:  fcntl.O_WRONLY | fcntl.O_APPEND | fcntl.O_CREAT
}


NAME2FOFLAGS = {
    'r': FO_READNEW,
    'rb': FO_READNEW,
    'w': FO_WRITETR,
    'wb': FO_WRITETR,
    'a': FO_APPEND,
    'ab': FO_APPEND,
}


class File(FD):
    """File represents a Regular File's file descriptor."""

    def __init__(self, fd):
        super(self.__class__, self).__init__(fd)
        if not stat.S_ISREG(self.mode):
            raise WrongFileType(File, fd=self.fd)
        self.pos = 0

    def __len__(self):
        """Returns file's size"""
        return self.size

    def __getitem__(self, index):
        if isinstance(index, int):
            return self.pread(1, index)
        elif isinstance(index, slice):
            start, stop, step = index.indices(len(self))
            if step == 1:
                return self.pread(stop - start, start)
            else:
                return ''.join(self.pread(1, pos) for pos
                               in xrange(start, stop, step))
        raise IndexError('wrong index type: %s' % type(index))

    @staticmethod
    @check.delimit('fd-reg-open')
    def open(fpath, oflags, mode=0666):
        """Open a file descript for a regular file in fpath using the open mode
        specifie by *oflag* with *mode*"""
        _oflags = FOFLAGS2OFLAGS.get(int(oflags), None)
        if oflags is None:
            raise ValueError("unknown file open mode: %r" % oflags)
        mode = int(mode)
        if not fcheck.mode_check(mode):
            raise ValueError("wrong mode: %r" % oct(mode))
        fd = -1
        try:
            fd = fcntl.open(fpath, _oflags, mode) if oflags in _FO_NEW_FLAGS \
                 else fcntl.open(fpath, _oflags)
            if oflags in _FO_NEW_FLAGS and not fcheck.ino_check(int(fd)):
                raise OSError("not enough free inodes")
            fd = File(fd)
        except:
            if fd > -1:
                unistd.close(fd)
            raise
        return fd

    @staticmethod
    def touch(fpath, mode=0666):
        """Create a new file with passed *mode* in *fpath*.
        If file *fpath* exists, a IOError will be raised."""
        mode = int(mode)
        if not fcheck.mode_check(mode):
            raise ValueError("wrong mode: %r" % oct(mode))
        fd = -1
        try:
            fd = fcntl.open(fpath, fcntl.O_RDONLY | fcntl.O_CREAT, mode)
        finally:
            if fd >= 0:
                unistd.close(fd)

    @read_check
    def read(self, size=None, pos=None):
        """Read *pos*-length data starting from position *pos*."""
        size = int(self.size) if size is None else int(size)
        pos = int(self.pos if pos is None else pos)
        if size < 0:
            raise ValueError("invalid size, %d" % size)
        chunk = unistd.pread(self.fd, size, pos)
        self.pos = pos + len(chunk)
        return chunk

    @read_check
    def pread(self, size=None, pos=None):
        """Read *pos*-length data starting from position *pos*.
        This operation doesn't change the pointer position."""
        size = int(self.size) if size is None else int(size)
        pos = int(self.pos if pos is None else pos)
        if size < 0:
            raise ValueError("invalid size, %d" % size)
        chunk = unistd.pread(self.fd, size, pos)
        return chunk

    @write_check
    def write(self, data, pos=None, tries=3):
        """Write data starting from position *pos* and do maximum *tries*
        write attempt, if all will fail it raises a IncompleteWrite
        exception. This operation moves the position pointer at end of written
        data."""
        fd = int(self)
        _tries = tries = int(tries)
        pos = int(self.pos if pos is None else pos)
        data = str(data)
        if not data:
            return
        dlen = len(data)
        dev = self.device
        if not fcheck.space_check(fd, dlen):
            raise OSError("not enough free space in device %r" % dev)
        wlen = 0
        while wlen < dlen:
            _wlen = unistd.pwrite(fd, data[wlen:], pos + wlen)
            if not _wlen:
                _tries -= 1
                if not _tries:
                    raise IncompleteWrite(fd, pos, tries)
            else:
                wlen += _wlen
                _tries = tries
        self.pos = pos + wlen

    @write_check
    def pwrite(self, data, pos=None, tries=3):
        """Write data starting from position *pos* and do maximum *tries*
        write attempt, if all will fail it raises a IncompleteWrite
        exception. This operation doesn't change the pointer position."""
        fd = int(self)
        _tries = tries = int(tries)
        pos = int(self.pos if pos is None else pos)
        data = str(data)
        if not data:
            return
        dlen = len(data)
        dev = self.device
        if not fcheck.space_check(fd, dlen):
            raise OSError("not enough free space in device %r" % dev)
        wlen = 0
        while wlen < dlen:
            _wlen = unistd.pwrite(fd, data[wlen:], pos + wlen)
            if not _wlen:
                _tries -= 1
                if not _tries:
                    raise IncompleteWrite(fd, pos, tries)
            else:
                wlen += _wlen
                _tries = tries

    def setbit(self, n, bit):
        byte, offset = divmod(n, 8)
        self[byte] = self[byte] | (1 << offset)

    @write_check
    def truncate(self, length=0):
        """Truncate the file and if the pointer is in a inexistent part of file
        it will be moved to the end of file."""
        fd = int(self)
        length = int(length)
        if length < 0:
            raise ValueError("negative length: %r" % length)
        size = self.size
        unistd.ftruncate(fd, length)
        self.moveto(length)

    def moveto(self, pos):
        """Move position pointer in position *pos* from start of FD."""
        pos = int(pos)
        if pos < 0:
            raise ValueError("invalid negative position: %d" % pos)
        self.pos = pos

    def xlines(self, start=0, stop=None, eol='\n', keep_eol=0, size=4096):
        """Splits FD's content in lines' boundaries that end with *eol*, it will
        start from *start* position and it'll stop at stop position, if *stop*
        is None it will stop at the end of FD. If keep_eol is true doesn't
        remove *eol* from the line"""
        line_start = chunk_start = int(start)
        if start < 0:
            raise ValueError("negative *start*: %d" % start)
        stop = len(self) if stop is None else int(stop)
        if stop < 0:
            raise ValueError("negative *stop*: %d" % stop)
        if start > stop:
            raise ValueError("*stop* must be greater than or euqal to *start*")
        if size < 0:
            raise ValueError("negative *size*: %d" % size)
        eol_len = len(eol)
        size = max(size, eol_len)
        chunk = self[chunk_start:chunk_start+max(size, eol_len)]
        chunk_end = chunk_start + len(chunk)
        while chunk:
            pos = chunk.find(eol)
            if pos < 0:
                if chunk_end >= stop:
                    if chunk:
                        yield line_start, stop
                    break
                chunk_start = chunk_end - eol_len
                chunk_end = min(chunk_start + size, stop)
                chunk = self[chunk_start:chunk_end]
            else:
                chunk_start = chunk_start + pos + eol_len
                if chunk_start > stop:
                    yield line_start, min((chunk_start if keep_eol else (chunk_start - eol_len)), stop)
                    break
                yield line_start, chunk_start if keep_eol else (chunk_start - eol_len)
                line_start = chunk_start
                chunk = chunk[pos + eol_len:]
                if not chunk:
                    chunk_start = chunk_end - eol_len + 1
                    chunk_end = chunk_start + size
                    chunk = self[chunk_start:chunk_end]

    def lines(self, start=0, stop=None, eol='\n', keep_eol=0, size=4096):
        return (self[start:end] for start, end
                in self.xlines(start, stop, eol, keep_eol, size))

    def readlines(self):
        return list(self.lines())

    def get_line(self, lineno, start=None, max_size=None, eol='\n'):
        lineno = int(lineno)
        start = int(self.pos if start is None else start)
        eol = str(eol)
        len_eol = len(eol)
        try:
            for atline, (start, end) in enumerate(self.xlines(start, (None if max_size is None else start + max_size), eol, 1)):
                if atline == lineno:
                    line = self[start:end]
                    if not line:
                        return None
                    else:
                        return line[:-len_eol]
        except StopIteration:
            return None
        return None

    def chunks(self, size,  start=0, stop=None):
        """Divides FD's content in chunk of length *size* starting from *start*
        and stopping at *stop*, if *stop* is None it'll stop at end of FD's
        content."""
        size = int(size)
        for offset in xrange(*slice(int(start),
                             None if stop is None
                             else int(stop), size).indices(len(self))):
            yield self.pread(size, offset)

    def __iter__(self):
        ch = self.read(1)
        while ch:
            yield ch
            ch = self.read(1)


class Directory(FD):
    """Directory represents a Directory's file descriptor."""

    def __init__(self, fd ):
        super(self.__class__, self).__init__(fd)
        if not stat.S_ISDIR(self.mode):
            raise WrongFileType(Directory, fd=self.fd)

    @staticmethod
    def open(path, create=0, mode=0755):
        """Open a file descriptor for a directory path using read-only mode.
        We keep a copy of the directory path within the object for future
        reference. The object created will keep a file descriptor opened for
        the corresponding directory until close or destructor is called"""
        fd = -1
        path = os.path.abspath(path)
        try:
            fd = fcntl.open(path, unistd.O_DIRECTORY|unistd.O_CREAT if create else 0, mode)
            fd = Directory(fd)
        except:
            if fd > -1:
                os.close(fd)
            raise
        return fd

    def fileat(self, fpath, oflags, mode=0644):
        """Open a file descript for a regular file in fpath using the open mode
        specifie by *oflag* with *mode*"""
        _oflags = FOFLAGS2OFLAGS.get(int(oflags), None)
        if oflags is None:
            raise ValueError("unknown file open mode: %r" % oflags)
        mode = int(mode)
        if not fcheck.mode_check(mode):
            raise ValueError("wrong mode: %r" % oct(mode))
        fd = -1
        try:
            fd = fcntl.openat(int(self), fpath, _oflags, mode) \
                 if oflags in _FO_NEW_FLAGS \
                 else fcntl.openat(int(self), fpath, _oflags)
            if oflags in _FO_NEW_FLAGS and not fcheck.ino_check(int(fd)):
                raise OSError("not enough free inodes")
            fd = File(fd)
        except:
            if fd > -1:
                unistd.close(fd)
            raise
        return fd

    def dirat(self, create=0, mode=0755):
        fd = -1
        try:
            fd = fcntl.openat(int(self), fcntl.O_DIRECTORY|fcntl.O_CREAT if create else 0, mode)
            fd = Directory(fd)
        except:
            if fd > -1:
                unistd.close(fd)
            raise
        return fd

    def readdir(self):
        """Return a set of tuple (inode, name) for each file contained in this
        directory"""
        return set(dirent.readdir(self.fd))

    def ls(self, filt=lambda _: 1, dot=0, base=None):
        """Return a generator of names of the entries in this directory.
        If dot is true '.' and '..' will be include in the tuple."""
        base = '' if base is None else os.path.abspath(base)
        if dot:
            return (os.path.join(base, name) for _, name in self.readdir()
                    if filt(os.path.join(base, name)))
        else:
            return (os.path.join(base, name) for _, name in self.readdir()
                    if name != '.' and name != '..' and
                       filt(os.path.join(base, name)))

    def __iter__(self):
        """Return a iterator of all names of directory's entries.
        '.' and '..' are included."""
        return (name for _, name in self.readdir())


def for_stream(meth):
    meth.__sock_family__ = socket.SOCK_STREAM


def for_dgram(meth):
    meth.__sock_family__ = socket.SOCK_DGRAM


SOCK_STREAM = socket.SOCK_STREAM
SOCK_DGRAM = socket.SOCK_DGRAM

AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6
AF_UNIX = socket.AF_UNIX


class Socket(FD):
    """Class to interact with a socket"""

    def __init__(self, fd, origin=None):
        super(self.__class__, self).__init__(fd)
        if not stat.S_ISSOCK(self.mode):
            raise WrongFileType(Socket, fd=self.fd)
        family = self.family
        for name, meth in inspect.getmembers(self, predicate=inspect.ismethod):
            ok = getattr(meth, '__sock_family__', None)
            if ok is not None and not ok:
                delattr(meth, name)

    @property
    def family(self):
        return socket.getsocksolopt(int(self), socket.SO_DOMAIN)

    domain = family

    @property
    def can_accept(self):
        return socket.getsocksolopt(int(self), socket.SO_ACCEPTCONN)

    @property
    @for_dgram
    def broadcast(self):
        return socket.getsocksolopt(int(self), socket.SO_BROADCAST)

    @property
    def debug(self):
        return socket.getsocksolopt(int(self), socket.SO_DEBUG)

    @property
    def route(self):
        return socket.getsocksolopt(int(self), socket.SO_DONTROUTE)

    @property
    def error(self):
        return socket.getsocksolopt(int(self), socket.SO_ERROR)

    @property
    @for_stream
    def keepalive(self):
        return socket.getsocksolopt(int(self), socket.SO_KEEPALIVE)

    @property
    def linger(self):
        return socket.getsocksolopt(int(self), socket.SO_LINGER)

    @property
    def oob_in_line(self):
        return socket.getsocksolopt(int(self), socket.SO_OOBINLINE)

    @property
    def protocol(self):
        return socket.getsocksolopt(int(self), socket.SO_PROTOCOL)

    @property
    def recv_bufsize(self):
        return socket.getsocksolopt(int(self), socket.SO_RCVBUF)

    @property
    def rcv_low_at(self):
        return socket.getsocksolopt(int(self), socket.SO_RCVLOWAT)

    @property
    def recv_timeout(self):
        return socket.getsocksolopt(int(self), socket.SO_RCVTIMEO)

    @property
    def send_bufsize(self):
        return socket.getsocksolopt(int(self), socket.SO_SNDBUF)

    @property
    def snd_low_at(self):
        return socket.getsocksolopt(int(self), socket.SO_SNDLOWAT)

    @property
    def send_timeout(self):
        return socket.getsocksolopt(int(self), socket.SO_SNDTIMEO)

    @property
    def type(self):
        return socket.getsocksolopt(int(self), socket.SO_TYPE)

    @property
    def reuse_address(self):
        return socket.getsocksolopt(int(self), socket.SO_REUSEADDR)

    @staticmethod
    def open_stream(domain=socket.AF_INET):
        return Socket.open(domain, socket.SOCK_STREAM, 0)

    @staticmethod
    def open_dgram(domain=socket.AF_INET):
        return Socket.open(domain, socket.SOCK_DGRAM, 0)

    @staticmethod
    def open(domain=socket.AF_INET, type=socket.SOCK_STREAM, protocol=0):
        fd = -1
        try:
            fd = socket.socket(domain, type, protocol)
            fd = Socket(fd)
        except:
            if fd > -1:
                unistd.close(fd)
            raise
        return fd

    def recv(self, length, flags=0):
        return socket.recv_from(int(self), length, flags)

    @for_dgram
    def recv_from(self, length, flags=0):
        return socket.recv_from(int(self), length, flags)

    @for_stream
    def send(self, msg, flags):
        return socket.send(int(self), msg, flags)

    @for_stream
    def sendall(self, msg, flags=0, tries=0):
        _tries = tries = int(tries)
        if tries < 0:
            raise ValueError("trie must be >= 0")
        fd = int(self)
        msg_len = len(msg)
        sent = socket.send(fd, msg, flags)
        _sent = 0
        while sent < msg_len:
            _sent = socket.send(fd, msg, flags)
            if not _sent:
                if not _tries:
                    raise IncompleteWrite(fd, sent, tries)
                _tries -= 1
            else:
                _tries = tries
            sent += _sent

    @for_dgram
    def send_to(self, msg, to, flags=0):
        return socket.send(msg, to, flags)

    read = recv

    write = sendall
        

class BlockDev(FD):
    """File represents a Block Device's file descriptor."""
    pass


class CharDev(FD):
    """File represents a Character Device's file descriptor."""
    pass


class FIFO(FD):
    """File represents a FIFO's file descriptor."""
    pass

