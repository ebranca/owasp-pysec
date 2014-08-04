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
from pysec.core import Error, Object, unistd, dirent
from pysec.xsplit import xbounds
from pysec.alg import knp_first
from pysec.io import fcheck
from pysec.utils import xrange
from pysec.sys.process import ProcessUtil
import os,sys,resource,errno
import fcntl
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

class FailedDupFD(FDError):
    """Raise when failed to dup an file descriptor"""
    def __init__(self, fd, seq = None, detail = None):
        super(FailedDupFD, self).__init__(fd)
        self.seq = seq
        self.detail = detail
        
    def __str__(self):
        return "Failed to dup file descriptor %d" % (self.fd) + \
               "to %d" % (self.seq) if self.seq is not None else "" + \
               (", " + self.detail) if self.detail is not None else ""
                                                                           

def read_check(func):
    """Decorator to control read permission in reader methods"""
    def _read(fd, *args, **kargs):
        """*func* wrapped with read check"""
        if not fd.flags & os.O_WRONLY:
            return func(fd, *args, **kargs)
        raise NotReadableFD(fd)
    return _read


def write_check(func):
    """Decorator to control write permission in writer methods"""
    def _write(fd, *args, **kargs):
        """*func* wrapped with write check"""
        if fd.flags & os.O_WRONLY or fd.flags & os.O_APPEND:
            return func(fd, *args, **kargs)
        raise NotWriteableFD(fd)
    return _write

class FD(Object):
    """FD represents a File Descriptor"""

    def __init__(self, fd, inheritable=False):
        """Wrapper a file descriptor
        
        :param fd: the file descriptor
        :param inheritable: the file descriptor will be not inheritable `See PEP 446 <http://legacy.python.org/dev/peps/pep-0446/>`_ by default, or non-inheritable if inheritable is True
        :type inheritable: bool
        """
        fd = int(fd)
        if fd < 0:
            raise ValueError("Invalid fd value")
        self.fd = fd
        self._set_inheritable(inheritable)

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

    def __eq__(self, other):
        if type(other).__name__ != type(self).__name__:
            return False
        if self.fileno() == other.fileno():
            return True
        return False

    def __ne__(self, other):
        if type(other).__name__ != type(self).__name__:
            return False
        if self.fileno() != other.fileno():
            return True
        return False

    def __gt__(self, other):
        if type(other).__name__ != type(self).__name__:
            return False
        if self.fileno() > other.fileno():
            return True
        return False

    def __ge__(self, other):
        if type(other).__name__ != type(self).__name__:
            return False
        if self.fileno() >= other.fileno():
            return True
        return False

    def __lt__(self, other):
        if type(other).__name__ != type(self).__name__:
            return False
        if self.fileno() < other.fileno():
            return True
        return False

    def __le__(self, other):
        if type(other).__name__ != type(self).__name__:
            return False
        if self.fileno() <= other.fileno():
            return True
        return False

    def close(self):
        """Closes file descriptor"""
        unistd.close(self.fd)

    # factory function
    @staticmethod
    def FD(fd, **kwargs):
        """A factory of file descriptor wrapper
        This function will detect the type of file descriptor incoming and return the wrapped instance."""
        if fd < 0:
            raise ValueError("wrong fd value")
        fs = os.fstat(fd)
        st_mode = fs.st_mode
        if stat.S_ISREG(st_mode):
            return File(fd, **kwargs)
        elif stat.S_ISBLK(st_mode):
            return BlockDev(fd, **kwargs)
        elif stat.S_ISDIR(st_mode):
            return Directory(fd, **kwargs)
        elif stat.S_ISCHR(st_mode):
            return CharDev(fd, **kwargs)
        elif stat.S_ISFIFO(st_mode):
            return FIFO(fd, **kwargs)
        elif stat.S_ISLNK(st_mode):
            return SYMLNK(fd, **kwargs)
        elif stat.S_ISSOCK(st_mode):
            return Socket(fd, **kwargs)
        else:
            return FD(fd, **kwargs)

    # some private function
    def _set_inheritable(self, inheritable):
        """Set "inheritable" flag
        
        :param inheritable: the file descriptor will be set to a non-inheritable file descriptors if inheritable is False
        :type inheritable: bool
        """
        if sys.hexversion < 0x03040000:
            unistd.set_inheritable(self.fd, inheritable)
            #if inheritable is False:
            #    self.on_flags(fcntl.FD_CLOEXEC)
            #else:
            #    self.off_flags(fcntl.FD_CLOEXEC)
        else:
            os.set_inheritable(self.fd, inheritable)
    
    def _get_inheritable(self):
        """Get inheritable flag
        
        :returns: bool"""
        if sys.hexversion < 0x03040000:
            #return not self.has_flag(fcntl.FD_CLOEXEC)
            return unistd.get_inheritable(self.fd)
        else:
            return os.get_inheritable(self.fd)
    
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

    # Get fd's link
    def fd_link(self):
        """Get the file descriptor's link in /proc/self/fd/<fd>"""
        proc = '/proc/self/fd'
        return os.readlink(os.path.join(proc, str(self.fd)))

    # fcntl flags operator methods
    @property
    def flags(self):
        """Get file descriptor's flags (fcntl.F_GETFL)"""
        return fcntl.fcntl(self.fd, fcntl.F_GETFL, "0")

    @flags.setter
    def flags(self, flags):
        """Set file descriptor's flags (fcntl.F_SETFL)"""
        fcntl.fcntl(self.fd, fcntl.F_SETFL, flags)
    
    # About resource limit
    @staticmethod
    def get_maximum_value():
        """Get the maximum number of open file descriptors for this process.

        Return the process hard resource limit of maximum number of
        open file descriptors. If the limit is “infinity”, None will be returned
        """

        limits = resource.getrlimit(resource.RLIMIT_NOFILE)
        result = limits[1]
        if result == resource.RLIM_INFINITY:
            result = None
        return result


    #dup
    def dup(self, inheritable = False, seq = None):
        """
        Dup the file descriptor. The new descriptor is non-inheritable in default
        
        If the seq has set, the new file descriptor will shall be the lowest numbered available (that is, not already open) file descriptor 
        greater than or equal to the seq argument.
        
        :param inheritable: The inheritable setting
        :param seq: Assign to the value of file descriptor.
        :returns:  FD -- the new file descriptor will be wrapped by FD class.
        :raises: FailedDupFD"""
        newfd = -1
        if seq is not None:
            iseq = int(seq)
            if not hasattr(fcntl, "F_DUPFD"):
                FailedDupFD(self.fd, seq, "Current platform not support F_DUPFD")
            newfd = fcntl.fcntl(self.fd, fcntl.F_DUPFD, iseq)
        else:
            newfd = os.dup(self.fd)

        if newfd == -1:
            raise FailedDupFD(self.fd, seq)

        return FD.FD(newfd, inheritable=inheritable)

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
# open the file in append mode, if it doesn't exist create it
FO_APPEND = 10


_FO_NEW_MODES = FO_READNEW, FO_WRNEW, FO_APNEW, FO_READ, FO_WRITE, FO_APPEND


FO_MODES = FO_READNEW, FO_READEX, FO_WRNEW, FO_WREX, FO_WREXTR, \
           FO_APNEW, FO_APEX, FO_APEXTR, FO_READ, FO_WRITE, FO_APPEND


def _fo_readnew(fpath, mode):
    """Creates and open a regular file in read-only mode,
    raises an error if it exists"""
    return os.open(fpath, os.O_RDONLY | os.O_CREAT | os.O_EXCL, mode)


def _fo_readex(fpath, _):
    """Opens a regular file in read-only mode,
    raises an error if it doesn't exists"""
    return os.open(fpath, os.O_RDONLY)


def _fo_wrnew(fpath, mode):
    """Creates and opens a regular file in write-only,
    raises an error if it exists"""
    return os.open(fpath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)


def _fo_wrex(fpath, _):
    """Opens a regular file in write-only mode,
    raises an error if it doesn't exists"""
    return os.open(fpath, os.O_WRONLY)

    
def _fo_wrextr(fpath, _):
    """Opens a regular file in write-only mode and truncates it,
    raises an error if it doesn't exists"""
    return os.open(fpath, os.O_WRONLY | os.O_TRUNC)
    

def _fo_apnew(fpath, mode):
    """Creates and opens a regular file in append mode,
    raises an error if it exists"""
    return os.open(fpath, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL, mode)


def _fo_apex(fpath, _):
    """Opens a regular file in append mode,
    raises an error if it doesn't exists"""
    return os.open(fpath, os.O_WRONLY | os.O_APPEND)


def _fo_apextr(fpath, _):
    """Opens a regular file in append mode and truncates it,
    raises an error if it doesn't exists"""
    return os.open(fpath, os.O_WRONLY | os.O_APPEND | os.O_TRUNC)


def _fo_read(fpath, mode):
    """Opens a regular file in read-only mode,
    if it doesn't exist a new file will be created"""
    return os.open(fpath, os.O_RDONLY | os.O_CREAT, mode)


def _fo_write(fpath, mode):
    """Opens a regular file in write-only mode,
    if it doesn't exist a new file will be created"""
    return os.open(fpath, os.O_WRONLY | os.O_CREAT, mode)


def _fo_append(fpath, mode):
    """Opens a regular file in append mode,
    if it doesn't exist a new file will be created"""
    return os.open(fpath, os.O_WRONLY | os.O_APPEND | os.O_CREAT, mode)


FO_READNEW, FO_READEX, FO_WRNEW, FO_WREX, FO_WREXTR, \
           FO_APNEW, FO_APEX, FO_READ, FO_WRITE, FO_APPEND

_FOMODE2FUNC = _fo_readnew, _fo_readex, _fo_wrnew, _fo_wrex, _fo_wrextr, \
               _fo_apnew, _fo_apex, _fo_apextr,_fo_read, _fo_write, _fo_append


class File(FD):
    """File represents a Regular File's file descriptor."""

    def __init__(self, fd, **kwagrs):
        super(self.__class__, self).__init__(fd, **kwagrs)
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

    @property
    def filepath(self):
        return self.fd_link()

    @staticmethod
    def open(fpath, oflag, mode=0666):
        """Open a file descript for a regular file in fpath using the open mode
        specifie by *oflag* with *mode*"""
        oflag = int(oflag)
        if oflag not in FO_MODES:
            raise ValueError("unknown file open mode: %r" % oflag)
        mode = int(mode)
        if not fcheck.mode_check(mode):
            raise ValueError("wrong mode: %r" % oct(mode))
        fopen = _FOMODE2FUNC[oflag]
        fd = -1
        try:
            fd = fopen(fpath, mode)
            fd = File(fd)
            if mode in _FO_NEW_MODES and not fcheck.ino_check(int(fd)):
                raise OSError("not enough free inodes")
        except:
            if fd > -1:
                os.close(fd)
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
            fd = os.open(fpath, os.O_RDONLY | os.O_CREAT, mode)
        finally:
            if fd >= 0:
                os.close(fd)

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

    @write_check
    def truncate(self, length=0):
        """Truncate the file and if the pointer is in a inexistent part of file
        it will be moved to the end of file."""
        fd = int(self)
        length = int(length)
        if length < 0:
            raise ValueError("negative length: %r" % length)
        size = self.size
        os.ftruncate(fd, length)
        if size > length:
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
                    break
                chunk_start = chunk_end - eol_len
                chunk_end = min(chunk_start + size, stop)
                chunk = self[chunk_start:chunk_end]
            else:
                chunk_start = chunk_start + pos + eol_len
                yield line_start, chunk_start if keep_eol else (chunk_start - eol_len)
                line_start = chunk_start
                chunk = chunk[pos + eol_len:]
                if not chunk:
                    if chunk_start >= stop:
                        break
                    chunk_start = chunk_end - eol_len + 1
                    chunk_end = chunk_start + size
                    chunk = self[chunk_start:chunk_end]

    def lines(self, start=0, stop=None, eol='\n', keep_eol=0, size=4096):
        return (self[start:end] for start, end
                in self.xlines(start, stop, eol, keep_eol, size))

    def get_line(self, lineno, start=None, max_size=None, eol='\n'):
        lineno = int(lineno)
        start = int(self.pos if start is None else start)
        len_eol = len(eol)
        try:
            for atline, (start, end) in enumerate(xbounds(self, eol, 1, start, (start + max_size) if max_size is not None else None, knp_first)):
                if atline == lineno:
                    if start is None:
                        return None
                    if self[end-len_eol:end] == eol:
                        return self[start:end-len_eol]
                    else:
                        return None
                elif atline > lineno:
                    return None
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


class Directory(FD):
    """Directory represents a Directory's file descriptor."""

    def __init__(self, fd, origin=None, **kwagrs):
        super(self.__class__, self).__init__(fd, **kwagrs)
        self.origin = os.path.abspath(origin)
        # self.pos = 0

    @staticmethod
    def open(path):
        """Open a file descriptor for a directory path using read-only mode.
        We keep a copy of the directory path within the object for future
        reference. The object created will keep a file descriptor opened for
        the corresponding directory until close or destructor is called"""
        fd = -1
        path = os.path.abspath(path)
        try:
            fd = dirent.opendir(path)
            fd = Directory(fd, path)
            fd.path = path
        except:
            if fd > -1:
                os.close(fd)
            raise
        return fd

    def readdir(self):
        """Return a set of tuple (inode, name) for each file contained in this
        directory"""
        return set(dirent.readdir(self.fd))

    def ls(self, filt=lambda _: 1, dot=0, base=None):
        """Return a generator of names of the entries in this directory.
        If dot is true '.' and '..' will be include in the tuple."""
        base = self.origin if base is None else os.path.abspath(base)
        if dot:
            return (os.path.join(base, name) for _, name in self.readdir()
                    if filt(os.path.join(base, name)))
        else:
            return (os.path.join(base, name) for _, name in self.readdir()
                    if name != '.' and name != '..' and
                       filt(os.path.join(base, name)))

    def __iter__(self):
        """Return a iterator of all names of direcotry's entries.
        '.' and '..' are included."""
        return (name for _, name in self.readdir())


class Socket(FD):
    """File represents a Socket's file descriptor."""
    pass


class BlockDev(FD):
    """File represents a Block Device's file descriptor."""
    pass


class CharDev(FD):
    """File represents a Character Device's file descriptor."""
    pass


class FIFO(FD):
    """File represents a FIFO's file descriptor."""
    pass

class SYMLNK(FD):
    """File represents a symbolic link"""
    pass

class FDUtils():
    def __init__(self):
        pass

    @staticmethod
    def list_fds(pid = None):
        """This function will return an iterator with all file descriptors in current process or special process

        :param pid: the special process id, default is None
        :raises: AttributeError, KeyError
        :return: FD derivative class , path link tuple via iterator.
        :rtype: iterator
        """
        if not sys.platform.startswith('linux'):
            raise NotImplementedError('Unsupported platform: %s' % sys.platform)

        procBase = None
        if pid is not None:
            allPIDs = ProcessUtil.get_pid_list()
            if pid in allPIDs:
                procBase = os.path.join("proc", str(pid), "fd")
            else:
                raise ValueError("Invalid fd value")
        else:
            procBase = '/proc/self/fd'

        for num in os.listdir(procBase):
            path = None
            try:
                path = os.readlink(os.path.join(procBase, num))
            except OSError as err:
                # Last FD is always the "listdir" one (which may be closed), we shoul ignore it.
                if err.errno != errno.ENOENT:
                    raise
            if path is not None:
                yield (FD.FD(int(num)), path)

    @staticmethod
    def close_all_open_fds(exclude = None):
        """Close all open file descriptors but not in exclude in current process
        """
        for fd, path in FDUtils.list_fds():
            if exclude is not None and fd.fileno() in exclude:
                continue
            fd.close()

    @staticmethod
    def clear_all_open_fds(exclude = None):
        """Close all open file descriptors in current process by violence way

        This function will try to close file descriptors from 0 to maximum value in current process whatever available or not
        """
        maxfd = FD.get_maximum_value()
        for fd in reversed(range(maxfd)):
            if exclude is None or fd not in exclude:
                unistd.close(fd)
