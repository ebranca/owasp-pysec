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
            fdr = _os.open(file, _os.O_RDONLY|_os.O_CREAT|_os.O_EXCL, 0600)
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
