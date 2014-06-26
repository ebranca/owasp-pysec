#!/usr/bin/python2.7 -OOBRtt
import errno
import os
import operator
import sys

from pysec import alg
from pysec.io import fd
from pysec.utils import ilen, xrange
from pysec import tb
from pysec.xsplit import xbounds


# tb.set_excepthook(tb.short_tb)


BUFSIZE = 4096
MAX_MEMORY_SORT = 10240
TMP_DIR = os.path.abspath('./tmp')
try:
    os.mkdir(TMP_DIR)
except OSError, ex:
    if ex.errno != errno.EEXIST:
        raise


def sort_in_memory(fp, start, end):
    lines = [fp[start:end] for start, end in fp.xlines(start, end, keep_eol=1, size=BUFSIZE)]
    lines.sort()
    return lines



def _main():
    path = os.path.abspath(sys.argv[1])
    fno = 0
    with fd.File.open(path, fd.FO_READEX) as txt:
        # split and sort
        prev_end = offset = 0
        for lineno, (start, end) in enumerate(txt.xlines(keep_eol=1, size=BUFSIZE)):
            if end - offset > MAX_MEMORY_SORT:
                if end - prev_end > MAX_MEMORY_SORT:
                    print >> sys.stderr, "[ERROR]"
                    print >> sys.stderr,  "Line %d bigger than MAX_MEMORY_SORT limit" % lineno
                    print >> sys.stderr,  "Line's length: %d" % (end - prev_end)
                    print >> sys.stderr,  "MAX_MEMORY_SORT limit: %d" % MAX_MEMORY_SORT
                    return 1
                with fd.File.open(os.path.join(TMP_DIR, '%s.srt' % str(fno)), fd.FO_WRITE) as fout:
                    fout.truncate()
                    for line in sort_in_memory(txt, offset, prev_end):
                        fout.write(line)
                fno += 1
                offset = end
            prev_end = end
        else:
            with fd.File.open(os.path.join(TMP_DIR, '%s.srt' % str(fno)), fd.FO_WRITE) as fout:
                fout.truncate()
                for line in sort_in_memory(txt, offset, prev_end):
                    fout.write(line)
            fno += 1
        splits = fno
        # merge and sort
        files = [fd.File.open(os.path.join(TMP_DIR, '%s.srt' % str(fno)), fd.FO_READ).lines()
                 for fno in xrange(0, splits)]
        lines = [f.next() for f in files]
        while files:
            fno, line = min(enumerate(lines), key=operator.itemgetter(1))
            print line
            try:
                lines[fno] = files[fno].next()
            except StopIteration:
                del lines[fno]
                del files[fno]
        for i in xrange(0, splits):
            os.unlink(os.path.join(TMP_DIR, '%s.srt' % str(i)))


if __name__ == '__main__':
    ret = _main()
    os.rmdir(TMP_DIR)
