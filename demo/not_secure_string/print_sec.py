#!/usr/bin/python2.7 -OOBRtt
import os
import sys

from pysec import alg
from pysec.io import fd
from pysec import strings
from pysec.xsplit import xlines


BUFSIZE = 4096


if __name__ == '__main__':
    path = os.path.abspath(sys.argv[1])
    offset = 0 if len(sys.argv) < 3 else int(sys.argv[2])
    size = None if len(sys.argv) < 4 else int(sys.argv[3])
    with fd.File.open(path, fd.FO_READEX) as fb:
        if size is None:
            size = len(fb) - offset
        print "=== Repr visible characters ==="
        for chunk in fb.chunks(BUFSIZE, start=offset, stop=offset+size):
            sys.stdout.write(strings.erepr(chunk))
        print
        print "=== Repr visible characters and split lines ==="
        for line in xlines(fb, eol='\n', keep_eol=1, start=offset, stop=offset+size, find=alg.knp_first):
            sys.stdout.write(strings.erepr(line))
            sys.stdout.write('\n')
        print
        print "=== Only printable characters and split lines ==="
        for line in xlines(fb, eol='\n', keep_eol=0, start=offset, stop=offset+size, find=alg.knp_first):
            sys.stdout.write(strings.only_printable(line))
            sys.stdout.write('\n')
        print

