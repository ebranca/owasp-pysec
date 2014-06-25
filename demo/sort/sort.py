#!/usr/bin/python2.7 -OOBRtt
import os
import sys

from pysec import alg
from pysec.io import fd
from pysec.xsplit import xbounds


def find_ck(fp, sub, chunk):
    buf = fp[:chunk]
    offset = len(buf)
    sub_len = len(sub)
    while buf:
        pos = alg.find(sub)
        if pos >= 0:
            yield pos
            buf = buf[pos+1:]
        else:
            offset = offset - sub_len
            buf = buf[offset:offset+chunk-sub_len]
        


if __name__ == '__main__':
    path = os.path.abspath(sys.argv[1])
    with fd.File.open(path, fd.FO_READEX) as txt:
        for lineno, (start, end) in enumerate(xbounds(txt, sep='\n', keep_sep=1, find=lambda t, s: find_ck(t, s, 4096))):
            print lineno

