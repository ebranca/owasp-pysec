#!/usr/bin/python2.7 -OOBRtt
import os
import sys
from string import digits

from pysec import chain
from pysec.io import fd

if __name__ == '__main__':
    path = os.path.abspath(sys.argv[1])
    with fd.File.open(path, fd.FO_READEX) as txt:
        for line in txt.lines() | chain.contains(*digits) | chain.to_erepr:
            print line
