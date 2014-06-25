#!/usr/bin/python2.7 -OOBRtt
import sys
import os

from pysec import load


if __name__ == '__main__':
    for arg in sys.argv[1:]:
        name, _, arg = arg.partition(':')
        path, _, version = arg.rpartition('@')
        version = tuple(int(v) for v in version.split('.'))[:3]
        print load.make_line(path, name, version)

