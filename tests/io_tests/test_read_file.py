#!/usr/bin/python -OOBtt
"""This test reads the current file, first as a whole and then one character at a time
If any errors occur the test displays a "FAILED" message"""
import os
import sys

import pysec
import pysec.io
import pysec.io.fcheck
import pysec.io.fd
import pysec.io.fs
import pysec.io.temp


def main():
    sys.stdout.write("BASIC READ TEST: ")
    with pysec.io.fd.File.open(__file__, pysec.io.fd.FO_READ) as ftest:
        test_cnt = ftest.read()
        if len(test_cnt) != os.path.getsize(__file__):
            sys.stdout.write("FAILED\n")
            return
    with pysec.io.fd.File.open(__file__, pysec.io.fd.FO_READ) as ftest:
        for byte in test_cnt:
            if ftest.read(1) != byte:
                sys.stdout.write("FAILED\n")
                return
        sys.stdout.write("PASSED\n")


if __name__ == '__main__':
    main()