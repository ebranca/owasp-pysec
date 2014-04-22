#!/usr/bin/python -OOBtt
"""This test writes random data to a file, then reads it using standard API and compares results
If any errors occur the test displays a "FAILED" message."""

import random
import sys

import pysec
import pysec.io
import pysec.io.fcheck
import pysec.io.fd
import pysec.io.fs
import pysec.io.temp

FILE_SIZE = 4096
FILE_NAME = '/tmp/__pysec_write_test.tmp'


def main():
    sys.stdout.write("BASIC WRITE TEST: ")
    test_cnt = []
    with pysec.io.fd.File.open(FILE_NAME, pysec.io.fd.FO_WRITE) as ftest:
        for test_num in (random.randint(0,9) for _ in xrange(FILE_SIZE)):
            ftest.write(test_num)
            test_cnt.append(str(test_num))
    with open(FILE_NAME, 'rb') as ftest:
        test_check = ftest.read()

    if test_check != ''.join(test_cnt):
        sys.stdout.write("FAILED\n")
    else:
        sys.stdout.write("PASSED\n")


if __name__ == "__main__":
    main()