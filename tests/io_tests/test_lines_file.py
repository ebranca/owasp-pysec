#!/usr/bin/python -OOBtt
"""This test reads the current file using "lines" function, and compares against standard API
If any errors occur the test displays a "FAILED" message"""
import sys

import pysec
import pysec.io
import pysec.io.fcheck
import pysec.io.fd
import pysec.io.fs
import pysec.io.temp

def standard_read_self():
    test_data = []
    fd = open(__file__, "r")
    for line in fd:
        test_data.append(line)
    fd.close()
    return test_data

def main():
    sys.stdout.write("BASIC LINES TEST: ")
    # saving whole file in memory for future comparison
    test_data = standard_read_self()
    # Read lines with EOL
    with pysec.io.fd.File.open(__file__, pysec.io.fd.FO_READ) as ftest:
        test_cnt = ftest.lines(keep_eol=True)
        if ''.join(test_cnt) != ''.join(test_data):
            sys.stdout.write("FAILED with KEEP_EOL=TRUE\n")
            return
    # Read lines without EOL
    with pysec.io.fd.File.open(__file__, pysec.io.fd.FO_READ) as ftest:
        test_cnt = ftest.lines(keep_eol=False)
        if ''.join(test_cnt) != ''.join(test_data).replace('\n', ''):
            sys.stdout.write("FAILED with KEEP_EOL=FALSE\n")
            return
    # Read lines using EOL=')'
    with pysec.io.fd.File.open(__file__, pysec.io.fd.FO_READ) as ftest:
        test_cnt = ftest.lines(eol=')', keep_eol=True)
        if ''.join(test_cnt) != ''.join(test_data):
            sys.stdout.write("FAILED with EOL=')' and KEEP_EOL=TRUE\n")
            return
    # Read lines using EOL=')' and KEEP_EOL=FALSE
    with pysec.io.fd.File.open(__file__, pysec.io.fd.FO_READ) as ftest:
        test_cnt = ftest.lines(eol=')', keep_eol=False)
        if ''.join(test_cnt) != ''.join(test_data).replace(')', ''):
            sys.stdout.write("FAILED with EOL=')' and KEEP_EOL=FALSE\n")
            return
    # Read first line starting at offset 32 and ending at 256
    with pysec.io.fd.File.open(__file__, pysec.io.fd.FO_READ) as ftest:
        test_cnt = ftest.lines(start=32, stop=256, eol='\n', keep_eol=True)
        if ''.join(test_cnt) != ''.join(test_data)[32:256]:
            sys.stdout.write("FAILED with different start and stop\n")
            return
    sys.stdout.write("PASSED\n")

if __name__ == '__main__':
    main()

