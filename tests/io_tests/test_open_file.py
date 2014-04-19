#!/usr/bin/python
"""This test tries to open and create a file in multiple modes
If any errors occur the test displays a "FAILED" message"""
import os
import subprocess
import sys

import pysec
import pysec.io
import pysec.io.fcheck
import pysec.io.fd
import pysec.io.fs
import pysec.io.temp

FILE_NAME = '/tmp/__pysec_open_test.tmp '
FILE_MODES = {
    pysec.io.fd.FO_READNEW: 'READNEW',
    pysec.io.fd.FO_READEX: 'READEX',
    pysec.io.fd.FO_WRNEW: 'WRNEW',
    pysec.io.fd.FO_WREX: 'WREX',
    pysec.io.fd.FO_WREXTR: 'WREXTR',
    pysec.io.fd.FO_APNEW: 'APNEW',
    pysec.io.fd.FO_APEX: 'APEX',
    pysec.io.fd.FO_APEXTR: 'APEXTR',
    pysec.io.fd.FO_READ: 'READ',
    pysec.io.fd.FO_WRITE: 'WRITE',
    pysec.io.fd.FO_APPEND: 'APPEND',
    pysec.io.fd.FO_READNEW: 'READNEW'
}

# This Array marks the iteration where we generate an exception
# If the exception is not expected we mark the test as FAILED
# For example in the last iteration we attempt to open a file using
# FO_READNEW, but the file already exists
FILE_EXCEPTIONS = 2, 5, 11


def is_file_open(pid, name):
    sp = subprocess.Popen(['lsof', '-p', str(pid), '-F', 'n'], stdout=subprocess.PIPE)
    for line in sp.stdout:
        if name in line:
            return True
    return False


def main():
    sys.stdout.write("BASIC OPEN TEST: ")
    pid = os.getpid()
    if os.path.exists(FILE_NAME):
        os.unlink(FILE_NAME)
    for step, test_mode in enumerate(FILE_MODES):
        test_name = FILE_MODES[test_mode]
        try:
            with pysec.io.fd.File.open(FILE_NAME, test_mode) as ftest:
                if not is_file_open(pid, FILE_NAME):
                    print "FAILED %s, file %r is not open" % (test_name, FILE_NAME)
                    return
            # Check if the file has been closed
            if is_file_open(pid, FILE_NAME):
                print "FAILED %s, file %r is not closed" % (test_name, FILE_NAME)
                return
        except OSError,ex:
            # Check if the file has been closed
            if is_file_open(pid, FILE_NAME):
                print "FAILED %s, file %r is not closed" % (test_name, FILE_NAME)
                return
            if step not in FILE_EXCEPTIONS:
                print "FAILED %s, unexpected error %r" % (test_name, FILE_NAME, str(ex))
                return
        else:
            if step in FILE_EXCEPTIONS:
                print "FAILED %s, expected error" % test_name
                return
    sys.stdout.write("PASSED\n")    

if __name__ == "__main__":
    main()
    os.remove(FILE_NAME);