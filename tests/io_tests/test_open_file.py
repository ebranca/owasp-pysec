#!/usr/bin/python

# "==========="
# "OPEN FILE TEST"
# "==========="

import os
import subprocess
import sys

import pysec
import pysec.io
import pysec.io.fcheck
import pysec.io.fd
import pysec.io.fs
import pysec.io.temp

FILE_NAME = "/tmp/pysec_open_test"
FILE_MODES = [pysec.io.fd.FO_READNEW, \
	pysec.io.fd.FO_READEX, \
	pysec.io.fd.FO_WRNEW, \
	pysec.io.fd.FO_WREX, \
	pysec.io.fd.FO_WREXTR, \
	pysec.io.fd.FO_APNEW, \
	pysec.io.fd.FO_APEX, \
	pysec.io.fd.FO_APEXTR, \
	pysec.io.fd.FO_READ, \
	pysec.io.fd.FO_WRITE, \
	pysec.io.fd.FO_APPEND, \
	pysec.io.fd.FO_READNEW]

# This Array marks the iteration where we generate an exception
# If the exception is not expected we mark the test as FAILED
# For example in the last iteration we attempt to open a file using FO_READNEW, but the file already exists
FILE_EXCEPTIONS = [3, 6, 12]

def is_file_open(pid, name):
	sp = subprocess.Popen(["lsof", "-p", str(pid), "-F", "n"], stdout = subprocess.PIPE)
	for line in sp.stdout:
		if name in line:
			return True
	return False

# This test tries to open and create a file in multiple modes
# If any errors occur the test displays a "FAILED" message
def main():
	sys.stdout.write("BASIC OPEN TEST = ")
	__test_pid = os.getpid()
	__test_progress = 0
	for __test_mode in FILE_MODES:
		__test_progress += 1
		try:
			_test_file = pysec.io.fd.File.open(FILE_NAME, __test_mode)
			if _test_file == -1:
				if is_file_open(__test_pid, FILE_NAME) == True:
					sys.stdout.write("FAILED\n")
					return
			else:
				if is_file_open(__test_pid, FILE_NAME) == False:
					sys.stdout.write("FAILED\n")
					return
				_test_file.close()
				# Check if the file has been closed
				if is_file_open(__test_pid, FILE_NAME) == True:
					sys.stdout.write("FAILED\n")
					return
		except:
#			print __test_progress
			if __test_progress not in FILE_EXCEPTIONS:
				sys.stdout.write("FAILED\n")
				return
			continue
	sys.stdout.write("PASSED\n")	

if __name__ == "__main__":
	main()
	os.remove(FILE_NAME);