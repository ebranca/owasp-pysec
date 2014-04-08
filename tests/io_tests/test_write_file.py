#!/usr/bin/python

# "==========="
# "WRITE FILE TEST"
# "==========="

import os
import random
import sys

import pysec
import pysec.io
import pysec.io.fcheck
import pysec.io.fd
import pysec.io.fs
import pysec.io.temp

FILE_SIZE = 4096
FILE_NAME = "/tmp/pysec_write_test"

# This test writes random data to a file, then reads it using standard API and compares results
# If any errors occur the test displays a "FAILED" message
def main():
	sys.stdout.write("BASIC WRITE TEST = ")
	_test_file = pysec.io.fd.File.open(FILE_NAME, pysec.io.fd.FO_WRITE)
	_test_content = []
	for i in range(0, FILE_SIZE):
		_test_number = random.randint(0,9)
		_test_file.write(_test_number)
		_test_content.append(_test_number)
	_test_file.close()

	_test_file = open(FILE_NAME, "r")
	_test_check = _test_file.read()
	_test_file.close()
	for i in range(0, FILE_SIZE):
		if int(_test_check[i]) != int(_test_content[i]):
			sys.stdout.write("FAILED\n")
			return
	sys.stdout.write("PASSED\n")
	
if __name__ == "__main__":
	main()
	os.remove(FILE_NAME);