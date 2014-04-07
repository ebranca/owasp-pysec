#!/usr/bin/python

# "==========="
# "READ FILE TEST"
# "==========="

import os
import sys

import pysec
import pysec.io
import pysec.io.fcheck
import pysec.io.fd
import pysec.io.fs
import pysec.io.temp

# This test reads the current file, first as a whole and then one character at a time
# If any errors occur the test displays a "FAILED" message
def main():
	sys.stdout.write("BASIC READ TEST = ")
	_test_file = pysec.io.fd.File.open(__file__, pysec.io.fd.FO_READ)
	_test_content = _test_file.read()
	if len(_test_content) == os.path.getsize(__file__):
		_test_file.close()
		_test_file = pysec.io.fd.File.open(__file__, pysec.io.fd.FO_READ)
		for i in range(0, len(_test_content)):
			_test_character = _test_file.read(1)
			if _test_character != _test_content[i]:
				sys.stdout.write("FAILED\n")
				_test_file.close()
				return
		sys.stdout.write("PASSED\n")
	else:
		sys.stdout.write("FAILED\n")
	_test_file.close()

if __name__ == "__main__":
	main()