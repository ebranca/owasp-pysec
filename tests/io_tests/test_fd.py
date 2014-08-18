#!/usr/bin/python -OOBtt
"""The Unittest for io.fd"""

import unittest
import tempfile
import os
import fcntl
from pysec.io.fd import FD, File, process_opened_fds

class TestFD(unittest.TestCase):
    def setUp(self):
        tf = tempfile.mkstemp()
        self.testFileFD = FD.create(tf[0])
        self.testFileFDPath = tf[1]

    def test_getpath(self):
        self.assertEqual(self.testFileFDPath, self.testFileFD.filepath)

    def test_inheritable(self):
        inheritable = self.testFileFD._get_inheritable()
        self.assertFalse(inheritable)

    def test_dup(self):
        dupFD = self.testFileFD.dup()
        self.assertIsNotNone(dupFD)
        self.assertNotEqual(dupFD.fd, self.testFileFD.fd)
        self.assertEqual(dupFD.filepath, self.testFileFD.filepath)
        dupFD.close()

    def test_compare(self):
        sameFD = FD.create(self.testFileFD.fd)
        self.assertTrue(sameFD == self.testFileFD)

        dupFD = self.testFileFD.dup(seq=256)
        self.assertTrue(dupFD > self.testFileFD)
        self.assertTrue(dupFD >= self.testFileFD)
        self.assertTrue(sameFD >= self.testFileFD)
        self.assertTrue(self.testFileFD < dupFD)
        self.assertTrue(self.testFileFD <= sameFD)
        self.assertTrue(self.testFileFD <= dupFD)
        dupFD.close()
    
    def tearDown(self):
        self.testFileFD.close()

class TestFDFunction(unittest.TestCase):
    def setUp(self):
        tf = tempfile.mkstemp()
        self.testFileFD = FD.create(tf[0])

    def test_listfds(self):
        fdin = False
        for fd, path in process_opened_fds():
            if fd == self.testFileFD:
                fdin = True
        self.assertTrue(fdin)

    def tearDown(self):
        self.testFileFD.close()

if __name__ == '__main__':
    unittest.main()
