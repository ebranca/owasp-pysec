#!/usr/bin/python -OOBtt
"""The Unittest for io.fd"""

import random
import unittest
import tempfile
import os,fcntl
from pysec.io.fd import FD, File, FDUtils

class TestFD(unittest.TestCase):
    def setUp(self):
        tf = tempfile.mkstemp()
        self.testFileFD = FD.FD(tf[0])
        self.testFileFDPath = tf[1]

    def test_getpath(self):
        self.assertEqual(self.testFileFDPath, self.testFileFD.filepath)

    def test_inheritable(self):
        inheritable = self.testFileFD._get_inheritable()
        self.assertFalse(inheritable)

    def test_dup(self):
        newFD = self.testFileFD.dup()
        self.assertIsNotNone(newFD)
        self.assertNotEqual(newFD.fd, self.testFileFD.fd)
        self.assertEqual(newFD.filepath, self.testFileFD.filepath)
    
    def tearDown(self):
        self.testFileFD.close()

class TestFDUtil(unittest.TestCase):
    def setUp(self):
        tf = tempfile.mkstemp()
        self.testFileFD = FD.FD(tf[0])

    def test_listfds(self):
        fdin = False
        for fd, path in FDUtils.list_fds():
            if fd == self.testFileFD:
                fdin = True
        self.assertTrue(fdin)

    def tearDown(self):
        self.testFileFD.close()

if __name__ == '__main__':
    unittest.main()
