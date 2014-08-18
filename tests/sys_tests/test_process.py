#!/usr/bin/env python
# coding=utf-8

import unittest
import multiprocessing, time
from pysec.sys.process import get_pids_list, process_is_alive

class TestProcessUtil(unittest.TestCase):
    def setUp(self):
        self.proc = multiprocessing.Process(target=time.sleep, args=(1000,))
        self.proc.start()

    def test_get_pid_list(self):
        self.assertTrue(self.proc.pid in get_pids_list())

    def test_is_alive(self):
        self.assertTrue(process_is_alive(self.proc.pid))
        
    def tearDown(self):
        self.proc.terminate()

if __name__ == "__main__":
    unittest.main()
