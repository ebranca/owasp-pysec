#!/usr/bin/env python
# coding=utf-8

import unittest
import signal,os
from pysec.sys.psignal import list_singals, default_all_signals

class TestSignalUtil(unittest.TestCase):
    def setUp(self):
        self.count = 0
        def handler(signum, frame):
            self.count += 1
            print "A signal occured"
        signal.signal(signal.SIGUSR1, handler)

    def test_list_signals(self):
        all_signals = dict([(num, name) for num, name in list_singals()])
        self.assertTrue(signal.SIGKILL in all_signals)

    def test_setDefault(self):
        default_all_signals()

        os.kill(os.getpid(), signal.SIGUSR1)
        self.assertEqual(self.count, 0)

    def tearDown(self):
        signal.signal(signal.SIGALRM, signal.SIG_DFL)

if __name__ == "__main__":
    unittest.main()
