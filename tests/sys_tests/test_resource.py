#!/usr/bin/env python
# coding=utf-8

import unittest
import os, sys, resource
from pysec.sys.utils import Resource

class TestResourceUtil(unittest.TestCase):
    def test_fork_limit(self):
        try:
            pid = os.fork()
            if pid == 0:
                #In children
                rs = Resource()
                rs.limit_fork()

                try:
                    cpid = os.fork()
                    if cpid < 0:
                        os._exit(0)
                    os._exit(1)
                except OSError:
                    os._exit(0)
            else:
                pid, status = os.waitpid(pid, 0)
                if os.WEXITSTATUS(status) != 0:
                    self.fail("RLIMIT_NPROC not enforced")
        except OSError:
            self.fail("Fork error!!")

if __name__ == "__main__":
    unittest.main()
