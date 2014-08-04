# Python Security Project (PySec) and its related class files.
#
# PySec is a set of tools for secure application development under Linux
#
# Copyright 2014 PySec development team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# -*- coding: ascii -*-

"""
.. module:: pysec.sys.process
   :platform: Unix
   :synopsis: The process module define constants and useful functions about process.
   We will try to import psutil module for platform compatibility, otherwise the module can only run in the Unix plarform currently.

.. moduleauthor:: Federico Figus <figus.federico@gmail.com>, Jone Casper <xu.chenhui@live.com>

"""
from pysec.core import Error
import sys, glob

psutil_has_import = False
try:
    import psutil
    psutil_has_import = True
except ImportError:
    psutil_has_import = False

class ProcessError(Error):
    """Generic process moulde's errorfor"""
    def __init__(self, pid):
        super(ProcessError, self).__init__()
        self.pid = int(pid) 
        

class ProcessUtil:
    def __init__(self):
        pass

    @staticmethod
    def list_pid():
        """This function will return an iterator with the process pid/cmdline tuple

        :return: pid, cmdline tuple via iterator
        :rtype: iterator

        >>> for procs in list_processes():
        >>>     print procs
        ('5593', '/usr/lib/mozilla/kmozillahelper')
        ('6353', 'pickup -l -t fifo -u')
        ('6640', 'kdeinit4: konsole [kdeinit]')
        ('6643', '/bin/bash')
        ('7451', '/usr/bin/python /usr/bin/ipython')
        """
        for pid_path in glob.glob('/proc/[0-9]*/'):
            pid = pid_path.split("/")[2] # get the PID
            # cmdline represents the command whith which the process was started
            try:
                with open("%s/cmdline" % pid_path) as fd:
                    # we replace the \x00 to spaces to make a prettier output from kernel
                    cmdline = fd.read().replace("\x00", " ").rstrip()
                    yield (pid, cmdline)
            except IOError:
                # proc has already terminated
                continue

    @staticmethod
    def get_pid_list():
        """Get running process list"""
        if psutil_has_import:
            return psutil.get_pid_list()
        else:
            if not sys.platform.startswith('linux'):
                raise NotImplementedError('Unsupported platform: %s' % sys.platform)
            return [int(pid) for pid, cmdline in ProcessUtil.list_pid()]
        
    @staticmethod
    def is_running_process(pid):
        """Check whether the process owned the pid is running"""
        pid = int(pid)
        if pid < 0:
            raise ValueError("Invalid pid value")


if __name__ == "__main__":
    #some test
    pids = ProcessUtil.get_pid_list()
    print(pids)