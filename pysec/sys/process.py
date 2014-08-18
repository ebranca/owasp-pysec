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

is_mswindows = (sys.platform == "win32")

class ProcessError(Error):
    """Generic process moulde's error"""
    def __init__(self, pid):
        super(ProcessError, self).__init__()
        self.pid = int(pid) 
        
def list_processes():
    """This function will return an iterator with the process pid/cmdline tuple

    :return: pid, cmdline tuple via iterator
    :rtype: iterator

    >>> for procs in Process.list_processes():
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
    
def get_pids_list():
    """Get running process list"""
    if psutil_has_import:
        return psutil.get_pid_list()
    else:
        if is_mswindows:
            raise NotImplementedError('Unsupported platform: %s' % sys.platform)
        return [int(pid) for pid, cmdline in list_processes()]

def process_is_alive(pid):
    """Check whether the process owned the pid is running"""
    pid = int(pid)
    if pid < 0:
        raise ValueError("Invalid pid value")
    return pid in get_pids_list()


if __name__ == "__main__":
    #some test
    pids = get_pids_list()
    print(pids)
