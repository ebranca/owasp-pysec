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
.. module:: pysec.sys.popen
   :platform: Unix
   :synopsis: The popen module support a safety Popen function based on subprocess.Popen .
   We will force to set some setting for making a safety environment before executing exec*, such as:
   - Set uid, gid (Force to change the process's owner and owner group to which set in the /etc/pysec/pysec.conf if not specified).
   - Change working directory (optional).
   - Close all file descriptors except 0, 1 and 2.
   - All signals restored to default function (restore_signals was added after Python 3.2 but just restored SIGPIPE, SIGXFZ and SIGXFSZ signals).
   - Prevent core dump.
   - Limit fork , default prohibit forking process completely.

.. moduleauthor:: Federico Figus <figus.federico@gmail.com>, Jone Casper <xu.chenhui@live.com>

"""
from pysec.core import Error, Object
from pysec.sys.psignal import default_all_signals
from pysec.sys.utils import Resource
from subprocess import Popen as _popen
import os.path, sys, warnings
try:
    from configparser import ConfigParser
except ImportError:
    #for python 2.x
    from ConfigParser import ConfigParser

is_mswindows = (sys.platform == "win32")
if not is_mswindows:
    import pwd, grp

class PopenSystemError(Error, OSError):
    """ Exception raised when the environment setup receives error. """

class Popen(_popen):
    """
    Execute a child program in a new process. We only list which the characteristic parameters, others please see the python's document.

    :param args: args should be a sequence of program arguments or else a single string.
    :param close_fds: By default, we will close all file descriptors except 0, 1 and 2.
    :param restore_signals: By default, all signals restored to default function.
    :param start_new_session: the setsid() system call will be made in the child process
    :param uid: change the process's owner
    :param gid: change the process's owner group
    :param working_directory: change_working directory, same as the cwd parameter
    :param root_directory: change_root directory by invoking chroot()
    :param prevent_coredump: By default, the chile process ban makeing the core dump file only if the setting is False
    :param limit_fork: By default, prohibit forking process completely in child process
    :param conf: The config file which defined the defualt owner and owner group.The defualt location is /etc/pysec/pysec.conf.
    """
    def __init__(self, args, 
                 uid = None, 
                 gid = None,
                 working_directory = None,
                 root_directory = None,
                 prevent_coredump = True,
                 limit_fork = True,
                 conf = "/etc/pysec/pysec.conf", 
                 **kwargs):

        if not is_mswindows:
            user, group = self._initConfig(conf)
            #init user id
            if uid is not None:
                self.uid = int(uid)
            elif user is not None:
                self.uid = self._getuid(user)
            else:
                self.uid = None
            
            #init group id
            if gid is not None:
                self.gid = int(gid)
            elif group is not None:
                self.gid = self._getgid(group)
            else:
                self.gid = None

            if self.uid == 0 or (self.uid is None and os.getuid() == 0):
                warnings.warn('We strongly recommend not to run script using root privilege even though you trust it.', RuntimeWarning)

            self.working_directory = working_directory or kwargs.get('cwd')
            self.root_directory = root_directory
            self._preexec_fn = kwargs.get('preexec_fn')

            #pass signals
            if kwargs.get('pass_signals'):
                self.pass_signals = kwargs.get('pass_signals')
                del kwargs["pass_signals"]
            else:
                self.pass_signals = ()

            #start_new_session
            self.start_new_session = kwargs.get('start_new_session', False)
            if sys.hexversion < 0x03020000 and 'start_new_session' in kwargs:
                del kwargs['start_new_session']
            else:
                kwargs['start_new_session'] = False

            #restore_signals
            self.restore_signals = kwargs.get('restore_signals', True)
            if sys.hexversion < 0x03020000 and 'restore_signals' in kwargs:
                del kwargs['restore_signals']
            
            self.prevent_coredump = prevent_coredump
            self.limit_fork = limit_fork

            if sys.hexversion < 0x03020000 and kwargs.get('close_fds') is not False:
                kwargs['close_fds'] = True

            #We will call chdir at the end of the preexec_fn to make sure some function can work on normally.
            kwargs['cwd'] = None

            self.old_preexec_fn = kwargs.get('preexec_fn')
            kwargs['preexec_fn'] = self.preexec_fn
        else:
            kwargs['close_fds'] = True

        super(Popen, self).__init__(args, **kwargs)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self.stdout:
            self.stdout.close()
        if self.stderr:
            self.stderr.close()
        if self.stdin:
            self.stdin.close()
        # Wait for the process to terminate, to avoid zombies.
        self.wait()
        
    def _getuid(self, user):
        uid = None
        if user is None:
            return None

        try:
            uid = int(user)
        except ValueError:
            try:
                pstruct = pwd.getpwnam(user)
                uid = pstruct.pw_uid
            except KeyError, exc:
                error = PopenSystemError(
                    "Get uid by name error (%(exc)s)"
                )
                raise error
        return uid

    def _getgid(self, group):
        gid = None
        if group is None:
            return None
        try:
            gid = int(group)
        except ValueError:
            try:
                gstruct = grp.getgrnam(group)
                gid = gstruct.gr_gid
            except KeyError, exc:
                error = PopenSystemError(
                    "Get gid by name error (%(exc)s)"
                )
                raise error
        return gid

    def _initConfig(self, conf = "/etc/pysec/pysec.conf"):
        """Read the default user and group configure in /etc/pysec/pysec.conf 
        """
        if not os.path.exists(conf):
            return 
        config = ConfigParser()
        config.read(conf)
        user = config.get('SYSTEM', 'user') 
        group = config.get('SYSTEM', 'group')
        return user, group

    def change_working_directory(self, directory):
        """ Change the working directory of this process.
        """
        try:
            os.chdir(directory)
        except Exception, exc:
            error = PopenSystemError(
                "Unable to change working directory (%(exc)s)"
            )
            raise error
    
    def change_root_directory(self, directory):
        """ Change the working directory of this process.
        """
        try:
            os.chroot(directory)
        except Exception, exc:
            error = PopenSystemError(
                "Unable to change root directory (%(exc)s)"
            )
            raise error


    def preexec_fn(self):
        """ This function will be as the preexec_fn parameter in subprocess.Popen"""
        #set uid, gid
        if self.gid is not None:
            os.setgid(self.gid)
        if self.uid is not None:
            os.setuid(self.uid)

        #close file descriptors
        #We can only use the close_fd parameter because the subprocess.Popen will be created a fuck errpipe_write for reading transferring possible exec failure that we can not close nor distinguish
        #if sys.hexversion < 0x03020000:
        #    exclude = [0,1,2] + list(self.pass_fds)
        #    FDUtils.close_all_open_fds(exclude = exclude)
 
        #set all signals to default
        if self.restore_signals:
            default_all_signals(excepts=list(self.pass_signals))
        
        #set working and root directory
        if self.working_directory is not None:
            self.change_working_directory(self.working_directory)
        if self.root_directory is not None:
            self.change_root_directory(self.root_directory)

        if self.start_new_session:
            os.setsid()

        try:
            rs = Resource()
            #prevent core dump
            if self.prevent_coredump is True:
                rs.prevent_core_dump()
            #set limit fork
            if self.limit_fork is not None:
                rs.limit_fork(limit = self.limit_fork)
        except Exception, exc:
            warnings.warn("Set the resource limit failed, maybe we had some privilege's problems. (%(exc)s)")

        if self.old_preexec_fn:
            self.old_preexec_fn()

if __name__ == "__main__":
    from subprocess import PIPE
    p = Popen(['ls', '-la'], stdout=PIPE, working_directory="/home/" ,start_new_session=True)
    if p.wait() != 0:
        print "Error"
    else:
        for line in p.stdout:
            print line
