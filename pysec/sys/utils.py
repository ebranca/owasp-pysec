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
.. module:: pysec.sys.utils
   :platform: Unix
   :synopsis: Some useful functions about process, resource and others.

.. moduleauthor:: Federico Figus <figus.federico@gmail.com>, Jone Casper <xu.chenhui@live.com>

"""
from pysec.core import Error, Object
import resource, sys
is_mswindows = (sys.platform == "win32")

class SYSUtilError(Error):
    """Generic util moulde's error"""
    def __init__(self, *args, **kwargs):
        super(SYSUtilError, self).__init__(*args, **kwargs)
        
class SYSUtilResourceError(SYSUtilError, OSError):
    """ Exception raised when environment setup error. """
    
class Resource(Object):
    def __init__(self):
        if is_mswindows:
            raise NotImplementedError('Unsupported platform: %s' % sys.platform)
        super(Resource, self).__init__()
    
    def check_resource_env(self, setting):
        """ Determines whether the resource setting is supported.
        If the OS not support the resource setting, the function will raise SYSUtilResourceError"""
        try:
            resource.getrlimit(setting)
        except ValueError:
            error = SYSUtilResourceError(
                "System does not support RLIMIT_CORE resource limit (%(exc)s)"
                % vars())
            raise error
        
    def prevent_core_dump(self):
        """ Prevent this process from generating a core dump.

        Sets the soft and hard limits for core dump size to zero. On Unix, this prevents the process from creating core dump altogether.
        """
        self.check_resource_env(resource.RLIMIT_CORE)

        # Set hard and soft limits to zero, i.e. no core dump at all
        core_limit = (0, 0)
        resource.setrlimit(resource.RLIMIT_CORE, core_limit)
    
    def limit_fork(self, limit = None):
        """ Limit this process invoke fork() to create processes.
        
        Set this limits can prevent from process forking infinitely(fork bumb) """
        self.check_resource_env(resource.RLIMIT_NPROC)
        
        fork_limit = (0, 0)
        if isinstance(limit, int):
            fork_limit = (limit, limit)
        if isinstance(limit, tuple):
            fork_limit = limit 
        resource.setrlimit(resource.RLIMIT_NPROC, fork_limit)
