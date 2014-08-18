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
.. module:: pysec.sys.signal
   :platform: Unix
   :synopsis: The process module define constants and useful functions about signal.

.. moduleauthor:: Federico Figus <figus.federico@gmail.com>, Jone Casper <xu.chenhui@live.com>
"""

import signal

def list_singals():
    """This function will return an iterator with the number of value/signal name

    :return: number/name of signal
    :rtype: iterator
    """
    for name, num in signal.__dict__.iteritems():
        if name.startswith('SIG') and not name.startswith('SIG_'):
            yield (num, name)

def default_all_signals(excepts=[]):
    """Set signal.SIG_DFL for all tranditional signal under signal.SIGRTMIN"""
    #SIGKILL and SIGSTOP can not be caught or ignored
    excepts = excepts + [signal.SIGKILL, signal.SIGSTOP]
    for num, name in list_singals():
        if num not in excepts:
            signal.signal(num, signal.SIG_DFL)

if __name__ == "__main__":
    for num, name in list_singals():
        print name
