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
"""Time utilities"""
import signal

from pysec.core import Object, Error


class Timeout(Error):
    pass


RAISE_TIMEOUT = Object()


def timeout(timeout, default=RAISE_TIMEOUT):
    """Decorator for functions, if the returned function doesn't terminate
    after *timeout* seconds and *default* isn't defined a Timeout exception
    will be raised, otherwise return *default* value.
    If it terminate before *timeout* seconds its result will be returned."""
    timeout = int(timeout)
    def raise_timeout(signalnum, frame):
        raise Timeout()
    def _timeout(func):
        def __timeout(*args, **kwds):
            old_handler = signal.signal(signal.SIGALRM, raise_timeout)
            signal.alarm(timeout)
            try: 
                result = func(*args, **kwds)
            except Timeout:
                if default is RAISE_TIMEOUT:
                    raise
                return default
            finally:
                signal.signal(signal.SIGALRM, old_handler)
            signal.alarm(0)
            return result
        return __timeout
    return _timeout

