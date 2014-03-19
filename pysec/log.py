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
"""Log module"""
from contextlib import contextmanager
import time
import types
import inspect
import errno
from .core.monotonic import monotonic_time

EVENT_START = 0
EVENT_SUCCESS = 1
EVENT_WARNING = 2
EVENT_ERROR = 3
EVENT_CRITICAL = 4
EVENT_END = 5

EVENT_NAMES = 'start', 'success', 'warning', 'error', 'critical', 'end'


__all__ = 'start', 'success', 'warning', 'error', 'critical', 'end', \
          'start_log', 'LogError', 'wrap', 'ctx', \
          'add_local_emit', 'add_global_emit', 'register_action', \
          'register_actions', 'get_action_code', 'get_action_name', 'errors'


class LogError(Exception):
    pass


class Logger(object):

    def __init__(self, action, fields=None, parent=None, timer=time.time):
        self.act = int(action)
        self.fields = {} if fields is None else dict(fields)
        self.parent = parent
        self.global_emits = []
        self.__local_emits = []
        self._time_offset = monotonic_time()
        self.start_time = int(timer if isinstance(timer, (int, long))
                          else timer()) 

    def add_global_emit(self, emiter):
        self.global_emits.append(emiter)

    def add_local_emit(self, emiter):
        self.__local_emits.append(emiter)

    def subaction(self, action, fields=None):
        return Logger(action, fields, self, self.start_time)

    def actions(self):
        log = self
        while log:
            yield log.action
            log = log.parent

    def all_fields(self):
        log = self
        while log:
            yield log.fields
            log = log.parent

    def log(self, event, errcode, info):
        time = self.start_time + (monotonic_time() - self._time_offset) 
        log = self
        while log:
            actions = tuple(self.actions())
            fields = {}
            for fds in self.all_fields():
                fields.update(fds)
            for em in log.__local_emits:
                em(event, time, actions, int(errcode), fields, info)
            for em in log.global_emits:
                em(event, time, actions, int(errcode), fields, info)
            log = log.parent


    def action(self, action=None, info=None, res_hdl=None,
               ex_hdl=None, reraise=1):
        def _action(fun):
            def __action(*args, **kwds):
                log = self if action is None else self.subaction(action)
                try:
                    log.start()
                    res = res_hdl(fun(*args, **kwds))
                    log.success(**res)
                except Exception, ex:
                    log.error(*ex_hdl(ex))
                    if reraise:
                        raise
                finally:
                    log.end()
            return __action
        return _action

    @contextmanager
    def ctx(self, action, info=None):
        log = self.subaction(action, info)
        if info is None:
            info = {}
        log.start()
        yield log
        log.end()

    def wrap(self, action):
        def _wrap(fun):
            def __wrap(*args, **kwargs):
                with self.ctx(action) as log:
                    # FIXME
                    kwargs['log'] = log
                    fun(*args, **kwargs)
            return __wrap
        return _wrap

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.end()
        return 0

    def __str__(self):
        return '<Logger %r:%r>' % (tuple(self.actions()), self.fields)


def start_log(action, fields=None, timer=time.time):
    frame = inspect.currentframe().f_back
    if frame.f_locals.get('__log__', None):
        raise LogError("log already set")
    frame.f_locals['__log__'] = Logger(action, fields, None, timer)


def push_log(frame, action, fields=None):
    frame = frame.f_back
    log = frame.f_locals.get('__log__', None)
    if log:
        parent = log
    else:
        parent = get_log()
    log = frame.f_locals['__log__'] = Logger(action, fields, parent,
                                       parent.start_time)
    return log


def pop_log(frame):
    frame = frame.f_back
    while frame:
        log = frame.f_locals.get('__log__', None)
        if log:
            frame.f_locals['__log__'] = log.parent
            return log
        frame = frame.f_back
    raise LogError("no log started")


def get_log(exc=1):
    frame = inspect.currentframe().f_back
    while frame:
        log = frame.f_locals.get('__log__', None)
        if log:
            return log
        frame = frame.f_back
    if exc:
        raise LogError("no log started")
    return None


# log actions
def start(**info):
    get_log().log(EVENT_START, 0, info)


def end(**info):
    get_log().log(EVENT_END, 0, info)


def success(**info):
    get_log().log(EVENT_SUCCESS, 0, info)


ok = success


def warning(errcode, **info):
    get_log().log(EVENT_WARNING, errcode, info)


def error(errcode, **info):
    get_log().log(EVENT_ERROR, errcode, info)


def critical(errcode, **info):
    get_log().log(EVENT_CRITICAL, errcode, info)


def add_global_emit(emit):
    get_log().add_global_emit(emit)


def add_local_emit(emit):
    get_log().add_local_emit(emit)


@contextmanager
def ctx(action, fields=None):
    push_log(inspect.currentframe().f_back, action, fields)
    start()
    yield
    end()
    pop_log(inspect.currentframe().f_back)


def wrap(action, fields=(), result=None, err_hdl=None, lib=0):
    if result is not None:
        result = str(result)
    def _fun(fun):
        def __fun(*args, **kwargs):
            kwds = inspect.getcallargs(fun, *args, **kwargs)
            if get_log(lib):
                push_log(inspect.currentframe(),
                         action,
                         {key: kwds[key] for key in fields if key in kwds})
                try:
                    start()
                    val = fun(**kwds)
                    if result is not None:
                        success(**{result: val})
                    else:
                        success()
                    return val
                except Exception, ex:
                    if err_hdl is not None:
                        errcode, info = err_hdl(ex)
                        error(errcode, **info)
                    raise
                finally:
                    end()
                    pop_log(inspect.currentframe())
            else:
                return fun(**kwds)
        return __fun
    return _fun

# ERRORS
ERRORS = {}
ERR_NAMES = {}


def register_error(name, code=None):
    if code is None:
        code = min(-1, *ERRORS.keys()) + 1
    code = int(code)
    name = str(name).lower()
    if code < 0:
        raise ValueError("invalid negative integer like action code: %d" % code)
    if code in ERRORS:
        raise ValueError("code already present: %d" % code)
    if name in ERR_NAMES:
        raise ValueError("name already present: %r" % name)
    ERRORS[code] = name
    ERR_NAMES[name] = code
    return code


def register_errors(*onlynames, **withcodes):
    for name in onlynames:
        register_error(name)
    for name, code in withcodes.iteritems():
        register_error(name, code)


def get_error_code(name):
    return ERR_NAMES[name]


def get_error_name(code):
    return ERRORS[code]


# ACTIONS
ACTIONS = {}
ACT_NAMES = {}


def register_action(name, code=None):
    if code is None:
        code = min(-1, *ACTIONS.keys()) + 1
        if code < 0:
            code = 0
    code = int(code)
    name = str(name).lower()
    if code < 0:
        raise ValueError("invalid negative integer like action code: %d" % code)
    if code in ACTIONS:
        raise ValueError("code already present: %d" % code)
    if name in ACT_NAMES:
        raise ValueError("name already present: %r" % name)
    ACTIONS[code] = name
    ACT_NAMES[name] = code
    return code


def register_actions(*onlynames, **withcodes):
    for name in onlynames:
        register_action(name)
    for name, code in withcodes.iteritems():
        register_action(name, code)


def get_action_code(name):
    return ACT_NAMES[name]


def get_action_name(code):
    return ACTIONS[code]


# import default errors
register_errors(**{
    'perm': 1,
    'noent': 2,
    'srch': 3,
    'intr': 4,
    'io': 5,
    'nxio': 6,
    'toobig': 7,
    'noexec': 8,
    'badf': 9,
    'child': 10,
    'again': 11,
    'nomem': 12,
    'acces': 13,
    'fault': 14,
    'notblk': 15,
    'busy': 16,
    'exist': 17,
    'xdev': 18,
    'nodev': 19,
    'notdir': 20,
    'isdir': 21,
    'inval': 22,
    'nfile': 23,
    'mfile': 24,
    'notty': 25,
    'txtbsy': 26,
    'fbig': 27,
    'nospc': 28,
    'spipe': 29,
    'rofs': 30,
    'mlink': 31,
    'pipe': 32,
    'dom': 33,
    'range': 34,
    'deadlock': 35,
    'nametoolong': 36,
    'nolck': 37,
    'nosys': 38,
    'notempty': 39,
    'loop': 40,
    'nomsg': 42,
    'idrm': 43,
    'chrng': 44,
    'l2nsync': 45,
    'l3hlt': 46,
    'l3rst': 47,
    'lnrng': 48,
    'unatch': 49,
    'nocsi': 50,
    'l2hlt': 51,
    'bade': 52,
    'badr': 53,
    'xfull': 54,
    'noano': 55,
    'badrqc': 56,
    'badslt': 57,
    'bfont': 59,
    'nostr': 60,
    'nodata': 61,
    'time': 62,
    'nosr': 63,
    'nonet': 64,
    'nopkg': 65,
    'remote': 66,
    'nolink': 67,
    'adv': 68,
    'srmnt': 69,
    'comm': 70,
    'proto': 71,
    'multihop': 72,
    'dotdot': 73,
    'badmsg': 74,
    'overflow': 75,
    'notuniq': 76,
    'badfd': 77,
    'remchg': 78,
    'libacc': 79,
    'libbad': 80,
    'libscn': 81,
    'libmax': 82,
    'libexec': 83,
    'ilseq': 84,
    'restart': 85,
    'strpipe': 86,
    'users': 87,
    'notsock': 88,
    'destaddrreq': 89,
    'msgsize': 90,
    'prototype': 91,
    'noprotoopt': 92,
    'protonosupport': 93,
    'socktnosupport': 94,
    'notsup': 95,
    'pfnosupport': 96,
    'afnosupport': 97,
    'addrinuse': 98,
    'addrnotavail': 99,
    'netdown': 100,
    'netunreach': 101,
    'netreset': 102,
    'connaborted': 103,
    'connreset': 104,
    'nobufs': 105,
    'isconn': 106,
    'notconn': 107,
    'shutdown': 108,
    'toomanyrefs': 109,
    'timedout': 110,
    'connrefused': 111,
    'hostdown': 112,
    'hostunreach': 113,
    'already': 114,
    'inprogress': 115,
    'stale': 116,
    'uclean': 117,
    'notnam': 118,
    'navail': 119,
    'isnam': 120,
    'remoteio': 121,
    'dquot': 122
})


class _Errors(object):

    def __getattr__(self, name):
        name = str(name).lower()
        code = ERR_NAMES.get(name, None)
        if code is None:
            raise AttributeError("error %r not found" % name)
        return int(code)


errors = _Errors()
