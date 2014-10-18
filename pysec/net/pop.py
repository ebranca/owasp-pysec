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
"""Implementations of POP protocols"""
import errno
import select
import socket
from pysec.core import memory, Object
from pysec.xsplit import xbounds
from pysec.net.error import TooBigReply, TooManyFlushData
from pysec import log

__name__ = 'pysec.net.pop'

# set actions
log.register_actions('POP3_NEW_SESSION',
                      'POP3_CONNECT',
                      'POP3_CLOSE',
                      'POP3_FLUSH',
                      'POP3_CMD',
                      'POP3_PUTCMD',
                      'POP3_SIMPLEREPLY',
                      'POP3_MULREPLY')


EOL = '\r\n'
MULTI_END = '.%s' % EOL

POP3_PORT = 110

OK_REPLY = 1
ERR_REPLY = 0
UNKNOWN_REPLY = -1


def is_ok(reply):
    return reply.startswith('+OK')


def is_err(reply):
    return reply.startswith('+ERR')


QUIT = 0
# TODO other commands
CMDS = 'QUIT',
MULTI = ()


def poplines(fd, bufsize, timeout):
    mem = memory.Memory(bufsize)
    timeout = int(timeout)
    rem = mstart = mend = 0
    while 1:
        # move
        if mstart > 0:
            mem[0:mend-mstart] = mem[mstart:mend]
        # fill
        if not select.select((fd,), (), (), timeout)[0]:
            raise socket.timeout
        mend += mem.read(fd, mend, mem.size - mend)
        if not mend:
            yield ''
            break
        #
        for start, end in xbounds(mem, EOL, 1, 0, mend):
            if mem[end-len(EOL):end] == EOL:
                yield mem[start:end]
                rem = end
            else:
                if (end-start) == mem.size:
                    raise TooBigReply()
        mem[0:mend-rem] = mem[rem:mend]
        mend -= rem


class POP3_Session(Object):

    @log.wrap(log.actions.POP3_NEW_SESSION,
              fields=('host', 'port', 'timeout', 'bufsize', 'maxflush'),
              lib=__name__)
    def __init__(self, host, port=POP3_PORT, timeout=60,
                 bufsize=4096, maxflush=4096):
        self.host = str(host)
        self.port = int(port)
        self.bufsize = int(bufsize)
        self.timeout = int(timeout)
        socket.setdefaulttimeout(self.timeout)
        self.sock = socket.socket()
        self.sock.settimeout(self.timeout)
        self.lines = poplines(self.sock.fileno(), self.bufsize, self.timeout)
        self.maxflush = int(maxflush)

    @log.wrap(log.actions.POP3_SIMPLEREPLY, result='reply', lib=__name__)
    def get_reply(self):
        return self.lines.next()

    @log.wrap(log.actions.POP3_MULREPLY, result='reply', lib=__name__)
    def get_multi_reply(self):
        for line in self.lines:
            if line == MULTI_END:
                yield line
                break
            yield line

    @property
    def is_open(self):
        return self.sock.fileno() >= 0

    @property
    def can_read(self):
        return bool(select.select((self.sock.fileno(),), (), (), 0)[0])
                
    def connect(self):
        self.sock.connect((self.host, self.port))
        return self.get_reply()

    @log.wrap(log.actions.POP3_CLOSE, lib=__name__)
    def close(self):
        sock = self.sock
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except IOError, ex:
            if ex.args[0] != errno.ENOTCONN:
                raise
        finally:
            sock.close()

    def flush(self):
        size  = 0
        while self.can_read:
            chunk = self.sock.recv(self.bufsize)
            size += len(chunk)
            if size > self.maxflush:
                raise TooManyFlushData()
            yield self.sock.recv(self.bufsize)

    @log.wrap(log.actions.POP3_FLUSH, lib=__name__)
    def flush_all(self):
        for _ in self.flush():
            pass

    @log.wrap(log.actions.POP3_PUTCMD, fields=('cmd', 'args'), lib=__name__)
    def putcmd(self, cmd, args=None):
        self.sock.sendall('%s%s%s' % (cmd, ' ' if args is None
                                               else ' %s ' % args, EOL))

    @log.wrap(log.actions.POP3_CMD, fields=('cmd', 'args'), lib=__name__)
    def cmd(self, cmd, args=None):
        self.flush_all()
        cmd = str(cmd).upper()
        if cmd not in CMDS:
            raise ValueError("command %r unknown" % cmd)
        self.putcmd(cmd, args)
        if cmd in MULTI:
            return self.get_multi_reply()
        else:
            return self.get_reply()

    def __enter__(self):
        return self, self.connect()

    def __exit__(self, exc_type, exc_val, exc_trace):
        self.close()
        return 0
