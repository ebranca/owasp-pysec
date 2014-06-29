import socket
import select
import errno

from pysec.core import memory, Object
from pysec.xsplit import xbounds
from pysec.net.error import TooBigReply, TooManyFlushData
from pysec import log

__name__ = 'pysec.net.smtp'

# set actions
log.register_actions('SMTP_NEW_SESSION',
                      'SMTP_CONNECT',
                      'SMTP_CLOSE',
                      'SMTP_FLUSH',
                      'SMTP_CMD',
                      'SMTP_PUTCMD',
                      'SMTP_REPLY')

EOL = '\r\n'

SMTP_PORT = 25

CMDS = 'QUIT', 'HELO', 'EHLO', 'HELP', 'NOOP', 'RSET'


def is_1xx(reply):
    return reply[:3].isdigit() and reply[0] == '1'


def is_2xx(reply):
    return reply[:3].isdigit() and reply[0] == '2'


def is_3xx(reply):
    return reply[:3].isdigit() and reply[0] == '3'


def is_4xx(reply):
    return reply[:3].isdigit() and reply[0] == '4'


def is_5xx(reply):
    return reply[:3].isdigit() and reply[0] == '5'


def smtplines(fd, bufsize, timeout):
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


class SMTP_Session(Object):

    @log.wrap(log.actions.SMTP_NEW_SESSION,
              fields=('host', 'port', 'timeout', 'bufsize', 'maxflush'),
              lib=__name__)
    def __init__(self, host, port=SMTP_PORT, timeout=60,
                 bufsize=4096, maxflush=4096):
        self.host = str(host)
        self.port = int(port)
        self.bufsize = int(bufsize)
        self.timeout = int(timeout)
        socket.setdefaulttimeout(self.timeout)
        self.sock = socket.socket()
        self.sock.settimeout(self.timeout)
        self.lines = smtplines(self.sock.fileno(), self.bufsize, self.timeout)
        self.maxflush = int(maxflush)

    @log.wrap(log.actions.SMTP_REPLY, result='reply', lib=__name__)
    def get_reply(self):
        line = self.lines.next()
        code = line[:3]
        yield line
        if len(code) == 3 and line[3:4] == '-' and code.isdigit():
            for line in self.lines:
                yield line
                if line[3:4] == ' ' or not line:
                    break

    @property
    def is_open(self):
        return self.sock.fileno() >= 0;

    @property
    def can_read(self):
        return bool(select.select((self.sock.fileno(),), (), (), 0)[0])

    @log.wrap(log.actions.SMTP_CONNECT, lib=__name__)
    def connect(self):
        self.sock.connect((self.host, self.port))
        return self.get_reply()

    @log.wrap(log.actions.SMTP_CLOSE, lib=__name__)
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

    @log.wrap(log.actions.SMTP_FLUSH, lib=__name__)
    def flush_all(self):
        for _ in self.flush():
            pass

    @log.wrap(log.actions.SMTP_PUTCMD, fields=('cmd', 'args'), lib=__name__)
    def putcmd(self, cmd, args=None):
        self.sock.sendall('%s%s%s' % (cmd, ' ' if args is None
                                               else ' %s ' % args, EOL))

    @log.wrap(log.actions.SMTP_CMD, fields=('cmd', 'args'), lib=__name__)
    def cmd(self, cmd, args=None):
        self.flush_all()
        cmd = str(cmd).upper()
        if cmd not in CMDS:
            raise ValueError("command %r unknown" % cmd)
        self.putcmd(cmd, args)
        return self.get_reply()

    def full_cmd(self, cmd, args=None):
        return ''.join(self.cmd(cmd, args))

    def __enter__(self):
        return self, self.connect()

    def __exit__(self, exc_type, exc_val, exc_trace):
        self.close()
        return 0
