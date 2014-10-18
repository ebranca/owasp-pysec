#!/usr/bin/python2.7 -OOBtt
__doc__ = """Search malicious string in PE files.

Usage: pescan.py [--db=<DB>] [--log=<LOG>] <PATH>...

Options:
    --db=<DB>     database file with malicous strings [default: ./sign-db.txt]
    --log=<LOG>   log type: human (default), pipe

"""
from docopt import docopt

import glob
import os
import struct
import sys

import pysec
from pysec import binary
from pysec.io import fd
from pysec import log
from pysec.strings import erepr
from pysec import tb


MAX_LINE = 4096


# register actions
ACT_LOADDB = log.register_action('LOAD_DB')
ACT_SCANFILE = log.register_action('SCAN_FILE')
ACT_CALCOFFSET = log.register_action('CALCULATE_OFFSET')
ACT_SEARCHSIGNS = log.register_action('SEARCH_SIGNATURES')


# register errors
ERR_WRONGFMT = log.register_error('WRONG_FILE_FORMAT')
ERR_NOTFOUND = log.register_error('SIGNATURE_NOT_FOUND')
ERR_LINETOOBIG = log.register_error('LINE_TOO_LONG')


DOS_HEADER = '<HHHHHHHHHHHHHH8sHH20sI'
FILE_HEADER_SIZE = struct.calcsize('<HHIIIHH')
OPT_HEADER = '<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII'
              

def get_offset(data):
    if len(data) < 64:
        return None
    dos_hdr = data[:64]
    nt_hdr_offset = struct.unpack(DOS_HEADER, dos_hdr)[18]
    offset = nt_hdr_offset + 4 + FILE_HEADER_SIZE
    if len(data) < offset + 96:
        return None
    code_offset = struct.unpack(OPT_HEADER, data[offset:offset+96])[6]
    return None if code_offset < offset + 96 else code_offset


ST_NAME = 1
ST_SIGN = 2
ST_EPONLY = 3


def sign2bmask(sign):
    mask = []
    for part in sign.split(' '):
        if part == '??':
            mask.append('?')
        else:
            chr(int(part, 16))
            mask.append(r'\x%s' % part)
    return ''.join(mask)


@log.wrap(ACT_LOADDB, ('db_path',))
def load_db(db_path):
    db = {}
    with fd.File.open(db_path, fd.FO_READEX) as fp:
        state = ST_NAME
        name = None
        signature = None
        for start, stop in fp.xlines():
            if stop - start >= MAX_LINE:
                log.error(ERR_LINETOOBIG, start=start, end=end)
                continue
            line = fp[start:stop].strip()
            if not line or line[:1] == ';':
                continue
            if state == ST_NAME:
                name = line.strip().strip('[]')
                state = ST_SIGN
            elif state == ST_SIGN:
                signature = sign2bmask(line.partition('=')[2].strip())
                state = ST_EPONLY
            elif state == ST_EPONLY:
                db[signature] = name
                state = ST_NAME
            else:
                raise Exception
    return db


def emit_human(event, time, actions, errcode, fields, info, lib):
    act = actions[0]
    if act == ACT_LOADDB:
        if event == log.EVENT_START:
            sys.stdout.write("Loading db...")
        elif event == log.EVENT_SUCCESS:
            sys.stdout.write(" DONE\n")
        elif event == log.EVENT_END:
            sys.stdout.write("\n")
    elif act == ACT_SCANFILE:
        if event == log.EVENT_START:
            sys.stdout.write("Scan file: %s\n" % erepr(fields['path']))
        elif event == log.EVENT_END:
            sys.stdout.write("\n")
    elif act == ACT_CALCOFFSET:
        if event == log.EVENT_SUCCESS:
            sys.stdout.write("Offset code: %s\n" % hex(info['offset']))
        elif event == log.EVENT_ERROR and errcode == ERR_WRONGFMT:
            sys.stdout.write("ERROR: Wrong file format")
    elif act == ACT_SEARCHSIGNS:
        if event == log.EVENT_SUCCESS:
            sys.stdout.write("Found signature %r at %s\n" % (info['name'], hex(info['pos'])))
        elif event == log.EVENT_ERROR and errcode == ERR_NOTFOUND:
            sys.stdout.write("Signature not found\n")
    sys.stdout.flush()


def emit_pipe(event, time, actions, errcode, fields, info, lib):
    act = actions[0]
    if act == ACT_SEARCHSIGNS:
        if event == log.EVENT_SUCCESS:
            sys.stdout.write('|'.join(('FOUND', repr(fields['path']), hex(info['pos'])[2:], repr(info['name']))))
            sys.stdout.write('\n')
        elif event == log.EVENT_ERROR and errcode == ERR_NOTFOUND:
            sys.stdout.write('|'.join(('NOTFOUND', repr(fields['path']), '', '')))
            sys.stdout.write('\n')
    elif act == ACT_CALCOFFSET and errcode == ERR_WRONGFMT:
        sys.stdout.write('|'.join(('WRONGFMT', repr(fields['path']), '', '')))
        sys.stdout.write('\n')
    sys.stdout.flush()


def _pescan():
    opts = docopt(__doc__)
    emitter = opts['--log']
    if emitter is None or emitter == 'human':
        emitter = emit_human
    elif emitter == 'pipe':
        emitter = emit_pipe
    elif emitter == 'classic':
        emitter = log.emit_simple
    else:
        raise ValueError("Unknown log type")
    #
    pysec.init("PEscan", emitter=emitter)
    #
    db_path = os.path.abspath(opts['--db'])
    paths = opts['<PATH>']
    #
    db = load_db(db_path)
    for path in paths:
        path = os.path.abspath(path)
        for path in glob.iglob(path):
            if not os.path.isfile(path):
                continue
            with log.ctx(ACT_SCANFILE, {'path': path}), \
                 fd.File.open(path, fd.FO_READEX) as fp:
                with log.ctx(ACT_CALCOFFSET):
                    offset = get_offset(fp)
                    if offset is None:
                        log.error(ERR_WRONGFMT, size=len(fp))
                        continue
                    log.ok(offset=offset)
                with log.ctx(ACT_SEARCHSIGNS):
                    n = -1
                    for n, (pos, pattern, name) in enumerate(binary.byte_msearch(fp, db, offset)):
                        log.success(n=n, pos=pos, name=name)
                    if n == -1:
                        log.error(ERR_NOTFOUND)


if __name__ == '__main__':
    _pescan()

