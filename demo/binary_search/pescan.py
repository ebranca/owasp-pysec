#!/usr/bin/python2.7 -OOBRtt
__doc__ = """Search malicious string in PE files.

Usage: pescan (--db=<DB> | --db-kc | --db-txt) <PATH>
       pescan --txt2kc <TXT> <KYOTO>

Options:
    --db=<DB>   database file with malicous strings
    --txt2kc    parse txt db to Kyoto Cabinet db

"""
import os
import struct
import sys

from docopt import docopt

from pysec import alg
from pysec import binary
from pysec.io import fd
from pysec.kv.kyoto import KyotoKV
from pysec import log
from pysec import tb


tb.set_excepthook(tb.long_tb)

KV = dict


DOS_HEADER = '<HHHHHHHHHHHHHH8sHH20sI'
FILE_HEADER = '<HHIIIHH'
OPT_HEADER = '<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII'
              



def get_offset(data):
    if len(data) < 64:
        return None
    dos_hdr = data[:64]
    nt_hdr_offset = struct.unpack(DOS_HEADER, dos_hdr)[18]
    offset = nt_hdr_offset + 4 + struct.calcsize(FILE_HEADER)
    if len(data) < offset + 96:
        return None
    return struct.unpack(OPT_HEADER, data[offset:offset+96])[6]


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


def load_db_txt(path):
    db = KV()
    with fd.File.open(path, fd.FO_READEX) as fp:
        state = ST_NAME
        name = None
        signature = None
        for line in fp.readlines():
            line = line.strip()
            if not line:
                continue
            if state == ST_NAME:
                name = line.partition(' -> ')[0].strip('[]')
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


def load_db_kyoto(path):
    return KyotoKV(path)
    


EXT2LOADER = {
    '.txt': load_db_txt,
    '.kch': load_db_kyoto
}

def _pescan():
    opts = docopt(__doc__)
    #
    if opts['--txt2kc']:
        print '== TXT to KCH'
        with KyotoKV(opts['<KYOTO>']) as kv:
            for key, value in load_db_txt(opts['<TXT>']).iteritems():
                kv[key] = value
    else:
        print '== SEARCHING SIGNATURE'
        print "Loading signatures db..."
        if opts['--db']:
            db_path = opts['--db']
            load_db = EXT2LOADER.get(os.path.splitext(db_path)[1], None)
            if load_db is None:
                raise ValueError("unknown file extension")
        elif opts['--db-txt']:
            db_path = opts['--db-txt']
            load_db = load_db_txt
        elif opts['--db-kyoto']:
            db_path = opts['--db-kyoto']
            load_db = load_db_kc
        db = load_db(db_path)
        # with fd.File.open(path, fd.FO_READEX) as fp:
        path = os.path.abspath(opts['<PATH>'])
        with fd.File.open(path, fd.FO_READEX) as fp:
            offset = get_offset(fp)
            print "Offset: %s" % hex(offset)
            print "Searching signatures (%d)..." % len(db)
            state = 0
            step = len(db) // 10                
            #
            for pos, pattern, name in binary.byte_msearch(fp, db, offset):
                print "PATTERN FOUND at %d: %r" % (pos, name)
        print

if __name__ == '__main__':
    _pescan()

