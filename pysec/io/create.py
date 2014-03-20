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
from . import fd
from itertools import chain
from . import fcheck
import os
from . import temp

SYS_PATH = '/'
MIN_FDS = 64
#               128 MiB
BIG_FILE_SIZE = 128 * 1024 * 1024
#          1 MiB
CTL_SIZE = 1024 * 1024

_TEST_LINE = ''.join(chr(n) for n in xrange(0, 256))


def fill_zero(bufsize=4096):
    chunk = 'f' * bufsize
    while 1:
        yield chunk


def create_and_fill(fpath, dirtemp, size, filler, tries, fhash):
    """Crea un nuovo file di dimensione *size* e lo riempe con i risultati del
    iteratore filler, se l'iteratore non fornisce abbastanza dati, lo spazio
    rimanente sara' riempito da '\0'.
    *temp* indica la cartella temporanea usata per la creazione e il
    riempimento.
    *tries* indica il numero di prove da effettuare quando un'operazione non
    viene portata a termine con successo.
    *fhash* e' una funzione che rendere un oggetto per calcolare l'hash di una
    porzione del file, verra' utilizzata quando servira' il check su file di
    grandi dimensioni."""
    fpath = os.path.abspath(str(fpath))
    dirout = os.path.dirname(fpath)
    size = int(size)
    if size < 0:
        raise ValueError
    _tries = tries = int(tries)
    ### Preconditions
    print "== CHECKS"
    # check sys dir
    fcheck.ino_check(SYS_PATH, 64)
    # check temp dir
    fcheck.ino_check(dirtemp, 64)
    fcheck.space_check(dirtemp, 3 * size)
    # check destination dir
    fcheck.ino_check(dirout, 64)
    fcheck.space_check(dirout, 3 * size)
    # check temp permission rwx
    # with temp.mkdtemp(dirtemp, '~', '.TMP') as dtmp:
    dtmp = temp.mkdtemp(dirtemp, '~', '_TMP')
    #################################################
    print "== TEMP PERMS"
    _, ftmp_wr = temp.mkstemp(dtmp, '~', '.TMP')
    ftmp_wr.write(_TEST_LINE)
    # os.rmdir(dtmp)
    #################################################
    print "== CREATE TEMP FILE"
    ftmp_rd, ftmp_wr = temp.mkstemp(dirtemp, '~', '.TMP')
    with ftmp_rd, ftmp_wr:
        if size < BIG_FILE_SIZE:
            print "== IS NOT BIG FILE"
            fsize = 0
            for chunk in chain(filler, fill_zero()):
                chunk = str(chunk)
                print "== WRITE CHUNK %d bytes" % len(chunk)
                if fsize >= size:
                    break
                elif size - fsize < len(chunk):
                    print "== LAST CHUNK"
                    chunk = chunk[:size-fsize]
                while _tries:
                    print "== REMAIN %d TRIES" % _tries
                    ftmp_wr.pwrite(chunk, ftmp_rd.pos)
                    print 'py: pread', len(chunk), ftmp_rd.pos
                    if ftmp_rd.pread(len(chunk), ftmp_rd.pos) == chunk:
                        print "== GOOD WRITE"
                        _tries = tries
                        ftmp_rd.moveto(ftmp_rd.pos + len(chunk))
                        ftmp_wr.moveto(ftmp_wr.pos + len(chunk))
                        break
                    print "== WRONG WRITE"
                    _tries -= 1
                else:
                    raise fd.IncompleteWrite(fd, )
                fsize += len(chunk)
        else:
            print "== IS BIG FILE"
            tot_hash = fhash()
            fsize = 0
            part_hash = fhash()
            part_start = 0
            part_size = 0
            for chunk in chain(filler, fill_zero()):
                chunk = str(chunk)
                if fsize >= size:
                    break
                elif size - fsize < len(chunk):
                    chunk = chunk[:size-fsize]
                ftmp_wr.write(chunk)
                tot_hash.update(chunk)
                part_hash.update(chunk)
                fsize += len(chunk)
                part_size += len(chunk)
                if part_size >= CTL_SIZE:
                    chk_hash = fhash()
                    for pstart in xrange(part_start, part_start + part_size,
                                         4096):
                        ftmp_rd.pread(4096, pstart)
                    part_start += part_size
                    part_size = 0
                    part_hash = fhash()
        print "=== MOVE TO DESTINATION"
        with fd.File.open(fpath, fd.FO_WRNEW) as fout_wr:
            if os.stat(fpath).st_dev == ftmp_rd.device:
                unistd.rename(temp_path, fpath)
            elif size < BIG_FILE_SIZE:
                with fd.File.open(fpath, fd.FO_READ) as fout_rd:
                    pos = 0
                    chunk = ftmp_rd.pread(4096, pos)
                    while _tries:
                        fout_wr.pwrite(chunk, pos)
                        if chunk == fout_rd.pread(4096, pos):
                            break
                        _tries -= 1
                    else:
                        raise fd.IncompleteWrite(fd, )
                    _tries = tries
            else:
                with fd.File.open(fpath, fd.FO_READ) as fout_rd:
                    part_st = pos = 0
                    part_hs = fhash()
                    chunk = ftmp_rd.pread(4096, 0)
                    while chunk:
                        while _tries:
                            ftmp_wr.pwrite(chunk, pos)
                            part_hs.update(chunk)
                            pos += len(chunk)
                            if pos - part_st >= CTL_SIZE:
                                part_out_hash = fhash()
                                for part_out_start in xrange(part_st,
                                                             pos, 4096):
                                    part_out_hash.update(
                                        out_rd.pread(4096, part_out_start))
                                if part_hs.digest() == part_out_hash.digest():
                                    part_st = pos
                                    part_hs = fhash()
                                    _tries = tries
                                    break
                                else:
                                    pos = part_st
                                    part_hs = fhash()
                                    _tries -= 1
                        else:
                            raise fd.IncompleteWrite(fd, )
                        chunk = ftmp_rd.pread(4096, pos)
