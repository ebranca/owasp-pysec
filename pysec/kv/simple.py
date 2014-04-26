import struct
from pysec.core import Error
from pysec.io import fd
from pysec.kv import HardKV


SIZE_LEN = 8
SIZE_FMT = '>Q'
DATA_FMT = '>%ds'
ITEM_FMT = '>Q%ds'
MAX_DATA_SIZE = 2 ** 8 - 1


class InvalidFormat(Error):
    pass


class UnexpectedEOF(InvalidFormat):
    pass


class SimpleKV(HardKV):

    def __init__(self, path):
        path = str(path)
        self.frd = fd.File.open(path, fd.FO_READ)
        self.fwr = fd.File.open(path, fd.FO_WRITE)
        if self.frd.inode != self.fwr.inode:
            raise Exception('file %r changed' % path)
        if len(self.frd):
            self._read()

    def _read(self):
        frd = self.frd
        frd.moveto(0)
        items = []
        while 1:
            # read size
            size = frd.read(SIZE_LEN)
            if not size:
                break
            size = struct.unpack(SIZE_FMT, size)[0]
            # read data
            data = frd.read(size)
            if len(data) != size:
                raise UnexpectedEOF
            data = struct.unpack(DATA_FMT % size, data)[0]
            items.append(data)
        if len(items) % 2 != 0:
            raise InvalidFormat
        while items:
            key = items.pop(0)
            value = items.pop(0)
            self[key] = value

    def _write(self):
        fwr = self.fwr
        fwr.truncate(0)
        fwr.moveto(0)
        for key, value in self.iteritems():
            key = str(key)
            value = str(value)
            key = struct.pack(ITEM_FMT % len(key), len(key), key)
            value = struct.pack(ITEM_FMT % len(value), len(value), value)
            item = '%s%s' % (key, value)
            fwr.write(item)

    def close(self):
        self._write()
        fd = getattr(self, 'frd')
        if fd:
            fd.close()
        fd = getattr(self, 'fwr')
        if fd:
            fd.close()


