""""""
import os

MIN_INODES = 64
MIN_FDS = 64


def ino_check(dev, min_ino=MIN_INODES):
    return os.statvfs(dev).f_ffree >= int(min_ino)


def size_check(size):
    return size <= resource.getrlimit(resource.RLIMIT_FSIZE)[0]


def space_check(dev, size):
    stdev = os.statvfs(dev)
    return size < stdev.f_bfree * stdev.f_bsize
