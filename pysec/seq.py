"""Various utilities fot sequences manipulation"""
from pysec.utils import xrange


def ioc(seq, shift=1):
    """Return the index of coincidence"""
    match = 0
    seq_len = len(seq)
    for i in xrange(0, seq_len):
        j = (i + shift) % seq_len
        if seq[i] == seq[j]:
            match += 1
    return float(match) / float(seq_len)


def contains_only(seq, *values):
    return all(el in values for el in seq)

