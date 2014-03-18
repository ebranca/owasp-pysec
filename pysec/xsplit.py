"""Splitters for sequence-like objects to improve memory usage and speed"""


def xsplit(val, sep, keep_sep=0, start=0, stop=None, find=None):
    """Make an iterator that returns subsequences of the val (sequence-like
    object), breaking at sep and using find function, to search sep, from start
    to stop indices of val.

    If find is None, it use val.find function to search sep."""
    return (val[a:b] for a, b
            in xbounds(val, sep, keep_sep, start, stop, find))


def xbounds(val, sep, keep_sep=0, start=0, stop=None, find=None):
    """Make an iterator that returns bounds of the val (sequence-like object),
    breaking at sep and using find function, to search sep, from start to stop
    indices of val.

    If find is None, it use val.find function to search sep."""
    if stop is None:
        stop = len(val)
    if find is None:
        find = val.find
    else:
        _find = find
        find = lambda sep, start, stop: _find(val, sep, start, stop)
    start, stop, _ = slice(start, stop).indices(len(val))
    lsep = len(sep)
    while start < stop:
        chunk_end = find(sep, start, stop)
        if chunk_end < 0 or chunk_end is None:
            chunk_end = stop
            yield start, chunk_end
        else:
            yield start, chunk_end + lsep if keep_sep else chunk_end
        start = chunk_end + lsep


def xlines(text, eol='\n', keep_eol=0, start=0, stop=None, find=None):
    """Specialized xsplit generator for string splitting"""
    return xsplit(text, eol, keep_eol, start, stop, find)
