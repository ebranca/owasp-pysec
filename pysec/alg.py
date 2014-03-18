from itertools import islice

def knp(source, pattern, start, stop):
    """Yields all oocurrencies of pattern in source[start:stop]"""
    shifts = [1] * (len(pattern) + 1)
    shift = 1
    for pos in range(len(pattern)):
        while pattern[pos] != pattern[pos - shift] and shift <= pos:
            shift += shifts[pos - shift]
        shifts[pos + 1] = shift
    # search pattern
    mlen = 0
    plen = len(pattern)
    for sub in islice(source, start, stop):
        while mlen == plen or mlen >= 0 and pattern[mlen] != sub:
            sl = shifts[mlen]
            start += sl
            mlen -= sl
        mlen += 1
        if mlen == plen:
            yield start


def knp_find(source, pattern, start, stop):
    for index in knp(source, pattern, start, stop):
        return index
    return -1
