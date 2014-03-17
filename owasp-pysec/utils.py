import os
from itertools import izip_longest, islice
import operator
import heapq


def absjoinpath(*parts):
    return os.path.abspath(os.path.join(*parts))


def path_split(path):
    parts = []
    pre, post = os.path.split(os.path.normpath(str(path)))
    if not pre:
        return [post]
    while post:
        parts.append(post)
        pre, post = os.path.split(os.path.normpath(str(pre)))
    if pre:
        parts.append(pre)
    return reversed(parts)


def is_subpath(path1, path2):
    """Returns:
        0   if path2 is not in directory path1
        1   if path2 is equal to path1
        2   if path2 is in directory path1
    """
    for p1, p2 in izip_longest(path_split(str(path1)),
                               path_split(str(path2)), fillvalue=None):
        if p1 is None and p2 is None:
            return 1
        elif p1 is None:
            return 2
        elif p2 is None:
            return 0
        if p1 != p2:
            return 0
    return 1


def subtract_path(prefix, path):
    pre = []
    post = []
    zl = izip_longest(path_split(str(prefix)), path_split(str(path)), fillvalue=None)
    for p1, p2 in zl:
        if p1 is None and p2 is None:
            break
        elif p1 == p2:
            pre.append(p1)
        else:
            post.append(p2)
            break
    for _, p2 in zl:
        post.append(p2)
    return os.path.join(*pre), os.path.join(*post)



def xrange(start, stop, step=1):
    n = int(start)
    stop = int(stop)
    step = int(step)
    if step < 0:
        start, stop = stop, start
        bcmp = operator.gt
    elif step > 0:
        bcmp = operator.lt
    else:
        raise StopIteration
    while bcmp(n, stop):
        yield n
        n += step


def top_n(values, n=10):
    values = iter(values)
    top = [val for val in islice(values, n)]
    if len(top) < n:
        return top
    heapq.heapify(top)
    for val in values:
        heapq.heappushpop(top, val)
    return top
