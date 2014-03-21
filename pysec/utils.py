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
#
# -*- coding: ascii -*-
"""A lot of utilies for:
    - Operations on paths
    - Counting
"""
import os
from itertools import izip_longest, islice
import operator
import heapq


def absjoinpath(*parts):
    """Joins all path's parts and returns the absolute path"""
    return os.path.abspath(os.path.join(*parts))


def path_split(path):
    """Returns all the directories that constitute the full path""" 
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
    for part1, part2 in izip_longest(path_split(str(path1)),
                               path_split(str(path2)), fillvalue=None):
        if part1 is None and part2 is None:
            return 1
        elif part1 is None:
            return 2
        elif part2 is None:
            return 0
        if part1 != part2:
            return 0
    return 1


def subtract_path(prefix, path):
    """Remove prefix path from path"""
    pre = []
    post = []
    couples = izip_longest(path_split(str(prefix)), path_split(str(path)),
                      fillvalue=None)
    for part1, part2 in couples:
        if part1 is None and part2 is None:
            break
        elif part1 == part2:
            pre.append(part1)
        else:
            post.append(part2)
            break
    for _, part2 in couples:
        post.append(part2)
    return os.path.join(*pre), os.path.join(*post)


def xrange(start, stop, step=1):
    """This xrange use python's integers and have not limits of
    machine integers."""
    act = int(start)
    stop = int(stop)
    step = int(step)
    if step < 0:
        start, stop = stop, start
        bcmp = operator.gt
    elif step > 0:
        bcmp = operator.lt
    else:
        raise StopIteration
    while bcmp(act, stop):
        yield act
        act += step


def top_n(values, first_n=10):
    """Returns the *n* greatest objects in values"""
    values = iter(values)
    top = [val for val in islice(values, first_n)]
    if len(top) < first_n:
        return top
    heapq.heapify(top)
    for val in values:
        heapq.heappushpop(top, val)
    return top
