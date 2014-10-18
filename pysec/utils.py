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
from itertools import islice
import operator
import heapq
import datetime
import calendar
import re

from pysec import lang


def xrange(*args):
    """xrange([start,] stop[, step]) -> xrange object

    This xrange use python's integers and has not limits of
    machine integers."""
    len_args = len(args)
    if len_args == 1:
        stop = int(args[0])
        start = 0
        step = 1
    elif len_args == 2:
        start = int(args[0])
        stop = int(args[1])
        step = 1
    elif len_args == 3:
        start = int(args[0])
        stop = int(args[1])
        step = int(args[2])
    else:
        raise TypeError("xrange() requires 1-3 int arguments")
    if step < 0:
        bcmp = operator.gt
    elif step > 0:
        bcmp = operator.lt
    else:
        raise StopIteration
    act = int(start)
    while bcmp(act, stop):
        yield act
        act += step


def range(*args):
    return list(xrange(*args))


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


def clamp(val, min_val, max_val):
    return min_val if val < min_val else (max_val if val > max_val else val)


def eq(*values):
    if not values:
        return 1
    cval = values[0]
    return all(cval == val for val in values[1:])


def secs_to_iso_utc(timestamp, suffix=1):
    return datetime.datetime.utcfromtimestamp(int(timestamp)).isoformat(' ') + suffix


ISO_UTC_FORMAT = re.compile(r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})[T_ ](?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?P<msecond>\.\d+)?Z?")

def iso_utc_to_secs(time):
    m = ISO_UTC_FORMAT.match(time)
    if not m:
        raise ValueError(lang.TIME_INVALID_TIME_FORMAT % time)
    year = int(m.group('year'))
    month = int(m.group('month'))
    day = int(m.group('day'))
    hour = int(m.group('hour'))
    minute = int(m.group('minute'))
    second = int(m.group('second'))
    msec = m.group('msecond')
    if msec:
        msec = float(msec)
    else:
        msec = 0.
    return float(calendar.timegm((year, month, day, hour, minute, second, 0, 1, 0))) + msec


DAY = 24 * 60 * 60
MONTH = 31 * DAY
YEAR = 365 * DAY


def parse_duration(duration):
    secs = 0
    for field in duration.split():
        field = field.strip()
        if field.endswith('sec'):
            field = field[:-3]
            unit = 1
        elif field.endswith('day'):
            unit = DAY
            field = field[:-3]
        elif field.endswith('month'):
            unit = MONTH
            field = field[:-5]
        elif field.endswith('year'):
            unit = YEAR
            field = field[:-4]
        else:
            raise ValueError(lang.TIME_UNKNOWN_TIME_UNIT % field)
        field = field.strip()
        if not field.isdigit():
            raise ValueError(lang.TIME_NOT_NUMERIC_VALUE % field)
        secs += int(field) * unit
    return secs


def ilen(gen, max=None):
    """Iterate a generator and return the number of iterations.
    If max is not None, the iteration terminate at *max* iteration."""
    l = 0
    if max is None:
        for _ in gen:
            l += 1
        return l
    else:
        max = int(max)
        if max < 0:
            raise ValueError("invalid negative max: %d" % max)
        for i in xrange(0, max):
            try:
                gen.next()
            except StopIteration:
                break
        else:
            return max
        return i + 1

