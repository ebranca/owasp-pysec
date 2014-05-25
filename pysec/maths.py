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
"""Various math utilities"""
import stats


def distance(p1, p2):
    """Return the distance between two points.
    The point is a tuple: (x, y).
    """
    x1, y1 = p1
    x2, y2 = p2
    return ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5


def centroid(*points):
    """Calculate the centroid point of a points set in a 2-dimensional space"""
    cx = stats.avg()
    cy = stats.avg()
    cx.next()
    cy.next()
    for x, y in points:
        x = float(x)
        y = float(y)
        cx.send(x)
        cy.send(y)
    return cx.next(), cy.next()


def div_ceil(n, m):
    """Return the smallest integer x such that x * m >= n."""
    q, r = divmod(n, m)
    return q + int(r != 0)


def next_multiple(n, m):
    """Return the smallest multiple of m greater than n"""
    return div_ceil(n, m) * m

