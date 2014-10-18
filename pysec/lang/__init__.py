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
"""Manage the language of human-readable messages in PySec"""
from . import en_US, it_IT

__all__ = 'set_lang',

_default = 'en_US'

WRONG_OPEN_MODE = "unknown open mode %r"
WRONG_ONE_CHAR_STRING = "wrong 1-char string: %r"

LANG_LOCALE_NOT_FOUND = "locale %r not found"

LOG_ALREADY_SET = "Log already set"
LOG_NOT_STARTED = "Log not started"
LOG_NEGATIVE_ACT_CODE = "invalid negative integer as action code: %d"
LOG_CODE_PRESENT = "code already present: %d"
LOG_NAME_PRESENT = "name already present: %r"
LOG_ERR_NOT_FOUND = "error %r not found"

CHECK_WRONG_SUBRULE_TYPE = "wrong subrule's type %r"
CHECK_WRONG_RULE_TYPE = "wrong rule's type %r"

ENT_NEGATIVE_BASE = "negative base: %d"
ENT_NEGATIVE_FREQ = "negative frequency: %d"
ENT_WRONG_BYTE = "wrong byte value: %r"

EXPR_WRONG_VAR_NAME = "wrong variable's name: %r"

LOAD_WRONG_FIELDS = "wrong number of fields at line %d"
LOAD_WRONG_LIB_NAME = "wrong library name at line %d"
LOAD_WRONG_VERSION_FORMAT = "wrong version format at line %d"
LOAD_WRONG_HASH_FORMAT = "wrong hash format at line %d"
LOAD_DUP_LIB = "duplicated library: %r %d.%d.%d"
LOAD_LIB_NOT_FOUND = "library %r not found"
LOAD_LIB_VER_NOT_FOUND = "library %r %r not found"
LOAD_INVALID_HASH = "module %r %r in %r don't match hash %r"

STR_WRONG_BYTE = "wrong byte value: %r"

TIME_INVALID_TIME_FORMAT = "invalid time format: %r"
TIME_UNKNOWN_TIME_UNIT = "unknown time unit: %r"
TIME_NOT_NUMERIC_VALUE = "unknown numeric value: %r"


_LOCALES = {
    'en_US': en_US,
    'it_IT': it_IT
}


def set_lang(locale):
    """Set language for human readable strings"""
    locale = str(locale)
    loc = _LOCALES.get(locale, None)
    if not loc:
        raise ValueError(LANG_LOCALE_NOT_FOUND % locale)
    for name in dir(loc):
        if not name.isupper() or name.startswith('_'):
            continue
        msg = globals().get(name, None)
        if not isinstance(msg, str):
            continue
        msg = getattr(loc, name, None)
        if isinstance(msg, str):
            globals()[name] = msg

