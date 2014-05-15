from . import en_US, it_IT

__all__ = 'set_lang',

_default = 'en_US'

WRONG_OPEN_MODE = "unknown open mode %r"

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
        print name
        if not name.isupper() or name.startswith('_'):
            continue
        msg = globals().get(name, None)
        print repr(msg)
        print
        if not isinstance(msg, str):
            continue
        msg = getattr(loc, name, None)
        if isinstance(msg, str):
            globals()[name] = msg
    _default = locale

