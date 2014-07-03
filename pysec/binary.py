#!/usr/bin/python -OOBRStt
""""""
from pysec.core import is_int, is_str, is_dict


SPECIAL_CHARS = '\\', '*', '?', '!', '[', ']', '{', '}', '-', ',', '#', '@'

ALPHA = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
DIGITS = '0123456789'
LOWER = 'abcdefghijklmnopqrstuvwxyz'
UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
ALPHANUMERIC = DIGITS + ALPHA
HEXDIGITS = '0123456789abcdefABCDEF'
PRINTABLE = tuple(chr(ch) for ch in xrange(0x20, 0x7F))
NOT_PRINTABLE = tuple(chr(ch) for ch in xrange(0x00, 0x20))
VISIBLE = tuple(chr(ch) for ch in xrange(0x21, 0x7F))
NOT_VISIBLE = tuple(chr(ch) for ch in xrange(0x00, 0x21))
ASCII_CHAR = tuple(chr(ch) for ch in xrange(0x00, 0x80))

CTRL_CHAR = ''.join(chr(ch) for ch in xrange(0x00, 0x1F)) + '\x7F'

CTRL2ABBR = {
    '\x00': 'NUL',
    '\x01': 'SOH',
    '\x02': 'STX',
    '\x03': 'ETX',
    '\x04': 'EOT',
    '\x05': 'ENQ',
    '\x06': 'ACK',
    '\x07': 'BEL',
    '\x08': 'BS',
    '\x09': 'HT',
    '\x0A': 'LF',
    '\x0B': 'VT',
    '\x0C': 'FF',
    '\x0D': 'CR',
    '\x0E': 'SO',
    '\x0F': 'SI',
    '\x10': 'DLE',
    '\x11': 'DC1',
    '\x12': 'DC2',
    '\x13': 'DC3',
    '\x14': 'DC4',
    '\x15': 'NAK',
    '\x16': 'SYN',
    '\x17': 'ETB',
    '\x18': 'CAN',
    '\x19': 'EM',
    '\x1A': 'SUB',
    '\x1B': 'ESC',
    '\x1C': 'FS',
    '\x1D': 'GS',
    '\x1E': 'RS',
    '\x1F': 'US',
    '\x7F': 'DEL',
}

CTRL2CARETNOTATION = {
    '\x00': '^@',
    '\x01': '^A',
    '\x02': '^B',
    '\x03': '^C',
    '\x04': '^D',
    '\x05': '^E',
    '\x06': '^F',
    '\x07': '^G',
    '\x08': '^H',
    '\x09': '^I',
    '\x0A': '^J',
    '\x0B': '^K',
    '\x0C': '^L',
    '\x0D': '^M',
    '\x0E': '^N',
    '\x0F': '^O',
    '\x10': '^P',
    '\x11': '^Q',
    '\x12': '^R',
    '\x13': '^S',
    '\x14': '^T',
    '\x15': '^U',
    '\x16': '^V',
    '\x17': '^W',
    '\x18': '^X',
    '\x19': '^Y',
    '\x1A': '^Z',
    '\x1B': '^[',
    '\x1C': '^\\',
    '\x1D': '^]',
    '\x1E': '^^',
    '\x1F': '^_',
    '\x7F': '^?',
}

CTRL2CESCAPE = {
    '\x00': r'\0',
    '\x07': r'\a',
    '\x08': r'\b',
    '\x09': r'\t',
    '\x0A': r'\n',
    '\x0B': r'\v',
    '\x0C': r'\f',
    '\x0D': r'\r',
    '\x1B': r'\e',
}

BACKSLASH_ORD = ord('\\')


MASK_NONE_CHAR = 0
MASK_ALL_CHAR = object()
MASK_PRINT = reduce(lambda a, b: a | b, (1 << ord(ch) for ch in PRINTABLE))
MASK_NOT_PRINT = (2 ** 0x20) - 1
MASK_ALPHNUM = reduce(lambda a, b: a | b, (1 << ord(ch) for ch in ALPHANUMERIC))
MASK_NUM = 1111111111 << 49
MASK_ALPH = reduce(lambda a, b: a | b, (1 << ord(ch) for ch in ALPHA))
MASK_VIS = reduce(lambda a, b: a | b, (1 << ord(ch) for ch in VISIBLE))
MASK_NOT_VIS = reduce(lambda a, b: a | b, (1 << ord(ch) for ch in NOT_VISIBLE))
MASK_ASCII = 2 ** 129 - 1
MASK_EXT = (2 ** 129 - 1) << 128


class WildSyntaxError(ValueError):
    pass


def minimize_pattern(pattern):
    new_pattern = []
    i = 0
    p_len = len(pattern)
    while i < p_len:
        ch = pattern[i]
        if ch == '?':
            new_pattern.append(MASK_ALL_CHAR)
        elif ch == '.':
            new_pattern.append(MASK_NOT_PRINT)
        elif ch == '$':
            new_pattern.append(MASK_ALPHNUM)
        elif ch == '#':
            new_pattern.append(MASK_NUM)
        elif ch == '@':
            new_pattern.append(MASK_ALPH)
        elif ch == '-':
            new_pattern.append(MASK_VIS)
        elif ch == '_':
            new_pattern.append(MASK_NOT_VIS)
        elif ch == '%':
            new_pattern.append(MASK_ASCII)
        elif ch == '+':
            new_pattern.append(MASK_EXT)
        elif ch == '\\':
            i += 1
            if i >= p_len:
                raise WildSyntaxError()
            ch = pattern[i]
            if ch in SPECIAL_CHARS:
                new_pattern.append(ord(ch))
            elif ch == 'x':
                i += 2
                if i >= p_len:
                    raise WildSyntaxError()
                hx = pattern[i-1:i+1]
                if hx[0] in HEXDIGITS and hx[1] in HEXDIGITS:
                    new_pattern.append(chr(int(hx, 16)))
                else:
                    raise WildSyntaxError()
            elif ch == '\\':
                new_pattern.append(BACKSLASH_ORD)
            elif ch == '[':
                raise NotImplementedError
            else:
                raise WildSyntaxError()
        else:
            new_pattern.append(ch)
        i += 1
    return new_pattern


def byte_search(text, pattern, offset=0):
    pattern = minimize_pattern(pattern)
    p = 0
    p_len = len(pattern)
    t = int(offset)
    t_len = len(text)
    while t < t_len and p <= t_len and p < p_len:
        tc = text[t]
        pc = pattern[p]
        if isinstance(pc, str):
            if pc == tc:
                p += 1
            else:
                p = 0
        elif pc is MASK_ALL_CHAR:
            p += 1
        elif isinstance(pc, (int, long)):
            if pc & (1 << (ord(tc) + 1)):
                p += 1
            else:
                p = 0
        else:
            raise Exception("unknown token: %r" % pc)
        t += 1
    return t - p_len if p >= p_len else -1



class SearchTree(object):

    def __init__(self, token=None, eop=None, parent=None, name=None):
        self.parent = parent
        self.token = token
        self.eop = bool(eop)
        self.children = {}
        self.name = name

    def add(self, token, eop=None):
        node = SearchTree(token, eop, self)
        self.children[token] = node
        return node

    def __getitem__(self, token):
        return self.children[token]

    def tokens(self):
        return self.children.keys()

    def items(self):
        return self.children.items()

    def ancestors(self):
        node = self
        while node:
            yield node
            node = node.parent


def byte_msearch(text, patterns, offset=0):
    if is_dict(patterns):
        patterns = patterns.iteritems()
    else:
        patterns = ((p, None) for p in patterns)
    root = SearchTree()
    for pattern, name in patterns:
        tree = root
        for tk in minimize_pattern(pattern):
            if tk in tree.children:
                tree = tree.children[tk]
            else:
                tree = tree.add(tk)
        tree.eop = 1
        tree.name = name
    t = int(offset)
    if t < 0:
        raise ValueError("negative offset: %d" % t)
    t_len = len(text)
    root.eop = 0
    actual_trees = set([root])
    while t < t_len and actual_trees:
        tc = text[t]
        next_trees = set()
        while actual_trees:
            tree = actual_trees.pop()
            if tree.eop:
                yield t, [node.token for node in reversed(tuple(tree.ancestors())[:-1])], tree.name
                tree.eop = 0
            for pc, node in tree.items():
                if is_str(pc):
                    pc = str(pc)
                    if pc == tc:
                        next_trees.add(node)
                    else:
                        next_trees.add(root)
                elif pc is MASK_ALL_CHAR:
                    next_trees.add(node)
                elif is_int(pc):
                    pc = int(pc)
                    if pc & (1 << (ord(tc) + 1)):
                        next_trees.add(node)
                    else:
                        next_trees.add(root)
                else:
                    raise Exception("unknown token: %r" % pc)
        actual_trees = next_trees
        t += 1

