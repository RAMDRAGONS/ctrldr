"""
Candidate names for FLIRT modules that sigmake kept without a name.

Such a module stands for several library functions with identical bytes, and
IDA names its matches unknown_libname. The signature builder writes their
pattern lines (FLAIR .pat format) to ctr_*.candidates; this matches a
function against them the way FLIRT does and returns the names it could be.

A tab after a pattern line lists the library versions holding it. The same
format in ctr_*.versions covers every function whose code changed between
versions, which tells what version a program links.
"""

from collections import defaultdict
from dataclasses import dataclass, field

LEAD = 32


def crc16(data):
    """The CRC FLAIR stores in patterns: CRC-16/X.25, byte-swapped."""
    crc = 0xFFFF
    for b in data:
        for _ in range(8):
            if (crc ^ b) & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
            b >>= 1
    crc = ~crc & 0xFFFF
    return ((crc << 8) & 0xFF00) | (crc >> 8)


def _parse_bytes(hexstr):
    """Pattern hex with '..' wildcards, as a list of int or None."""
    return [None if hexstr[i] == "." else int(hexstr[i:i + 2], 16)
            for i in range(0, len(hexstr), 2)]


def _fits(pattern, data, start=0):
    if start + len(pattern) > len(data):
        return False
    return all(p is None or p == data[start + i] for i, p in enumerate(pattern))


@dataclass
class Module:
    lead: list
    crc_len: int
    crc: int
    length: int
    names: list
    refs: list = field(default_factory=list)   # (offset, name)
    tail: list = field(default_factory=list)
    versions: frozenset = frozenset()

    def matches(self, data):
        """data holds at least the bytes of the function from its start."""
        if len(data) < self.length:
            return False
        if not _fits(self.lead[:self.length], data):
            return False
        return not self.crc_len or crc16(data[LEAD:LEAD + self.crc_len]) == self.crc

    def tail_fits(self, data):
        return _fits(self.tail, data, LEAD + self.crc_len)


def parse_line(line):
    line, _, versions = line.partition("\t")
    tokens = line.split(" ")
    if len(tokens) < 5:
        return None
    try:
        crc_len, crc, length = int(tokens[1], 16), int(tokens[2], 16), int(tokens[3], 16)
    except ValueError:
        return None
    mod = Module(_parse_bytes(tokens[0]), crc_len, crc, length, [],
                 versions=frozenset(v for v in versions.split("|") if v))
    i = 4
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith((":", "^")) and i + 1 < len(tokens):
            name = tokens[i + 1].partition(":")[0]
            off = int(tok[1:5], 16)
            if tok[0] == "^":
                mod.refs.append((off, name))
            # Thumb entry points carry the Thumb bit in their offset.
            elif off in (0, 1) and not tok.endswith("@"):
                mod.names.append(name)
            i += 2
        else:
            mod.tail = _parse_bytes(tok)
            i += 1
    return mod if mod.names else None


def read_modules(path):
    with open(path, encoding="latin-1") as f:
        for line in f:
            line = line.rstrip("\n")
            if line and line != "---":
                mod = parse_line(line)
                if mod is not None:
                    yield mod


class Candidates:
    """Pattern lines from one or more .candidates files, indexed by lead word."""

    def __init__(self, paths):
        self.by_head = defaultdict(list)
        self.wild = []
        self.count = 0
        for path in paths:
            for mod in read_modules(path):
                self.count += 1
                head = mod.lead[:4]
                if None in head:
                    self.wild.append(mod)
                else:
                    self.by_head[bytes(head)].append(mod)

    def __len__(self):
        return self.count

    @property
    def max_length(self):
        mods = self.wild + [m for v in self.by_head.values() for m in v]
        return max((m.length for m in mods), default=0)

    def match(self, data):
        """Modules matching the function whose bytes start data."""
        mods = self.by_head.get(bytes(data[:4]), []) + self.wild
        found = [m for m in mods if m.matches(data)]
        # FLIRT consults tail bytes only to choose between modules, so a
        # match may disagree with all of them.
        return [m for m in found if m.tail_fits(data)] or found


class VersionIndex:
    """
    The version-specific patterns of .versions files, by function name, for
    working out which library versions a program was linked with.
    """

    def __init__(self, paths):
        self.by_name = defaultdict(list)
        for path in paths:
            for mod in read_modules(path):
                if mod.versions:
                    for name in mod.names:
                        self.by_name[name].append(mod)

    @property
    def max_length(self):
        return max((m.length for mods in self.by_name.values() for m in mods), default=0)

    def linked(self, functions, tolerance=0.9):
        """
        The versions a program most likely links: those whose code fits
        nearly as many of its named, version-specific functions as the best
        one. functions yields (name, bytes from its start).
        """
        scores = defaultdict(int)
        for name, data in functions:
            fits = set()
            for m in self.by_name.get(name, ()):
                if m.matches(data):
                    fits |= m.versions
            for v in fits:
                scores[v] += 1
        if not scores:
            return set()
        best = max(scores.values())
        return {v for v, n in scores.items() if n >= best * tolerance}
