"""
CRO modules and the CRS static module of nn::ro, the 3DS dynamic linker.

A .cro is a relocatable module: the file starts with 0x80 bytes of SHA-256
hashes, then the "CRO0" header, then the segments (.text, .rodata, .data;
.bss has no file bytes) and the tables nn::ro works from. Everything in the
tables addresses code and data as a segment offset: (offset << 4) | segment
index. static.crs describes the program's own code.bin in the same format,
with its segment table holding the real load addresses, so modules can
import from it.

A module is mapped here at a chosen base with its file laid out unchanged,
so an address minus the base is an offset in the .cro file. Internal
relocations are applied; imports are pointed at slots of an extern segment
that carry the imported symbol's name.
"""

import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

from .util import PAGE, LoaderError, align_up, cstr, u32

CRO_MAGIC = b"CRO0"
STATIC_NAME = "|static|"
NONE = 0xFFFFFFFF

HEADER_FIELDS = (
    "name_offset", "next", "previous", "file_size", "bss_size", "fixed_size", "unk9c",
    "control_object", "on_load", "on_exit", "on_unresolved",
    "code_offset", "code_size", "data_offset", "data_size",
    "module_name_offset", "module_name_size",
    "segment_table_offset", "segment_count",
    "named_export_offset", "named_export_count",
    "indexed_export_offset", "indexed_export_count",
    "export_strings_offset", "export_strings_size",
    "export_tree_offset", "export_tree_count",
    "import_module_offset", "import_module_count",
    "import_patch_offset", "import_patch_count",
    "named_import_offset", "named_import_count",
    "indexed_import_offset", "indexed_import_count",
    "anonymous_import_offset", "anonymous_import_count",
    "import_strings_offset", "import_strings_size",
    "unk8_offset", "unk8_count",
    "relocation_offset", "relocation_count",
    "unk_relocation_offset", "unk_relocation_count",
)
HEADER_END = 0x138

# Segment table ids
SEG_TEXT, SEG_RODATA, SEG_DATA, SEG_BSS = 0, 1, 2, 3

# Patch types nn::ro applies (ELF relocation numbers)
R_ARM_ABS32 = 2
R_ARM_REL32 = 3
R_ARM_THM_CALL = 10
R_ARM_CALL = 28
R_ARM_JUMP24 = 29
R_ARM_TARGET1 = 38
R_ARM_PREL31 = 42

# Header entry points and the names nn::ro exports them under
ENTRY_NAMES = (("on_load", "nnroProlog"), ("on_exit", "nnroEpilog"),
               ("on_unresolved", "nnroUnresolved"))


def split_segment_offset(v):
    return v & 0xF, v >> 4


@dataclass
class Patch:
    target: int         # segment offset of the word to patch
    kind: int           # R_ARM_*
    segment: int        # relocations: segment the value is relative to
    last: bool          # import patch lists: last entry of the list
    addend: int


@dataclass
class ImportModule:
    name: str
    indexed: list = field(default_factory=list)     # (export index, patch list offset)
    anonymous: list = field(default_factory=list)   # (segment offset in that module, patch list offset)


class Cro:
    """Read-only view of a .cro or .crs file."""

    def __init__(self, data, origin=None):
        if len(data) < HEADER_END or data[0x80:0x84] != CRO_MAGIC:
            raise LoaderError("not a CRO/CRS (no CRO0 magic at 0x80)")
        self.data = data
        self.origin = origin
        self.h = dict(zip(HEADER_FIELDS, struct.unpack_from(f"<{len(HEADER_FIELDS)}I", data, 0x84)))
        self.name = cstr(data[self.h["module_name_offset"]:
                              self.h["module_name_offset"] + self.h["module_name_size"]])
        off = self.h["segment_table_offset"]
        self.segments = [struct.unpack_from("<III", data, off + 12 * i)
                         for i in range(self.h["segment_count"])]

    @property
    def is_static(self):
        return self.name == STATIC_NAME

    def string(self, off):
        end = self.data.index(b"\0", off)
        return self.data[off:end].decode("ascii", "replace")

    def _table(self, key, fmt):
        off, count = self.h[f"{key}_offset"], self.h[f"{key}_count"]
        size = struct.calcsize(fmt)
        return [struct.unpack_from(fmt, self.data, off + size * i) for i in range(count)]

    def named_exports(self):
        return [(self.string(n), so) for n, so in self._table("named_export", "<II")]

    def indexed_exports(self):
        return [so for (so,) in self._table("indexed_export", "<I")]

    def named_imports(self):
        return [(self.string(n), p) for n, p in self._table("named_import", "<II")]

    def import_modules(self):
        mods = []
        for name, idx_off, idx_n, anon_off, anon_n in self._table("import_module", "<5I"):
            m = ImportModule(self.string(name))
            m.indexed = [struct.unpack_from("<II", self.data, idx_off + 8 * i) for i in range(idx_n)]
            m.anonymous = [struct.unpack_from("<II", self.data, anon_off + 8 * i) for i in range(anon_n)]
            mods.append(m)
        return mods

    @staticmethod
    def _patch(raw):
        target, kind, seg, _flag, _unk, addend = raw
        return Patch(target, kind, seg, seg != 0, addend)

    def import_patches(self, off):
        """The patch list of one import, starting at a file offset."""
        out = []
        end = self.h["import_patch_offset"] + 12 * self.h["import_patch_count"]
        while off + 12 <= end:
            p = self._patch(struct.unpack_from("<IBBBBI", self.data, off))
            out.append(p)
            off += 12
            if p.last:
                break
        return out

    def relocations(self):
        return [self._patch(r) for r in self._table("relocation", "<IBBBBI")]

    def file_offset(self, segment_offset):
        """File offset of a segment offset in a module's own file, or None (bss, out of range)."""
        idx, off = split_segment_offset(segment_offset)
        if idx >= len(self.segments):
            return None
        start, size, _ = self.segments[idx]
        if off > size or (start == 0 and size):
            return None
        return start + off

    def static_address(self, segment_offset):
        """For a CRS: the code.bin address of a segment offset."""
        idx, off = split_segment_offset(segment_offset)
        if idx >= len(self.segments):
            return None
        start, size, _ = self.segments[idx]
        return start + off if off <= size else None

    def export_name_at(self, segment_offset):
        for name, so in self.named_exports():
            if so == segment_offset:
                return name
        return None


def read_cro(path):
    try:
        return Cro(Path(path).read_bytes(), str(path))
    except (OSError, LoaderError):
        return None


def find_static_crs(path):
    """static.crs next to a module or code.bin, or in a romfs directory near it."""
    if not path:
        return None
    p = Path(path).resolve().parent
    for d in (p, p / "romfs", p.parent / "romfs", p.parent.parent / "romfs"):
        f = d / "static.crs"
        if f.is_file():
            crs = read_cro(f)
            if crs is not None and crs.is_static:
                return crs
    return None


def find_module(directory, name):
    f = Path(directory) / f"{name}.cro"
    return read_cro(f) if f.is_file() else None


_SYM_LINE = re.compile(r"^(?P<name>.+?)\s*=\s*(?P<addr>0x[0-9A-Fa-f]+)t?\s*(?:#.*)?$")
_GHIDRA_LINE = re.compile(r"^(?P<name>\S+)\s+(?P<addr>0x[0-9A-Fa-f]+)(?:\s+[fl])?$")
SYMBOL_FILE_NAMES = ("static.sym", "code.sym", "static_symbols.txt")


def load_symbol_map(path):
    """
    Address -> name from a symbol list: "name = 0xADDR" lines (with an
    optional t suffix, @ section lines and # comments ignored) or Ghidra
    import lists ("name 0xADDR f").
    """
    out = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line[0] in "#@":
                continue
            m = _SYM_LINE.match(line) or _GHIDRA_LINE.match(line)
            if m:
                out.setdefault(int(m["addr"], 16) & ~1, m["name"])
    return out


def find_symbol_map(path):
    """CTRLDR_STATIC_SYMBOLS, or a symbol list beside the input. Returns (map, path) or None."""
    candidates = []
    env = os.environ.get("CTRLDR_STATIC_SYMBOLS")
    if env:
        candidates.append(Path(env))
    if path:
        d = Path(path).resolve().parent
        candidates += [d / n for n in SYMBOL_FILE_NAMES]
    for c in candidates:
        if c.is_file():
            try:
                return load_symbol_map(c), str(c)
            except OSError:
                continue
    return None


def _encode_arm_branch(insn, value):
    return (insn & 0xFF000000) | (((value >> 2) & 0xFFFFFF))


def _encode_thumb_bl(pair, value):
    hi, lo = pair & 0xFFFF, pair >> 16
    off = value >> 1
    hi = (hi & 0xF800) | ((off >> 11) & 0x7FF)
    lo = (lo & 0xF800) | (off & 0x7FF)
    return hi | (lo << 16)


def apply_patch(image, base, loc, kind, value_target):
    """
    Write one patch into image (bytes mapped at base). value_target is the
    patched symbol's address plus the addend. Returns False for a patch
    type this does not implement.
    """
    off = loc - base
    if off < 0 or off + 4 > len(image):
        return False
    orig = u32(image, off)
    if kind in (R_ARM_ABS32, R_ARM_TARGET1):
        v = value_target
    elif kind == R_ARM_REL32:
        v = value_target - loc
    elif kind == R_ARM_PREL31:
        v = (orig & 0x80000000) | ((value_target - loc) & 0x7FFFFFFF)
    elif kind in (R_ARM_CALL, R_ARM_JUMP24):
        v = _encode_arm_branch(orig, value_target - (loc + 8))
    elif kind == R_ARM_THM_CALL:
        v = _encode_thumb_bl(orig, value_target - (loc + 4))
    else:
        return False
    struct.pack_into("<I", image, off, v & 0xFFFFFFFF)
    return True


@dataclass
class Extern:
    name: str
    comment: str


class CroLayout:
    """Addresses of a module's parts once mapped at base."""

    def __init__(self, cro, base):
        self.cro = cro
        self.base = base
        self.file_end = align_up(max(cro.h["file_size"], len(cro.data)), PAGE)
        self.bss = base + self.file_end
        self.seg_base = []
        for start, size, sid in cro.segments:
            if sid == SEG_BSS and start == 0:
                self.seg_base.append(self.bss)
            else:
                self.seg_base.append(base + start)
        bss_size = max((s for _, s, i in cro.segments if i == SEG_BSS), default=0)
        self.bss_size = max(bss_size, cro.h["bss_size"])
        self.end = self.bss + align_up(self.bss_size, 4)

    def address(self, segment_offset):
        idx, off = split_segment_offset(segment_offset)
        if idx >= len(self.seg_base):
            return None
        return self.seg_base[idx] + off

    def in_text(self, ea):
        for (start, size, sid), b in zip(self.cro.segments, self.seg_base):
            if sid == SEG_TEXT and size and b <= (ea & ~1) < b + size:
                return True
        return False


def describe_module(cro):
    lines = [f"CRO module {cro.name}: file 0x{cro.h['file_size']:X}, bss 0x{cro.h['bss_size']:X}"]
    for name, so in cro.named_exports():
        lines.append(f"  export {name} @ seg{so & 0xF}+0x{so >> 4:X}")
    mods = cro.import_modules()
    if mods:
        lines.append("Imports from: " + ", ".join(
            f"{m.name} ({len(m.indexed) + len(m.anonymous)})" for m in mods))
    return lines
