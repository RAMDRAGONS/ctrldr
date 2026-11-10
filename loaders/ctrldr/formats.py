"""Input formats: loose .code / code.bin, ExeFS images, 3DSX and 3GX."""

import struct
from dataclasses import dataclass, field
from pathlib import Path

from . import blz
from .consts import DEFAULT_APP_MAPPINGS
from .exheader import ExHeader, find_beside
from .layout import LayoutInference, Section, compare_layouts, layout_from_exheader
from .util import CODE_BASE, MEDIA_UNIT, PAGE, LoaderError, align_up, cstr, u16, u32

FORMATS = ("code", "ExeFS", "3DSX", "3GX")


@dataclass
class Image:
    """Everything the IDA side needs, independent of the container format."""
    kind: str
    data: bytes
    sections: list
    entry: int = CODE_BASE
    exheader: ExHeader = None
    layout_source: str = ""
    notes: list = field(default_factory=list)
    symbols: dict = field(default_factory=dict)       # ea -> name
    thumb: set = field(default_factory=set)           # Thumb entry points
    functions: set = field(default_factory=set)       # known function starts
    call_targets: set = field(default_factory=set)    # BL/BLX targets to seed
    fixups: list = field(default_factory=list)        # (ea, target) 32-bit pointers
    mappings: list = field(default_factory=list)      # (start, end, read_only)
    compressed: bool = False
    sdk_app: bool = False


def looks_like_exefs(src):
    hdr = src.try_read(0, 0x200)
    if hdr is None:
        return False
    end = 0
    seen_code = False
    for i in range(10):
        raw = hdr[i * 16:i * 16 + 8]
        if raw == b"\0" * 8:
            continue
        name = cstr(raw)
        if not name or not all(0x20 < ord(c) < 0x7F for c in name):
            return False
        off, size = u32(hdr, i * 16 + 8), u32(hdr, i * 16 + 12)
        if off % MEDIA_UNIT:
            return False
        end = max(end, 0x200 + off + size)
        seen_code |= name == ".code"
    return seen_code and end <= src.length


def exefs_code(src):
    hdr = src.read(0, 0x200)
    for i in range(10):
        if cstr(hdr[i * 16:i * 16 + 8]) == ".code":
            return src.read(0x200 + u32(hdr, i * 16 + 8), u32(hdr, i * 16 + 12))
    raise LoaderError("ExeFS has no .code")


def looks_like_code(src, name):
    if src.length < PAGE or src.length % 4:
        return False
    footer = blz.footer(src.read(src.length - 0x10, 0x10), src.length)
    if footer and (src.length + footer[2]) % PAGE == 0:
        return True
    w = u32(src.read(0, 4), 0)
    is_branch = (w >> 24) in (0xEA, 0xEB) or w >> 25 == 0x7D
    named = name in ("code.bin", ".code") or name.endswith(".code") or \
        ("code" in name and name.endswith(".bin"))
    return is_branch and (named or src.length % PAGE == 0)


def detect_format(src, path):
    """Returns one of FORMATS, or None."""
    head = src.try_read(0, 8) or b""
    if head[:4] == b"3DSX":
        return "3DSX"
    if head[:8] == b"3GX$0002":
        return "3GX"
    if looks_like_exefs(src):
        return "ExeFS"
    name = Path(path).name.lower() if path else ""
    if looks_like_code(src, name):
        return "code"
    return None


def exheader_matches(exh, code):
    if exh.compressed:
        ft = blz.footer(code[-0x10:], len(code))
        return ft is not None and len(code) + ft[2] == exh.code_length()
    need = exh.code_length()
    return need <= len(code) < need + PAGE


def decompress_if_needed(code, exh=None):
    if exh is not None:
        return (blz.decompress(code), True) if exh.compressed else (code, False)
    ft = blz.footer(code)
    if ft and (len(code) + ft[2]) % PAGE == 0:
        return blz.decompress(code), True
    return code, False


def build_code_image(code, exh, exh_origin, kind):
    notes = []
    if exh is not None and not exheader_matches(exh, code):
        notes.append(f"ignored ExHeader {exh_origin}: its code set does not match this .code")
        exh = None
    raw_len = len(code)
    code, compressed = decompress_if_needed(code, exh)
    img = Image(kind=kind, data=code, sections=[], exheader=exh, compressed=compressed,
                notes=notes)
    if compressed:
        img.notes.append(f"BLZ-decompressed .code 0x{raw_len:x} -> 0x{len(code):x}")

    inference = None
    if exh is not None:
        img.sections = layout_from_exheader(exh, code)
        img.layout_source = f"ExHeader {exh_origin}"
        img.mappings = list(exh.mappings)
        if not exh.is_firm_module:
            try:
                inference = LayoutInference(code)
                diff = compare_layouts(img.sections, inference.run())
                if diff:
                    img.notes.append("layout inference disagrees with the ExHeader: " + diff)
            except LoaderError as e:
                img.notes.append(f"layout inference skipped: {e}")
                inference = None
    else:
        inference = LayoutInference(code)
        img.sections = inference.run()
        img.layout_source = "inferred from the image (no ExHeader)"
        img.mappings = list(DEFAULT_APP_MAPPINGS)

    if inference is not None:
        img.notes.extend(inference.notes)
        img.symbols.update(inference.symbols)
        img.thumb |= inference.thumb
        img.functions |= inference.functions
        img.sdk_app = inference.sdk_app
        text = img.sections[0]
        arm, thumb = inference.call_targets(text.start + text.size)
        img.call_targets = arm | thumb
        img.thumb |= thumb
    return img


def load_3dsx(src):
    """
    3DSX segments are linked as if laid out back to back from address 0,
    each rounded up to a page; relocations add the load base. The image is
    placed at CODE_BASE like the homebrew loader does.
    """
    h = src.read(0, 0x20)
    hdr_size, reloc_hdr_size = u16(h, 4), u16(h, 6)
    code_size, ro_size, data_size, bss_size = struct.unpack_from("<4I", h, 0x10)
    if bss_size > data_size:
        raise LoaderError("3DSX bss larger than its data segment")
    file_sizes = [code_size, ro_size, data_size - bss_size]
    mem_sizes = [align_up(code_size), align_up(ro_size), align_up(data_size)]
    bases = [CODE_BASE, CODE_BASE + mem_sizes[0], CODE_BASE + mem_sizes[0] + mem_sizes[1]]
    limits = [mem_sizes[0], mem_sizes[0] + mem_sizes[1]]

    def translate(v):
        if v < limits[0]:
            return bases[0] + v
        if v < limits[1]:
            return bases[1] + v - limits[0]
        return bases[2] + v - limits[1]

    off = hdr_size
    relocs = []
    for _ in range(3):
        r = src.read(off, reloc_hdr_size)
        relocs.append((u32(r, 0), u32(r, 4)))
        off += reloc_hdr_size
    segs = []
    for size in file_sizes:
        segs.append(bytearray(src.read(off, size)))
        off += size

    fixups = []
    for si, (n_abs, n_rel) in enumerate(relocs):
        seg = segs[si]
        pos = 0
        for relative, count in ((False, n_abs), (True, n_rel)):
            for _ in range(count):
                rec = src.read(off, 4)
                off += 4
                pos += u16(rec, 0) * 4
                for _ in range(u16(rec, 2)):
                    if pos + 4 > len(seg):
                        raise LoaderError(f"3DSX relocation past segment {si}")
                    ea = bases[si] + pos
                    orig = u32(seg, pos)
                    if relative:
                        # Top nibble selects the encoding: 0 = REL32, 1 = PREL31.
                        target = translate(orig & 0x0FFFFFFF)
                        value = (target - ea) & 0xFFFFFFFF
                        if orig >> 28 == 1:
                            value &= 0x7FFFFFFF
                    else:
                        target = value = translate(orig)
                        fixups.append((ea, target))
                    struct.pack_into("<I", seg, pos, value)
                    pos += 4

    flat = bytearray()
    sections = []
    for name, si, perm, sclass in ((".text", 0, 5, "CODE"), (".rodata", 1, 4, "CONST"),
                                   (".data", 2, 6, "DATA")):
        if not file_sizes[si]:
            continue
        sections.append(Section(name, bases[si], file_sizes[si], len(flat), perm, sclass))
        flat += segs[si]
    if bss_size:
        sections.append(Section(".bss", bases[2] + file_sizes[2], bss_size, -1, 6, "BSS"))
    img = Image(kind="3DSX", data=bytes(flat), sections=sections, fixups=fixups,
                layout_source="3DSX header")
    img.symbols[CODE_BASE] = "_start"
    img.functions.add(CODE_BASE)
    return img


def load_3gx(src):
    """Luma3DS game plugin: a flat image loaded at 0x07000000."""
    base = 0x07000000
    exe = src.read(0x8 + 0x4 + 0x4 + 0x48, 0x28)
    text_off, ro_off, data_off, text_size, ro_size, data_size, bss_size, \
        load_fn, save_fn, swap_load_fn = struct.unpack_from("<10I", exe, 0)
    blob = src.read(0, data_off + data_size)
    secs = [Section(".header", base, text_off, 0, 4, "CONST"),
            Section(".text", base + text_off, text_size, text_off, 5, "CODE")]
    if ro_size:
        secs.append(Section(".rodata", base + ro_off, ro_size, ro_off, 4, "CONST"))
    if data_size:
        secs.append(Section(".data", base + data_off, data_size, data_off, 6, "DATA"))
    if bss_size:
        secs.append(Section(".bss", base + data_off + data_size, bss_size, -1, 6, "BSS"))
    img = Image(kind="3GX", data=blob, sections=secs, entry=base + text_off,
                layout_source="3GX header")
    img.symbols[img.entry] = "_start"
    img.functions.add(img.entry)
    for addr, name in ((load_fn, "loadExeFunc"), (save_fn, "swapSaveFunc"),
                       (swap_load_fn, "swapLoadFunc")):
        if addr:
            img.symbols[base + addr] = name
            img.functions.add(base + addr)
    return img


def load_image(src, path, fmt, exheader_path=None, search_exheader=True):
    if fmt == "3DSX":
        return load_3dsx(src)
    if fmt == "3GX":
        return load_3gx(src)
    if fmt == "ExeFS":
        code = exefs_code(src)
    elif fmt == "code":
        code = src.read(0, src.length)
    else:
        raise LoaderError(f"unsupported format {fmt}")
    if exheader_path:
        found = (ExHeader.parse(Path(exheader_path).read_bytes()[:0x400]), exheader_path)
    elif search_exheader:
        found = find_beside(path)
    else:
        found = None
    exh, origin = found if found else (None, None)
    return build_code_image(code, exh, origin, fmt)
