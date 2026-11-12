"""Input formats: loose .code / code.bin, ExeFS images, 3DSX, 3GX and CRO modules."""

import struct
from dataclasses import dataclass, field
from pathlib import Path

from . import blz, cro
from .consts import DEFAULT_APP_MAPPINGS
from .exheader import ExHeader, find_beside
from .layout import ArmScan, LayoutInference, Section, call_targets_in, compare_layouts, layout_from_exheader
from .util import CODE_BASE, MEDIA_UNIT, PAGE, LoaderError, align_up, cstr, u16, u32

FORMATS = ("code", "ExeFS", "3DSX", "3GX", "CRO")


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
    data_symbols: set = field(default_factory=set)    # named eas that are data, not code
    comments: dict = field(default_factory=dict)      # ea -> comment
    types: list = field(default_factory=list)         # (ea, type name, count) to apply
    externs: list = field(default_factory=list)       # cro.Extern per slot of the extern segment
    extern_base: int = 0
    image_base: int = None                            # set as IDA's image base when not None
    info: list = field(default_factory=list)          # extra lines for the description comment
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
    magic = src.try_read(0x80, 4)
    if magic == cro.CRO_MAGIC:
        name_hdr = src.try_read(0x80, cro.HEADER_END - 0x80)
        name_off, name_size = struct.unpack_from("<II", name_hdr, 0x40)
        name = src.try_read(name_off, name_size) or b""
        # static.crs only describes code.bin; it is read alongside code.bin instead.
        return None if name.startswith(cro.STATIC_NAME.encode()) else "CRO"
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


def add_static_crs(img, path):
    """
    Names and comments from the static.crs that describes this code.bin: its
    named exports, and the words the loader fills with addresses inside CRO
    modules when they load.
    """
    crs = cro.find_static_crs(path)
    if crs is None:
        return
    text = img.sections[0]
    if not crs.segments or crs.segments[0][0] != text.start or crs.segments[0][1] != text.size:
        img.notes.append(f"ignored {crs.origin}: its segments do not match this code.bin")
        return
    named = 0
    for name, so in crs.named_exports():
        ea = crs.static_address(so)
        if ea is None:
            continue
        if crs.segments[so & 0xF][2] == cro.SEG_TEXT:
            if ea & 1:
                img.thumb.add(ea & ~1)
            img.functions.add(ea & ~1)
        else:
            img.data_symbols.add(ea)
        img.symbols.setdefault(ea & ~1, name)
        named += 1
    unresolved = crs.h["on_unresolved"]
    if unresolved != cro.NONE:
        ea = crs.static_address(unresolved)
        if ea is not None:
            # Module pointer slots hold this stub until their module is loaded.
            img.symbols.setdefault(ea & ~1, "nnroUnresolved")
            img.functions.add(ea & ~1)
            if ea & 1:
                img.thumb.add(ea & ~1)
    slots = 0
    romfs = Path(crs.origin).parent
    modules = {}
    for mod in crs.import_modules():
        target = modules.setdefault(mod.name, cro.find_module(romfs, mod.name))
        for so, patch_off in mod.anonymous:
            where = describe_import_target(target, mod.name, so)
            for p in crs.import_patches(patch_off):
                ea = crs.static_address(p.target)
                if ea is not None:
                    img.comments[ea] = f"nn::ro fills in: {where}"
                    slots += 1
    img.notes.append(f"{crs.origin}: {named} exported names, {slots} module pointers")


def describe_import_target(module, module_name, segment_offset):
    """'<Module>+0x<file offset>' plus the export name when the module file is available."""
    if module is None:
        return f"{module_name} seg{segment_offset & 0xF}+0x{segment_offset >> 4:X}"
    off = module.file_offset(segment_offset)
    name = module.export_name_at(segment_offset)
    where = f"{module_name}+0x{off:X}" if off is not None else \
        f"{module_name} seg{segment_offset & 0xF}+0x{segment_offset >> 4:X}"
    return f"{where} ({name})" if name else where


def load_cro(src, path, base=0):
    """
    A CRO module mapped at base with the file laid out as is, so that
    address - base is the offset in the .cro.
    """
    data = bytearray(src.read(0, src.length))
    mod = cro.Cro(bytes(data), path)
    lay = cro.CroLayout(mod, base)
    h = mod.h
    img = Image(kind="CRO", data=b"", sections=[], entry=base, image_base=base,
                layout_source="CRO segment table")
    img.info = cro.describe_module(mod)

    # Sections: header, the file-backed segments, the tables between them, .bss
    names = {cro.SEG_TEXT: (".text", 5, "CODE"), cro.SEG_RODATA: (".rodata", 4, "CONST"),
             cro.SEG_DATA: (".data", 6, "DATA")}
    regions = []
    for (start, size, sid), _ in zip(mod.segments, lay.seg_base):
        if size and start and sid in names:
            regions.append((start, size, sid))
    regions.sort()
    sections = [Section(".crohdr", base, h["code_offset"], 0, 4, "CONST")]
    cursor = h["code_offset"]
    for start, size, sid in regions:
        if start > cursor:
            sections.append(Section(".crotab", base + cursor, start - cursor, cursor, 4, "CONST"))
        name, perm, sclass = names[sid]
        sections.append(Section(name, base + start, size, start, perm, sclass))
        cursor = start + size
    if cursor < len(data):
        sections.append(Section(".crotab", base + cursor, len(data) - cursor, cursor, 4, "CONST"))
    sections = [s for s in sections if s.size > 0]
    text = next((s for s in sections if s.name == ".text"), None)
    if lay.bss_size:
        sections.append(Section(".bss", lay.bss, lay.bss_size, -1, 6, "BSS"))
    img.sections = sections

    # Internal relocations
    unsupported = 0
    for p in mod.relocations():
        loc = lay.address(p.target)
        if loc is None or p.segment >= len(lay.seg_base):
            unsupported += 1
            continue
        value = lay.seg_base[p.segment] + p.addend
        if not cro.apply_patch(data, base, loc, p.kind, value):
            unsupported += 1
            continue
        if p.kind in (cro.R_ARM_ABS32, cro.R_ARM_TARGET1):
            img.fixups.append((loc, value))
            if lay.in_text(value) and not lay.in_text(loc):
                # code pointers in data: vtables, callbacks
                img.functions.add(value & ~1)
                if value & 1:
                    img.thumb.add(value & ~1)
    if unsupported:
        img.notes.append(f"{unsupported} relocations not applied (unsupported type or target)")

    # Imports: each target gets a slot in the extern segment
    crs = cro.find_static_crs(path)
    symbols = cro.find_symbol_map(path)
    sym_map = symbols[0] if symbols else {}
    if symbols:
        img.notes.append(f"code.bin names from {symbols[1]}")
    static_exports = {}
    if crs is not None:
        for name, so in crs.named_exports():
            static_exports[name] = crs.static_address(so)
        img.notes.append(f"static module from {crs.origin}")
    elif any(m.name == cro.STATIC_NAME for m in mod.import_modules()):
        img.notes.append("no static.crs found: imports from code.bin are named by segment offset")

    img.extern_base = align_up(lay.end, PAGE)
    slots = {}

    def slot(key, name, comment):
        if key not in slots:
            slots[key] = img.extern_base + 4 * len(img.externs)
            img.externs.append(cro.Extern(name, comment))
        return slots[key]

    def patch_list(patch_off, target):
        for p in mod.import_patches(patch_off):
            loc = lay.address(p.target)
            if loc is None or not cro.apply_patch(data, base, loc, p.kind, target + p.addend):
                img.notes.append(f"import patch at seg{p.target & 0xF}+0x{p.target >> 4:X} not applied")
                continue
            if p.kind in (cro.R_ARM_ABS32, cro.R_ARM_TARGET1):
                img.fixups.append((loc, target + p.addend))

    def static_target(so):
        ea = crs.static_address(so) if crs is not None else None
        if ea is None:
            return f"static_seg{so & 0xF}_{so >> 4:X}", "code.bin, address unknown without static.crs"
        name = sym_map.get(ea & ~1) or next((n for n, a in static_exports.items() if a == ea), None)
        return name or f"static_{ea & ~1:08X}", f"code.bin 0x{ea:08X}"

    romfs = Path(path).resolve().parent if path else None
    others = {}
    for imod in mod.import_modules():
        other = None
        if imod.name != cro.STATIC_NAME and romfs is not None:
            other = others.setdefault(imod.name, cro.find_module(romfs, imod.name))
        for so, patch_off in imod.anonymous:
            if imod.name == cro.STATIC_NAME:
                name, comment = static_target(so)
            else:
                where = describe_import_target(other, imod.name, so)
                export = other.export_name_at(so) if other else None
                off = other.file_offset(so) if other else None
                name = export or (f"{imod.name}_{off:X}" if off is not None else
                                  f"{imod.name}_seg{so & 0xF}_{so >> 4:X}")
                comment = where
            patch_list(patch_off, slot((imod.name, so), name, comment))
        for index, patch_off in imod.indexed:
            target_so = None
            if other is not None and index < len(other.indexed_exports()):
                target_so = other.indexed_exports()[index]
            name = (other.export_name_at(target_so) if other is not None and target_so is not None else None) \
                or f"{imod.name}_export_{index}"
            comment = describe_import_target(other, imod.name, target_so) if target_so is not None \
                else f"{imod.name} indexed export {index}"
            patch_list(patch_off, slot((imod.name, "index", index), name, comment))
    for name, patch_off in mod.named_imports():
        ea = static_exports.get(name)
        comment = f"code.bin 0x{ea:08X}" if ea is not None else "resolved by name at load"
        patch_list(patch_off, slot(("name", name), name, comment))

    # Exports and the entry points in the header
    for name, so in mod.named_exports():
        ea = lay.address(so)
        if ea is None:
            continue
        img.symbols[ea & ~1] = name
        if lay.in_text(ea) and so != h["control_object"]:
            img.functions.add(ea & ~1)
            if ea & 1:
                img.thumb.add(ea & ~1)
        else:
            img.data_symbols.add(ea & ~1)
    for i, so in enumerate(mod.indexed_exports()):
        ea = lay.address(so)
        if ea is not None:
            img.symbols.setdefault(ea & ~1, f"{mod.name}_export_{i}")
    for key, name in cro.ENTRY_NAMES:
        so = h[key]
        if so == cro.NONE:
            continue
        ea = lay.address(so)
        if ea is not None:
            img.symbols.setdefault(ea & ~1, name)
            img.functions.add(ea & ~1)
            if ea & 1:
                img.thumb.add(ea & ~1)
    if h["control_object"] != cro.NONE:
        ea = lay.address(h["control_object"])
        if ea is not None:
            img.symbols.setdefault(ea, "nnroControlObject_")
            img.data_symbols.add(ea)

    # What code.bin uses of this module
    if crs is not None:
        for imod in crs.import_modules():
            if imod.name != mod.name:
                continue
            for so, patch_off in imod.anonymous:
                ea = lay.address(so)
                users = [crs.static_address(p.target) for p in crs.import_patches(patch_off)]
                users = [f"0x{u:08X}" for u in users if u is not None]
                if ea is None or not users:
                    continue
                img.comments[ea & ~1] = "referenced by code.bin at " + ", ".join(users)
                if lay.in_text(ea):
                    img.functions.add(ea & ~1)
                    if ea & 1:
                        img.thumb.add(ea & ~1)

    # Function seeds from calls inside the module's code
    if text is not None:
        scan = ArmScan(bytes(data), base)
        arm, thumb = call_targets_in(scan, text.start, text.start + text.size)
        img.call_targets = arm | thumb
        img.thumb |= thumb

    # Header and table types
    img.types.append((base + 0x80, "CroHeader", 1))
    img.types.append((base + h["segment_table_offset"], "CroSegment", h["segment_count"]))
    for key, typ in (("named_export", "CroNamedExport"), ("indexed_export", "u32"),
                     ("import_module", "CroImportModule"), ("import_patch", "CroPatch"),
                     ("named_import", "CroNamedImport"), ("indexed_import", "CroIndexedImport"),
                     ("anonymous_import", "CroAnonymousImport"), ("relocation", "CroPatch")):
        if h[f"{key}_count"]:
            img.types.append((base + h[f"{key}_offset"], typ, h[f"{key}_count"]))

    img.data = bytes(data)
    prolog = next((ea for ea, n in img.symbols.items() if n == "nnroProlog"), None)
    img.entry = prolog if prolog is not None else (text.start if text is not None else base)
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


def load_image(src, path, fmt, exheader_path=None, search_exheader=True, cro_base=0):
    if fmt == "CRO":
        return load_cro(src, path, cro_base)
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
    img = build_code_image(code, exh, origin, fmt)
    add_static_crs(img, path)
    return img
