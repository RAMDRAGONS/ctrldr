"""
IDA 9.x loader for Nintendo 3DS executables: ExeFS .code / code.bin
(BLZ-compressed or not, with or without an ExHeader), ExeFS images, 3DSX
homebrew, 3GX plugins and CRO modules. The format parsing lives in the
ctrldr package next to this file.
"""

import os
import re
import struct
import sys

import ida_auto
import ida_bytes
import ida_diskio
import ida_entry
import ida_funcs
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_lines
import ida_loader
import ida_name
import ida_nalt
import ida_netnode
import ida_offset
import ida_segment
import ida_segregs
import ida_typeinf

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

import ctrldr  # noqa: E402
from ctrldr.consts import (  # noqa: E402
    CONFIG_MEM, FMT_PREFIX, LOADER_NAME, NETNODE_NAME, SHARED_PAGE, SYSMODULE_NAMES,
)
from ctrldr.util import PAGE, LoaderError, Source, align_up  # noqa: E402

FORMAT_LABELS = {"code": "code.bin", "ExeFS": "ExeFS", "3DSX": "3DSX", "3GX": "3GX", "CRO": "CRO module"}


def log(msg):
    print(f"[{LOADER_NAME}] {msg}")


def _perm(p):
    r = 0
    if p & 4:
        r |= ida_segment.SEGPERM_READ
    if p & 2:
        r |= ida_segment.SEGPERM_WRITE
    if p & 1:
        r |= ida_segment.SEGPERM_EXEC
    return r


def add_segment(start, end, name, sclass, perm, sparse=False, seg_type=None):
    s = ida_segment.segment_t()
    s.start_ea = start
    s.end_ea = end
    s.bitness = 1
    s.align = ida_segment.saRelPara
    s.comb = ida_segment.scPub
    s.perm = _perm(perm)
    s.sel = ida_segment.setup_selector(0)
    if seg_type is not None:
        s.type = seg_type
    flags = ida_segment.ADDSEG_NOSREG
    if sparse:
        flags |= ida_segment.ADDSEG_SPARSE
    if not ida_segment.add_segm_ex(s, name, sclass, flags):
        raise LoaderError(f"could not create segment {name} at 0x{start:X}")
    seg = ida_segment.getseg(start)
    ida_segregs.set_default_sreg_value(seg, ida_idp.str2reg("T"), 0)
    return seg


def setup_processor():
    ida_idp.set_processor_type("ARM", ida_idp.SETPROC_LOADER)
    ida_ida.inf_set_app_bitness(32)
    ida_ida.inf_set_lflags(ida_ida.inf_get_lflags() | ida_ida.LFLG_PC_FLAT)


def setup_compiler():
    # ARMCC follows the AAPCS and the Itanium C++ ABI, which IDA models as GNU EABI.
    ida_typeinf.set_compiler_id(ida_typeinf.COMP_GNU, "eabi")
    ida_ida.inf_set_demnames(ida_ida.DEMNAM_GCC3)
    ida_typeinf.add_til("armv12", ida_typeinf.ADDTIL_DEFAULT)
    header = os.path.join(os.path.dirname(ctrldr.__file__), "ctr_types.h")
    errors = ida_typeinf.idc_parse_types(header, ida_typeinf.PT_FILE)
    if errors:
        log(f"{errors} errors while parsing {header}")


def apply_named_type(ea, name, count=1):
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, name):
        return
    if count > 1:
        array = ida_typeinf.tinfo_t()
        if not array.create_array(tif, count):
            return
        tif = array
    ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)


def set_name(ea, name, public=True):
    flags = ida_name.SN_NOWARN | ida_name.SN_NOCHECK | ida_name.SN_FORCE
    if public:
        flags |= ida_name.SN_PUBLIC
    ida_name.set_name(ea, name, flags)


def map_kernel_regions(img):
    """Pages the kernel maps into every process, plus the ExHeader IO/VRAM mappings."""
    add_segment(CONFIG_MEM, CONFIG_MEM + PAGE, "CFG_MEM", "DATA", 4, sparse=True)
    add_segment(SHARED_PAGE, SHARED_PAGE + PAGE, "SHARED_PAGE", "DATA", 6, sparse=True)
    set_name(CONFIG_MEM, "g_ConfigMem")
    set_name(SHARED_PAGE, "g_SharedPage")
    apply_named_type(CONFIG_MEM, "CtrConfigMem")
    apply_named_type(SHARED_PAGE, "CtrSharedPage")
    for start, end, read_only in img.mappings:
        if end <= start or ida_segment.getseg(start) or ida_segment.getseg(end - 1):
            continue
        if 0x1F000000 <= start < 0x1F600000:
            name, sclass = f"VRAM_{start:08X}", "DATA"
        elif 0x1FF00000 <= start < 0x1FF80000:
            name, sclass = f"DSPRAM_{start:08X}", "DATA"
        elif 0x1EC00000 <= start < 0x1F000000:
            name, sclass = f"IO_{start:08X}", "IO"
        else:
            name, sclass = f"MAP_{start:08X}", "DATA"
        add_segment(start, end, name, sclass, 4 if read_only else 6, sparse=True)


def describe(img):
    lines = [f"Loaded by {LOADER_NAME} ({FORMAT_LABELS[img.kind]}), layout: {img.layout_source}"]
    for s in img.sections:
        lines.append(f"  {s.name:8} 0x{s.start:08X}-0x{s.start + s.size:08X} (0x{s.size:X})")
    exh = img.exheader
    if exh:
        lines.append(f"Title: {exh.name}  Program ID: {exh.program_id:016X}  "
                     f"Remaster version: {exh.remaster_version}")
        lines.append(f"Stack: 0x{exh.stack_size:X}  Priority: {exh.priority}  "
                     f"Ideal CPU: {exh.ideal_processor}  Core version: 0x{exh.core_version:X}")
        if exh.kernel_version:
            lines.append(f"Kernel release: {exh.kernel_version[0]}.{exh.kernel_version[1]}  "
                         f"Handle table: {exh.handle_table_size}  Memory type: {exh.memory_type}")
        deps = []
        for d in exh.dependencies:
            if d >> 32 == 0x00040130 and (d & 0xFFFF) in SYSMODULE_NAMES:
                deps.append(SYSMODULE_NAMES[d & 0xFFFF])
            else:
                deps.append(f"{d:016X}")
        if deps:
            lines.append("Dependencies: " + ", ".join(deps))
        if exh.services:
            lines.append("Services: " + ", ".join(exh.services))
    lines.extend(img.info)
    lines.extend("Note: " + n for n in img.notes)
    return lines


def write_metadata(img):
    top = img.sections[0].start
    for i, line in enumerate(describe(img)):
        ida_lines.update_extra_cmt(top, ida_lines.E_PREV + i, line)
    node = ida_netnode.netnode(NETNODE_NAME, 0, True)
    node.hashset("kind", img.kind.encode())
    node.hashset("layout_source", img.layout_source.encode())
    for s in img.sections:
        node.hashset(f"section{s.name}", struct.pack("<II", s.start, s.size))
    if img.exheader:
        node.hashset("program_id", struct.pack("<Q", img.exheader.program_id))
        node.hashset("services", ",".join(img.exheader.services).encode())


# The SDK and the ARM runtime are linked into every program and are applied
# with auto-analysis. Middleware is applied afterwards, only to what they
# left unnamed, so its copies of their small functions cannot claim them.
CORE_SIGNATURES = ("ctr_sdk", "ctr_armcc")


def find_signatures(ext="sig"):
    """ctr_*.<ext> in the user and IDA sig/arm directories, user copies first."""
    dirs = [os.path.join(ida_diskio.get_user_idadir(), "sig", "arm"),
            ida_diskio.idadir(os.path.join("sig", "arm"))]
    found, seen = [], set()
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for n in sorted(os.listdir(d)):
            if re.fullmatch(r"ctr_.*\." + ext, n, re.I) and n.lower() not in seen:
                seen.add(n.lower())
                found.append(os.path.join(d, n))
    return found


def is_core_signature(path):
    return os.path.splitext(os.path.basename(path))[0].lower() in CORE_SIGNATURES


class PostAnalysis(ida_idp.IDB_Hooks):
    """Passes that need functions to exist, run once auto-analysis settles."""

    def __init__(self, text_start, text_end, middleware):
        super().__init__()
        self.text = (text_start, text_end)
        self.middleware = middleware

    def auto_empty_finally(self):
        self.unhook()
        if getattr(ctrldr, "_post_hook", None) is self:
            ctrldr._post_hook = None
        from ctrldr import idapost
        run_library_passes()
        try:
            for sig, kept, undone in idapost.apply_middleware_signatures(self.middleware):
                log(f"{sig}: {kept} functions named, {undone} isolated or unsupported matches undone")
        except Exception as e:  # noqa: BLE001
            log(f"middleware signatures failed: {e!r}")
        run_library_passes()
        run_post_analysis(*self.text)


def run_library_passes():
    """
    Settle unknown_libname matches. Runs after the SDK and runtime
    signatures and again after the middleware.
    """
    from ctrldr import idapost
    try:
        versions = idapost.linked_versions(find_signatures("versions"))
        if versions:
            log("library versions linked: " + ", ".join(sorted(versions)))
        annotated, renamed, undone = idapost.resolve_unknown_libnames(
            find_signatures("candidates"), versions)
        if annotated or undone:
            log(f"unknown_libname: {annotated} given FLIRT candidates, {renamed} renamed, "
                f"{undone} short matches undone")
    except Exception as e:  # noqa: BLE001
        log(f"unknown_libname pass failed: {e!r}")


def run_post_analysis(start, end):
    from ctrldr import idapost

    def switch_pass():
        helpers, tables = idapost.setup_switch8(start, end)
        if helpers:
            log(f"switch8 helpers: {helpers}, tables set up: {tables}")

    def svc_pass():
        named, used = idapost.name_svc_wrappers(start, end)
        log(f"{sum(used.values())} SVC sites ({len(used)} distinct), {named} wrappers named")

    def ipc_pass():
        log(f"{idapost.annotate_ipc_requests(start, end)} IPC request functions annotated")

    def hexrays_pass():
        try:
            from ctrldr import hexrays
        except ImportError:
            return
        if hexrays.install():
            log("Hex-Rays SVC/CP15/FPSCR filters installed")

    # Each pass stands on its own, so one failing leaves the others to run.
    for step in (switch_pass, svc_pass, ipc_pass, hexrays_pass):
        try:
            step()
        except Exception as e:  # noqa: BLE001
            log(f"{step.__name__} failed: {e!r}")


def populate(img):
    setup_processor()
    setup_compiler()
    for s in img.sections:
        if s.size <= 0:
            continue
        initialized = s.file_off >= 0
        end = s.start + (s.size if initialized else align_up(s.size, 4))
        add_segment(s.start, end, s.name, s.sclass, s.perm, sparse=not initialized)
        if initialized:
            ida_loader.mem2base(img.data[s.file_off:s.file_off + s.size], s.start, -1)
    if img.image_base is not None:
        ida_nalt.set_imagebase(img.image_base)
    if img.kind != "CRO":
        map_kernel_regions(img)
    add_externs(img)

    treg = ida_idp.str2reg("T")
    for ea in img.thumb:
        ida_segregs.split_sreg_range(ea, treg, 1, ida_segregs.SR_user)

    for ea, target in img.fixups:
        fd = ida_fixup_data(target)
        fd.set(ea)
        ida_bytes.create_dword(ea, 4)
        ida_offset.op_plain_offset(ea, 0, 0)

    entry_name = img.symbols.get(img.entry, "start")
    ida_entry.add_entry(img.entry, img.entry, entry_name, True)
    ida_ida.inf_set_start_ea(img.entry)
    ida_ida.inf_set_start_ip(img.entry)
    for ea, name in img.symbols.items():
        set_name(ea, name)
    for ea, text in img.comments.items():
        ida_bytes.set_cmt(ea, text, False)
    for ea, name, count in img.types:
        apply_named_type(ea, name, count)
    for ea in img.functions | img.call_targets:
        ida_auto.auto_make_proc(ea)
    main = next((ea for ea, n in img.symbols.items() if n == "nnMain"), None)
    if main is not None:
        ida_ida.inf_set_main(main)

    middleware = []
    if img.sdk_app or img.exheader is not None:
        sigs = find_signatures()
        core = [sig for sig in sigs if is_core_signature(sig)]
        middleware = [sig for sig in sigs if not is_core_signature(sig)]
        for sig in core:
            ida_funcs.plan_to_apply_idasgn(sig)
        if sigs:
            log("queued FLIRT: " + ", ".join(os.path.basename(s) for s in core) +
                "; after analysis: " + (", ".join(os.path.basename(s) for s in middleware) or "none"))
        else:
            log("no ctr_*.sig under sig/arm; tools/build_ctr_sigs.py builds them from the SDK")

    write_metadata(img)
    text = img.sections[0]
    hook = PostAnalysis(text.start, text.start + text.size, middleware)
    hook.hook()
    ctrldr._post_hook = hook


def add_externs(img):
    """Imported symbols of a CRO: one named dword per import, which the patched words point at."""
    if not img.externs:
        return
    start = img.extern_base
    add_segment(start, start + 4 * len(img.externs), "extern", "XTRN", 4,
                sparse=True, seg_type=ida_segment.SEG_XTRN)
    for i, ext in enumerate(img.externs):
        ea = start + 4 * i
        ida_bytes.create_dword(ea, 4)
        set_name(ea, ext.name)
        ida_bytes.set_cmt(ea, ext.comment, True)


def ida_fixup_data(target):
    import ida_fixup
    fd = ida_fixup.fixup_data_t(ida_fixup.FIXUP_OFF32)
    fd.off = target
    return fd


def _input_path():
    p = ida_nalt.get_input_file_path()
    return p if p and os.path.exists(p) else None


def accept_file(li, filename):
    try:
        fmt = ctrldr.detect_format(Source(li), filename)
    except Exception:  # noqa: BLE001
        return 0
    if fmt is None:
        return 0
    return {
        "format": f"{FMT_PREFIX} ({FORMAT_LABELS[fmt]})",
        "processor": "ARM",
        "options": 1 | ida_loader.ACCEPT_FIRST,
    }


def load_file(li, neflags, format):
    fmt = next((k for k, v in FORMAT_LABELS.items() if format == f"{FMT_PREFIX} ({v})"), None)
    if fmt is None:
        return 0
    src = Source(li)
    path = _input_path()
    cro_base = 0
    if fmt == "CRO" and not (ida_kernwin.cvar.batch or ida_kernwin.is_ida_library()):
        # A module has no fixed address; at 0, addresses are offsets in the .cro file.
        chosen = ida_kernwin.ask_addr(0, "Address to map the CRO module at (0: addresses equal file offsets)")
        if chosen is not None and chosen != ida_idaapi.BADADDR:
            cro_base = chosen & ~0xFFF
    try:
        img = ctrldr.load_image(src, path, fmt, cro_base=cro_base)
    except LoaderError as e:
        if fmt not in ("code", "ExeFS") or ida_kernwin.cvar.batch or ida_kernwin.is_ida_library():
            raise
        exh = ida_kernwin.ask_file(False, "*.bin", f"{e}\nSelect the matching ExHeader")
        if not exh:
            raise
        img = ctrldr.load_image(src, path, fmt, exheader_path=exh)
    log(f"layout: {img.layout_source}")
    for s in img.sections:
        log(f"  {s.name:8} 0x{s.start:08X}-0x{s.start + s.size:08X}")
    for n in img.notes:
        log("note: " + n)
    populate(img)
    return 1
