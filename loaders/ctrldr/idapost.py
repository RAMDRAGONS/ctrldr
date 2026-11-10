"""
Passes that need IDA's analysis results (functions, instructions), run once
auto-analysis has settled.
"""

import re
import struct
from collections import Counter

import ida_allins
import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_idp
import ida_name
import ida_nalt
import ida_regfinder
import ida_segregs
import ida_ua
import ida_xref
import idautils

from .flirt import Candidates
from .svc import SEND_SYNC_REQUEST_NAMES, SVC_NAMES

BADADDR = ida_idaapi.BADADDR
CMDBUF_OFFSET = 0x80          # ThreadLocalStorage::commandBuffer
SWITCH8_HEAD = struct.pack("<II", 0xE55EC001, 0xE153000C)   # ldrb r12,[lr,#-1]; cmp r3,r12


def _decode(ea):
    insn = ida_ua.insn_t()
    return insn if ida_ua.decode_insn(insn, ea) else None


def _is_auto_named(ea):
    flags = ida_bytes.get_flags(ea)
    if ida_bytes.has_user_name(flags):
        return False
    f = ida_funcs.get_func(ea)
    return not (f and f.flags & ida_funcs.FUNC_LIB)


def _unique_name(base):
    name, n = base, 1
    while ida_name.get_name_ea(BADADDR, name) != BADADDR:
        n += 1
        name = f"{base}_{n}"
    return name


def _set_name(ea, name):
    ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)


def name_svc_wrappers(start, end):
    """
    Comment every SVC with its name and name the small functions that do
    nothing but wrap one. Returns (named wrappers, Counter of SVC numbers).
    """
    used = Counter()
    named = 0
    for ea in range(start, end - 3, 4):
        w = ida_bytes.get_dword(ea)
        if w >> 24 != 0xEF or not ida_bytes.is_code(ida_bytes.get_flags(ea)):
            continue
        num = w & 0xFFFFFF
        used[num] += 1
        svc = SVC_NAMES.get(num)
        label = f"svc{svc}" if svc else f"svc_{num:02X}"
        ida_bytes.set_cmt(ea, f"{label} (0x{num:02X})", True)
        f = ida_funcs.get_func(ea)
        if svc and f and f.end_ea - f.start_ea <= 0x40 and _is_auto_named(f.start_ea) and \
                ida_name.get_name_ea(BADADDR, label) == BADADDR:
            _set_name(f.start_ea, label)
            named += 1
    return named, used


def _send_sync_targets():
    out = set()
    for n in SEND_SYNC_REQUEST_NAMES:
        ea = ida_name.get_name_ea(BADADDR, n)
        if ea != BADADDR:
            out.add(ea)
    return out


def annotate_ipc_requests(start, end):
    """
    Find functions that build an IPC request in the TLS command buffer and
    send it. The header word stored to commandBuffer[0] is commented, and
    functions still carrying an auto name are named after it.
    """
    send_targets = _send_sync_targets()
    calls = (ida_allins.ARM_bl, ida_allins.ARM_blx1, ida_allins.ARM_b)
    requests = 0
    for fea in idautils.Functions(start, end):
        tls_regs = set()        # hold the TLS pointer
        cmdbuf_regs = set()     # hold &commandBuffer[0]
        headers = []
        sends = False
        for ea in idautils.FuncItems(fea):
            insn = _decode(ea)
            if insn is None:
                continue
            it = insn.itype
            if it == ida_allins.ARM_mrc and insn.Op1.specflag1 == 15 and \
                    (insn.Op2.specflag1, insn.Op2.specflag2, insn.Op3.value) == (13, 0, 3):
                tls_regs.add(insn.Op2.reg)
                cmdbuf_regs.discard(insn.Op2.reg)
            elif it == ida_allins.ARM_add and insn.Op2.type == ida_ua.o_reg and \
                    insn.Op2.reg in tls_regs and insn.Op3.type == ida_ua.o_imm and \
                    insn.Op3.value == CMDBUF_OFFSET:
                cmdbuf_regs.add(insn.Op1.reg)
            elif it == ida_allins.ARM_svc and insn.Op1.value == 0x32:
                sends = True
            elif it in calls and insn.Op1.type == ida_ua.o_near and insn.Op1.addr in send_targets:
                sends = True
            elif it == ida_allins.ARM_str and insn.Op2.type in (ida_ua.o_displ, ida_ua.o_phrase):
                base, disp = insn.Op2.reg, insn.Op2.addr if insn.Op2.type == ida_ua.o_displ else 0
                if (base in tls_regs and disp == CMDBUF_OFFSET) or (base in cmdbuf_regs and disp == 0):
                    value = ida_regfinder.find_reg_value(ea, insn.Op1.reg)
                    if value is not None:
                        headers.append((ea, value & 0xFFFFFFFF))
        if not (sends and headers):
            continue
        requests += 1
        for ea, hdr in headers:
            ida_bytes.set_cmt(ea, f"IPC header 0x{hdr:08X}: command 0x{hdr >> 16:04X}, "
                                  f"{(hdr >> 6) & 0x3F} normal + {hdr & 0x3F} translate words", False)
        if len({h for _, h in headers}) == 1 and _is_auto_named(fea):
            _set_name(fea, _unique_name(f"IpcRequest_{headers[0][1]:08X}"))
    return requests


def _thumb(ea):
    return ida_segregs.get_sreg(ea, ida_idp.str2reg("T")) == 1


def setup_switch8(start, end):
    """
    ARMCC's __ARM_switch8 / __ARM_common_switch8 dispatch a Thumb switch from
    a byte table placed right after the BLX that calls them: a case count n,
    then n + 1 halfword offsets (the last one is the default) from the table
    start. Mark the helpers as non-returning, turn each table into data and
    describe it as a switch so the targets get analysed and decompiled.
    """
    helpers = []
    ea = start
    while True:
        ea = ida_bytes.find_bytes(SWITCH8_HEAD, ea, range_end=end)
        if ea == BADADDR:
            break
        if ea % 4 == 0:
            helpers.append(ea)
        ea += 4
    tables = 0
    treg = ida_idp.str2reg("T")
    for helper in helpers:
        ida_funcs.add_func(helper)
        f = ida_funcs.get_func(helper)
        if f:
            f.flags |= ida_funcs.FUNC_NORET
            ida_funcs.update_func(f)
        if _is_auto_named(helper):
            _set_name(helper, _unique_name("__ARM_switch8"))
        for call in list(idautils.CodeRefsTo(helper, False)):
            if not _thumb(call):
                continue
            table = call + 4
            count = ida_bytes.get_byte(table)
            offsets = [ida_bytes.get_byte(table + 1 + i) for i in range(count + 1)]
            targets = [table + 2 * o for o in offsets]
            ida_bytes.del_items(table, ida_bytes.DELIT_SIMPLE, count + 2)
            ida_bytes.create_byte(table, 1)
            ida_bytes.create_byte(table + 1, count + 1)
            si = ida_nalt.switch_info_t()
            si.set_jtable_element_size(1)
            si.set_shift(1)
            si.flags |= ida_nalt.SWI_ELBASE | ida_nalt.SWI_DEF_IN_TBL
            si.jumps = table + 1
            si.elbase = table
            si.ncases = count
            si.lowcase = 0
            si.startea = call
            si.defjump = targets[-1]
            si.set_expr(3, ida_ua.dt_dword)
            ida_nalt.set_switch_info(call, si)
            for t in set(targets):
                ida_segregs.split_sreg_range(t, treg, 1, ida_segregs.SR_auto)
                ida_xref.add_cref(call, t, ida_xref.fl_JN)
                ida_auto.auto_make_code(t)
            tables += 1
    return len(helpers), tables


UNKNOWN_LIBNAME = "unknown_libname"
MAX_LISTED_CANDIDATES = 8
NEIGHBOUR_RANGE = 0x400
# Agreeing on more than one scope level (nn::os, not just nn) is what
# separates a real hint from the namespace every SDK function shares.
MIN_SCOPE_MATCH = 2


def _is_library_name(ea):
    f = ida_funcs.get_func(ea)
    name = ida_name.get_name(ea)
    return bool(f and f.start_ea == ea and f.flags & ida_funcs.FUNC_LIB and
                not name.startswith(UNKNOWN_LIBNAME))


def _plain(name):
    return re.sub(r"_\d+$", "", name)


def _refs_agree(ea, mod):
    """
    A candidate whose referenced name contradicts a FLIRT-named target at
    the same offset is not the function here.
    """
    for off, name in mod.refs:
        targets = list(idautils.CodeRefsFrom(ea + off, False)) + list(idautils.DataRefsFrom(ea + off))
        named = [t for t in targets if _is_library_name(t)]
        if named and all(_plain(ida_name.get_name(t)) != name for t in named):
            return False
    return True


def _scope(name):
    """Enclosing scopes of a symbol, from its demangled form."""
    text = ida_name.demangle_name(name, ida_name.MNG_SHORT_FORM) or name
    parts, depth, cur = [], 0, ""
    i = 0
    while i < len(text):
        c = text[i]
        if c == "<":
            depth += 1
        elif c == ">":
            depth -= 1
        elif c == "(" and depth == 0:
            break
        if depth == 0 and text.startswith("::", i):
            parts.append(cur)
            cur = ""
            i += 2
            continue
        cur += c
        i += 1
    return [p.split(" ")[-1] for p in parts]


def _context_names(f):
    """Names of the FLIRT-identified functions around, calling and called by f."""
    out = []
    for ref in idautils.CodeRefsTo(f.start_ea, False):
        caller = ida_funcs.get_func(ref)
        if caller and _is_library_name(caller.start_ea):
            out.append(ida_name.get_name(caller.start_ea))
    for ea in idautils.FuncItems(f.start_ea):
        for ref in idautils.CodeRefsFrom(ea, False):
            callee = ida_funcs.get_func(ref)
            if callee and callee.start_ea != f.start_ea and _is_library_name(callee.start_ea):
                out.append(ida_name.get_name(callee.start_ea))
    for step in (ida_funcs.get_prev_func, ida_funcs.get_next_func):
        g = step(f.start_ea)
        if g and abs(g.start_ea - f.start_ea) <= NEIGHBOUR_RANGE and _is_library_name(g.start_ea):
            out.append(ida_name.get_name(g.start_ea))
    return out


def _pick_by_context(names, context):
    """The single candidate sharing the deepest scope with the context, if any."""
    scopes = [_scope(n) for n in context]
    scored = []
    for name in names:
        s = _scope(name)
        best = 0
        for t in scopes:
            k = 0
            while k < min(len(s), len(t)) and s[k] == t[k]:
                k += 1
            best = max(best, k)
        scored.append((best, name))
    top = max((b for b, _ in scored), default=0)
    winners = [n for b, n in scored if b == top]
    return winners[0] if top >= MIN_SCOPE_MATCH and len(winners) == 1 else None


def resolve_unknown_libnames(paths):
    """
    List the possible names of each unknown_libname function in its comment,
    and rename it when the library functions around it point to exactly one.
    Returns (functions annotated, functions renamed).
    """
    cands = Candidates(paths)
    if not len(cands):
        return 0, 0
    span = cands.max_length
    annotated = renamed = 0
    for ea in list(idautils.Functions()):
        if not ida_name.get_name(ea).startswith(UNKNOWN_LIBNAME):
            continue
        f = ida_funcs.get_func(ea)
        data = ida_bytes.get_bytes(ea, span) or b""
        names = sorted({n for m in cands.match(data) if _refs_agree(ea, m) for n in m.names})
        if not names:
            continue
        shown = sorted({ida_name.demangle_name(n, ida_name.MNG_SHORT_FORM) or n for n in names})
        lines = shown[:MAX_LISTED_CANDIDATES]
        if len(shown) > MAX_LISTED_CANDIDATES:
            lines.append(f"... {len(shown) - MAX_LISTED_CANDIDATES} more")
        ida_funcs.set_func_cmt(f, "FLIRT candidates:\n" + "\n".join(lines), False)
        annotated += 1
        pick = names[0] if len(names) == 1 else _pick_by_context(names, _context_names(f))
        if pick:
            _set_name(ea, _unique_name(pick))
            renamed += 1
    return annotated, renamed
