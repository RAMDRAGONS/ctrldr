"""
Passes that need IDA's analysis results (functions, instructions), run once
auto-analysis has settled.
"""

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
