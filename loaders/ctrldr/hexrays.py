"""
Hex-Rays microcode filters for 3DS code: each SVC becomes a typed call with
its kernel register ABI, and the CP15/VFP system register accesses the SDK
uses become named intrinsics instead of __mrc/__mcr/__asm blocks.
"""

import ida_allins
import ida_hexrays
import ida_idp

from .svc import SVCS


def _cp15(insn):
    """(opc1, Rt, CRn, CRm, opc2) for a p15 MRC/MCR, else None."""
    if insn.Op1.specflag1 != 15:
        return None
    return insn.Op1.value, insn.Op2.reg, insn.Op2.specflag1, insn.Op2.specflag2, insn.Op3.value


class SvcFilter(ida_hexrays.udc_filter_t):
    def match(self, cdg):
        if cdg.insn.itype != ida_allins.ARM_svc:
            return False
        entry = SVCS.get(cdg.insn.Op1.value)
        return bool(entry and entry[1] and self.init(entry[1]))


class Cp15Filter(ida_hexrays.udc_filter_t):
    """TLS pointer reads and the CP15 barrier operations ARMv6 code issues."""

    def match(self, cdg):
        insn = cdg.insn
        if insn.itype == ida_allins.ARM_mrc:
            f = _cp15(insn)
            if f and f[0] == 0 and (f[2], f[3], f[4]) == (13, 0, 3):
                return self.init(
                    f"ThreadLocalStorage *__usercall getThreadLocalStorage@<R{f[1]}>();")
        elif insn.itype == ida_allins.ARM_mcr:
            f = _cp15(insn)
            if f and f[0] == 0 and f[2] == 7:
                name = {(10, 4): "__dsb", (10, 5): "__dmb", (5, 4): "__isb"}.get((f[3], f[4]))
                if name:
                    return self.init(f"void {name}();")
        return False


class FpscrFilter(ida_hexrays.udc_filter_t):
    """VMSR/VMRS on FPSCR, as written by the runtime's _fp_init."""

    def match(self, cdg):
        insn = cdg.insn
        if insn.itype == ida_allins.ARM_vmsr and _is_fpscr(insn.Op1.reg):
            return self.init(f"void __usercall __set_FPSCR(u32 value@<R{insn.Op2.reg}>);")
        if insn.itype == ida_allins.ARM_vmrs and _is_fpscr(insn.Op2.reg) and insn.Op1.reg < 15:
            return self.init(f"u32 __usercall __get_FPSCR@<R{insn.Op1.reg}>();")
        return False


def _is_fpscr(reg):
    return ida_idp.get_reg_name(reg, 4).upper() == "FPSCR"


_installed = []


def install():
    """Install the filters once per session. Returns False without Hex-Rays."""
    if _installed:
        return True
    if not ida_hexrays.init_hexrays_plugin():
        return False
    for cls in (SvcFilter, Cp15Filter, FpscrFilter):
        f = cls()
        if ida_hexrays.install_microcode_filter(f, True):
            _installed.append(f)
    return bool(_installed)


def uninstall():
    while _installed:
        ida_hexrays.install_microcode_filter(_installed.pop(), False)
