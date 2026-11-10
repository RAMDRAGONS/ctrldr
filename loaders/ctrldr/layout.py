"""Code set layout: from an ExHeader, or recovered from a bare SDK .code image."""

import struct
from dataclasses import dataclass

from .consts import CTR_START_CALLS, CTR_START_EXIT
from .util import CODE_BASE, PAGE, LoaderError, align_down, align_up


@dataclass
class Section:
    name: str
    start: int
    size: int
    file_off: int = -1          # offset into the flat image bytes, -1 for uninitialized
    perm: int = 4               # rwx bits as in segment_t.perm (r=4, w=2, x=1)
    sclass: str = "DATA"


def section_from_codeset(name, cs, off, perm, sclass):
    return Section(name, cs.address, cs.size, off, perm, sclass)


def layout_from_exheader(exh, code):
    text, ro, data = exh.text, exh.rodata, exh.data
    if exh.is_firm_module:
        offs = [0, text.size, text.size + ro.size]
    else:
        offs = [0, text.pages * PAGE, (text.pages + ro.pages) * PAGE]
    end = offs[2] + data.size
    if end > len(code):
        raise LoaderError(
            f"ExHeader code set needs 0x{end:x} bytes but .code has 0x{len(code):x}")
    secs = [section_from_codeset(".text", text, offs[0], 5, "CODE")]
    if ro.size:
        secs.append(section_from_codeset(".rodata", ro, offs[1], 4, "CONST"))
    if data.size:
        secs.append(section_from_codeset(".data", data, offs[2], 6, "DATA"))
    if exh.bss_size:
        secs.append(Section(".bss", data.address + data.size, exh.bss_size, -1, 6, "BSS"))
    return secs


class ArmScan:
    """Byte-level ARM decoding over a flat image mapped at CODE_BASE."""

    def __init__(self, data, base=CODE_BASE):
        self.data = data
        self.base = base
        self.nwords = len(data) // 4
        self.words = struct.unpack_from(f"<{self.nwords}I", data, 0)

    def word(self, ea):
        i = (ea - self.base) >> 2
        if 0 <= i < self.nwords:
            return self.words[i]
        return None

    @staticmethod
    def branch_target(ea, w):
        """Decode B/BL/BLX(imm). Returns (target, kind, thumb) or None."""
        if (w >> 25) & 7 != 5:
            return None
        off = w & 0xFFFFFF
        if off & 0x800000:
            off -= 0x1000000
        target = ea + 8 + (off << 2)
        if w >> 28 == 0xF:
            return target + ((w >> 23) & 2), "blx", True
        return target, "bl" if w & 0x01000000 else "b", False

    def ldr_literal(self, ea, w):
        """LDR Rd, [PC, #imm] -> (rd, value) or None."""
        if w >> 28 == 0xF or w & 0x0F7F0000 != 0x051F0000:
            return None
        imm = w & 0xFFF
        lit = ea + 8 + (imm if w & 0x00800000 else -imm)
        v = self.word(lit)
        if v is None:
            return None
        return (w >> 12) & 0xF, v

    def find_zi_loop(self, func_ea, limit=16):
        """Match the crt0 nninitRegion body. Returns (zi_base, zi_limit) or None."""
        regs = {}
        for i in range(limit):
            ea = func_ea + i * 4
            w = self.word(ea)
            if w is None:
                return None
            lit = self.ldr_literal(ea, w)
            if lit:
                regs[lit[0]] = lit[1]
                continue
            # mov r2,#0 / cmp r0,r1 / strcc r2,[r0],#4 / bcc loop
            if w == 0xE3A02000 and self.word(ea + 4) == 0xE1500001 and \
                    self.word(ea + 8) == 0x34802004 and self.word(ea + 12) == 0x3AFFFFFC:
                if 0 in regs and 1 in regs and regs[0] <= regs[1]:
                    return regs[0], regs[1]
                return None
        return None

    def ctr_start_calls(self, entry):
        """Decode __ctr_start: a run of BL/BLX then a terminating B."""
        calls = []
        ea = entry
        for _ in range(16):
            w = self.word(ea)
            if w is None:
                break
            br = self.branch_target(ea, w)
            if br is None or w >> 28 not in (0xE, 0xF):
                break
            target, kind, thumb = br
            if kind == "b":
                return calls, (target, ea)
            calls.append((target, thumb, ea))
            ea += 4
        return calls, None


def page_code_score(words):
    """Fraction of non-zero words carrying the ARM 'always' condition."""
    nz = [w for w in words if w]
    if len(nz) < 64:
        return None
    return sum(1 for w in nz if w >> 28 == 0xE) / len(nz)


def page_thumb_score(halves):
    """
    Thumb BL/BLX pairs plus push {..,lr} / pop {..,pc} / bx lr per page.
    Thumb code pages score 90 and up; data rarely passes 75.
    """
    bl = 0
    prev = 0
    for h in halves:
        if prev & 0xF800 == 0xF000 and h & 0xC000 == 0xC000:
            bl += 1
        prev = h
    frame = sum(1 for h in halves if h >> 8 in (0xB5, 0xBD) or h == 0x4770)
    return bl, bl + frame


def page_is_code(words, halves):
    sc = page_code_score(words)
    if sc is None:
        return None
    if sc >= 0.45:
        return True
    bl, total = page_thumb_score(halves)
    return bl >= 30 and total >= 90


class LayoutInference:
    """Recover the code set of a page-aligned SDK .code image."""

    def __init__(self, data):
        self.data = data
        self.scan = ArmScan(data)
        self.image_end = CODE_BASE + len(data)
        self.notes = []
        self.symbols = {}
        self.thumb = set()
        self.functions = set()
        self.sdk_app = False

    def note(self, s):
        self.notes.append(s)

    def run(self):
        data = self.data
        if len(data) % PAGE:
            raise LoaderError(
                f".code size 0x{len(data):x} is not page aligned; this looks like a FIRM "
                "module or a truncated image, which needs an ExHeader")
        zi = self.find_zi()
        text_end = self.find_text_end()
        self.text_end = text_end
        text_size = self.trim(CODE_BASE, text_end) - CODE_BASE
        ro_start = text_end
        literals = self.collect_literals(text_end)
        written = sorted(literals["written"])
        targets = literals["targets"]

        if zi is None:
            zi = self.estimate_bss(text_end, literals["all"])
        zi_base, zi_limit = zi
        if not (ro_start <= zi_base <= self.image_end and self.image_end - zi_base < PAGE * 2):
            self.note(f"ZI base 0x{zi_base:x} does not end the image (0x{self.image_end:x}); "
                      "treating the image end as the data end")
            zi_base = self.trim(ro_start, self.image_end) if zi_base > self.image_end else zi_base
            zi_base = min(zi_base, self.image_end)

        upper = align_down(written[0]) if written else align_down(zi_base)
        upper = min(upper, align_down(zi_base))
        vt = literals["vtables"]
        lower = max((v for v in vt if v < upper), default=ro_start)
        data_start = self.find_data_start(ro_start, upper, targets, lower)

        secs = [Section(".text", CODE_BASE, text_size, 0, 5, "CODE")]
        if data_start > ro_start:
            ro_size = self.trim(ro_start, data_start) - ro_start
            if ro_size:
                secs.append(Section(".rodata", ro_start, ro_size, ro_start - CODE_BASE, 4, "CONST"))
        data_size = max(0, min(zi_base, self.image_end) - data_start)
        if data_size:
            secs.append(Section(".data", data_start, data_size, data_start - CODE_BASE, 6, "DATA"))
        bss_size = zi_limit - zi_base
        if bss_size > 0:
            secs.append(Section(".bss", zi_base, bss_size, -1, 6, "BSS"))
        return secs

    def trim(self, start, end):
        """End of the last non-zero word in [start, end), word aligned."""
        o0, o = start - CODE_BASE, end - CODE_BASE
        while o > o0 and self.data[o - 1] == 0:
            o -= 1
        return CODE_BASE + align_up(o, 4)

    def find_zi(self):
        calls, exit_branch = self.scan.ctr_start_calls(CODE_BASE)
        if calls:
            zi = self.scan.find_zi_loop(calls[0][0])
            if zi:
                self.sdk_app = True
                self.symbols[CODE_BASE] = "__ctr_start"
                self.functions.add(CODE_BASE)
                if len(calls) == len(CTR_START_CALLS):
                    names = CTR_START_CALLS
                else:
                    names = ["nninitRegion"] + [None] * (len(calls) - 2) + ["nnMain"]
                for (target, thumb, _), name in zip(calls, names):
                    if thumb:
                        self.thumb.add(target)
                    self.functions.add(target)
                    if name:
                        self.symbols[target] = name
                # nn::svc::ExitProcess is "svc 0x03; bx lr".
                if exit_branch and self.scan.word(exit_branch[0]) == 0xEF000003:
                    self.symbols[exit_branch[0]] = CTR_START_EXIT
                    self.functions.add(exit_branch[0])
                self.symbols[zi[0]] = "Image$$ZI$$ZI$$Base"
                return zi
        # Fall back to any copy of the ZI loop in the first pages of code.
        for i in range(min(self.scan.nwords, 0x4000) - 4):
            if self.scan.words[i] == 0xE3A02000:
                zi = self.scan.find_zi_loop(CODE_BASE + max(0, i - 2) * 4, 8)
                if zi:
                    self.note("ZI loop found outside __ctr_start")
                    return zi
        zi = self.find_libctru_bss()
        if zi:
            return zi
        self.note("no ZI clear loop found; .bss size is estimated from pointer literals")
        return None

    def find_libctru_bss(self):
        """libctru crt0: ldr r0,=__bss_start__ / ldr r1,=__bss_end__ / sub r1,r1,r0 / bl ClearMem."""
        s = self.scan
        for i in range(min(s.nwords, 0x400) - 3):
            ea = CODE_BASE + i * 4
            a = s.ldr_literal(ea, s.words[i])
            b = s.ldr_literal(ea + 4, s.words[i + 1])
            if a and b and a[0] == 0 and b[0] == 1 and s.words[i + 2] == 0xE0411000:
                if a[1] <= b[1]:
                    self.symbols[a[1]] = "__bss_start__"
                    self.symbols[b[1]] = "__bss_end__"
                    self.note("libctru crt0 detected")
                    return a[1], b[1]
        return None

    def find_text_end(self):
        """First page boundary after the last page that decodes as ARM or Thumb code."""
        npages = len(self.data) // PAGE
        per_page = PAGE // 4
        halves = struct.unpack_from(f"<{len(self.data) // 2}H", self.data, 0)
        scores = []
        for p in range(npages):
            scores.append(page_is_code(self.scan.words[p * per_page:(p + 1) * per_page],
                                       halves[p * per_page * 2:(p + 1) * per_page * 2]))
        last_code = 0
        run_gap = 0
        for p, sc in enumerate(scores):
            if sc is None:
                continue
            if sc:
                last_code = p
                run_gap = 0
            else:
                run_gap += 1
                # A long stretch of non-code pages means .rodata has started.
                if run_gap >= 8:
                    break
        # Thumb code scores low as ARM; pull in following pages that receive
        # BL/BLX targets from ARM code. Literal pools produce stray 0xEB words,
        # so a page needs several distinct targets to count.
        hits = {}
        for p in range(last_code + 1):
            if not scores[p]:
                continue
            for i in range(p * per_page, (p + 1) * per_page):
                w = self.scan.words[i]
                if w >> 24 == 0xEB or w >> 25 == 0x7D:
                    t = ArmScan.branch_target(CODE_BASE + i * 4, w)[0]
                    tp = (t - CODE_BASE) // PAGE
                    if last_code < tp < npages:
                        hits.setdefault(tp, set()).add(t)
        p = last_code + 1
        while len(hits.get(p, ())) >= 4:
            last_code = p
            p += 1
        end = CODE_BASE + (last_code + 1) * PAGE
        tail = self._text_tail(end)
        return align_up(tail) if tail > end else end

    def _text_tail(self, ea):
        """
        Follow .text past a page boundary. Older SDK scatter files end TEXT
        with .init_array (ARMCC emits it as REL32 offsets back into code) and
        init_aeabi.o, and a short final page holds too few words to score.
        """
        s = self.scan
        if not s.word(ea - 4):
            return ea
        while True:
            w = s.word(ea)
            if w is None or w == 0:
                break
            if w & 0x80000000 and CODE_BASE <= (ea + w) - (1 << 32) < ea:
                ea += 4
                continue
            if w >> 28 == 0xE or ArmScan.branch_target(ea, w):
                ea += 4
                continue
            break
        return ea

    def call_targets(self, text_end):
        """
        BL/BLX targets from ARM code pages, for seeding functions before
        auto-analysis. A target must itself decode as an unconditional ARM
        instruction (or a Thumb one for BLX), which rejects most stray 0xEB
        words in literal pools.
        """
        s = self.scan
        n = (text_end - CODE_BASE) // 4
        arm, thumb = set(), set()
        for i in range(n):
            w = s.words[i]
            top = w >> 24
            if top != 0xEB and w >> 25 != 0x7D:
                continue
            t, _, is_thumb = ArmScan.branch_target(CODE_BASE + i * 4, w)
            if not CODE_BASE <= t < text_end or t == CODE_BASE + i * 4 + 4:
                continue
            if is_thumb:
                h = struct.unpack_from("<H", self.data, t - CODE_BASE)[0]
                if h and h != 0xFFFF:
                    thumb.add(t)
            else:
                tw = s.word(t)
                if tw is not None and tw >> 28 == 0xE:
                    arm.add(t)
        return arm, thumb

    def collect_literals(self, text_end):
        """
        Classify pointer literals loaded by code. "written" targets are used
        as a store base, so they lie in .data/.bss. "vtables" are stored as a
        value into an object and point at a run of code pointers; ARMCC emits
        vtables as constant data, so they lie in .rodata.
        """
        s = self.scan
        n = (text_end - CODE_BASE) // 4
        words = s.words
        hi = self.image_end + 0x4000000
        written, targets, allv, vtables = set(), set(), set(), set()
        for i in range(n):
            w = words[i]
            if w & 0x0F7F0000 != 0x051F0000 or w >> 28 == 0xF:
                continue
            lit = s.ldr_literal(CODE_BASE + i * 4, w)
            if lit is None:
                continue
            rd, v = lit
            if not text_end <= v < hi:
                continue
            allv.add(v)
            if v < self.image_end:
                targets.add(v)
            base_store, value_store = self._trace_literal(i, rd, n)
            if base_store:
                written.add(v)
            if value_store and v < self.image_end and self._is_vtable(v, text_end):
                vtables.add(v)
        return {"written": written, "targets": targets, "all": allv, "vtables": vtables}

    def _is_vtable(self, ea, text_end):
        for k in range(2):
            w = self.scan.word(ea + k * 4)
            if w is None or not CODE_BASE <= (w & ~1) < text_end:
                return False
        return True

    def _trace_literal(self, i, rd, n):
        """
        Follow rd for a few instructions after it is loaded. Returns
        (used as a store base, stored as a value).
        """
        words = self.scan.words
        for j in range(i + 1, min(i + 12, n)):
            x = words[j]
            if x >> 28 == 0xF:
                break
            op = (x >> 25) & 7
            if op == 3 and x & 0x10:
                continue                                      # media instructions
            load = (x >> 20) & 1
            rn = (x >> 16) & 0xF
            rt = (x >> 12) & 0xF
            if op in (2, 3) and not load:                     # STR/STRB
                if rn == rd:
                    return True, False
                if rt == rd:
                    return False, True
            if op == 0 and x & 0x90 == 0x90 and (x >> 5) & 3 == 1 and not load and rn == rd:
                return True, False                            # STRH
            if op == 4 and not load and rn == rd:
                return True, False                            # STM
            if op == 6 and not load and rn == rd:
                return True, False                            # VSTR/VSTM
            if op == 5:
                break
            # The function ends here; anything after is a literal pool or
            # another function with its own register contents.
            if x & 0x0FFFFFD0 == 0x012FFF10:
                break                                         # BX/BLX reg
            if op == 4 and load and x & (0x8000 | (1 << rd)):
                break                                         # LDM into pc or rd
            if op in (0, 1, 2, 3) and rt == 15:
                break                                         # write to pc
            if op in (2, 3) and load and rt == rd:
                break
            if op in (0, 1) and rt == rd and not (8 <= (x >> 21) & 0xF <= 11):
                break
            if op == 7 and x & 0x00100010 == 0x00100010 and rt == rd:
                break                                         # MRC into rd
        return False, False

    def find_data_start(self, ro_start, upper, targets, lower):
        """
        .data starts on the page after .rodata's zero padding. Candidates are
        page boundaries reached by a zero run that began inside the previous
        page; a literal pointing exactly at the boundary (the first .data
        object) and a long run both raise the score.
        """
        data = self.data
        best, best_score = None, -1
        p = max(ro_start + PAGE, align_up(lower + 8))
        while p <= upper:
            o = p - CODE_BASE
            if data[o - 1] == 0 or p in targets:
                z0 = o
                while z0 > 0 and data[z0 - 1] == 0:
                    z0 -= 1
                if align_up(z0) == o or z0 == o:
                    z1 = o
                    while z1 < len(data) and data[z1] == 0:
                        z1 += 1
                    score = (z1 - z0) + (0x1000 if p in targets else 0)
                    if score >= best_score:
                        best, best_score = p, score
            p += PAGE
        if best is None:
            self.note("no .rodata/.data boundary candidate; mapping everything after .text as .rodata")
            return upper
        return best

    def estimate_bss(self, text_end, literals):
        beyond = sorted(v for v in literals if v >= self.image_end and v < self.image_end + 0x2000000)
        if not beyond:
            return self.image_end, self.image_end
        # Stop at the first large hole: pointers past it are unrelated constants.
        last = beyond[0]
        for v in beyond[1:]:
            if v - last > 0x100000:
                break
            last = v
        return self.trim(CODE_BASE, self.image_end), align_up(last + 4, 4)


def compare_layouts(a, b, slack=0x10):
    """
    Describe differences between two layouts. Sizes may differ by trailing
    zero padding, which inference cannot tell apart from section contents.
    """
    out = []
    bm = {s.name: s for s in b}
    for s in a:
        t = bm.get(s.name)
        if t is None:
            out.append(f"{s.name} missing")
        elif s.start != t.start or abs(s.size - t.size) > slack:
            out.append(f"{s.name} 0x{s.start:x}+0x{s.size:x} vs 0x{t.start:x}+0x{t.size:x}")
    return "; ".join(out)
