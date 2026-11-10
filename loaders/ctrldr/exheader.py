import struct
from dataclasses import dataclass, field
from pathlib import Path

from .consts import FIRM_MODULE_IDS
from .util import CODE_BASE, PAGE, LoaderError, cstr, u16, u32, u64


@dataclass
class CodeSetInfo:
    address: int = 0
    pages: int = 0
    size: int = 0


@dataclass
class ExHeader:
    name: str = ""
    flags: int = 0
    remaster_version: int = 0
    text: CodeSetInfo = field(default_factory=CodeSetInfo)
    rodata: CodeSetInfo = field(default_factory=CodeSetInfo)
    data: CodeSetInfo = field(default_factory=CodeSetInfo)
    stack_size: int = 0
    bss_size: int = 0
    dependencies: list = field(default_factory=list)
    save_data_size: int = 0
    jump_id: int = 0
    program_id: int = 0
    core_version: int = 0
    ideal_processor: int = 0
    affinity_mask: int = 0
    priority: int = 0
    extdata_id: int = 0
    services: list = field(default_factory=list)
    allowed_svcs: set = field(default_factory=set)
    handle_table_size: int = 0
    kernel_version: tuple = None
    memory_type: int = 0
    mappings: list = field(default_factory=list)    # (start, end, read_only)
    interrupts: list = field(default_factory=list)

    @property
    def compressed(self):
        return bool(self.flags & 1)

    @property
    def is_firm_module(self):
        return (self.program_id >> 32) == 0x00040130 and \
            (self.program_id & 0xFFFE) in FIRM_MODULE_IDS

    @staticmethod
    def parse(b):
        if len(b) < 0x400:
            raise LoaderError("ExHeader shorter than 0x400 bytes")
        e = ExHeader()
        e.name = cstr(b[0:8])
        e.flags = b[0x0D]
        e.remaster_version = u16(b, 0x0E)

        def codeset(o):
            return CodeSetInfo(u32(b, o), u32(b, o + 4), u32(b, o + 8))

        e.text = codeset(0x10)
        e.stack_size = u32(b, 0x1C)
        e.rodata = codeset(0x20)
        e.data = codeset(0x30)
        e.bss_size = u32(b, 0x3C)
        e.dependencies = [d for d in struct.unpack_from("<48Q", b, 0x40) if d]
        e.save_data_size = u64(b, 0x1C0)
        e.jump_id = u64(b, 0x1C8)
        e.program_id = u64(b, 0x200)
        e.core_version = u32(b, 0x208)
        flag0 = b[0x20E]
        e.ideal_processor = flag0 & 3
        e.affinity_mask = (flag0 >> 2) & 3
        e.priority = b[0x20F]
        e.extdata_id = u64(b, 0x230)
        for o in range(0x250, 0x360, 8):
            s = b[o:o + 8].split(b"\0", 1)[0]
            if s and all(0x20 <= c < 0x7F for c in s):
                e.services.append(s.decode("ascii"))
        e._parse_kernel_caps(struct.unpack_from("<28I", b, 0x370))
        return e

    def _parse_kernel_caps(self, descs):
        range_start = None
        for d in descs:
            if d == 0xFFFFFFFF:
                continue
            if d & 0xF0000000 == 0xE0000000:
                self.interrupts.append(d & 0x0FFFFFFF)
            elif d & 0xF8000000 == 0xF0000000:
                idx = (d >> 24) & 7
                for bit in range(24):
                    if d & (1 << bit):
                        self.allowed_svcs.add(idx * 24 + bit)
            elif d & 0xFE000000 == 0xFC000000:
                self.kernel_version = ((d >> 8) & 0xFF, d & 0xFF)
            elif d & 0xFF000000 == 0xFE000000:
                self.handle_table_size = d & 0x7FFFF
            elif d & 0xFF800000 == 0xFF000000:
                self.memory_type = (d >> 8) & 0xF
            elif d & 0xFFE00000 == 0xFF800000:
                # Ranges come as a start/end descriptor pair.
                addr = (d & 0xFFFFF) << 12
                if range_start is None:
                    range_start = (addr, bool(d & 0x100000))
                else:
                    self.mappings.append((range_start[0], addr, range_start[1]))
                    range_start = None
            elif d & 0xFFF00000 == 0xFFE00000:
                addr = (d & 0xFFFFF) << 12
                self.mappings.append((addr, addr + PAGE, bool(d & 0x100000)))

    def plausible(self):
        return self.text.address == CODE_BASE and self.text.size > 0 and \
            self.text.size <= self.text.pages * PAGE and \
            self.rodata.size <= self.rodata.pages * PAGE and \
            self.data.size <= self.data.pages * PAGE

    def code_length(self):
        """Decompressed .code length this code set implies."""
        if self.is_firm_module:
            return self.text.size + self.rodata.size + self.data.size
        return (self.text.pages + self.rodata.pages + self.data.pages) * PAGE


EXHEADER_NAMES = ("exheader.bin", "extheader.bin", "exh.bin", "exheader", "extheader")


def find_beside(path):
    """
    Look for an ExHeader in the same directory as a loose code.bin, under
    the names ExeFS/NCCH extractors use. Returns (ExHeader, path) or None.
    """
    if not path:
        return None
    p = Path(path)
    names = list(EXHEADER_NAMES) + [f"{p.stem}.exheader", f"{p.stem}_exheader.bin"]
    try:
        entries = {e.name.lower(): e for e in p.parent.iterdir() if e.is_file()}
    except OSError:
        return None
    for n in names:
        e = entries.get(n.lower())
        if e is None:
            continue
        try:
            exh = ExHeader.parse(e.read_bytes()[:0x400])
        except (OSError, LoaderError):
            continue
        if exh.plausible():
            return exh, str(e)
    return None
