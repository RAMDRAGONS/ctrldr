import os
import struct

PAGE = 0x1000
MEDIA_UNIT = 0x200
CODE_BASE = 0x00100000


class LoaderError(Exception):
    pass


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def cstr(b):
    return b.split(b"\0", 1)[0].decode("ascii", "replace")


def align_up(v, a=PAGE):
    return (v + a - 1) & ~(a - 1)


def align_down(v, a=PAGE):
    return v & ~(a - 1)


class Source:
    """Random access over an IDA loader_input_t or a Python file object."""

    def __init__(self, f):
        self.f = f
        if hasattr(f, "size"):
            self.length = f.size()
        else:
            f.seek(0, os.SEEK_END)
            self.length = f.tell()

    def read(self, off, size):
        if off < 0 or size < 0 or off + size > self.length:
            raise LoaderError(f"read 0x{off:x}+0x{size:x} past end 0x{self.length:x}")
        self.f.seek(off)
        data = self.f.read(size)
        if len(data) != size:
            raise LoaderError(f"short read at 0x{off:x}")
        return bytes(data)

    def try_read(self, off, size):
        try:
            return self.read(off, size)
        except LoaderError:
            return None
