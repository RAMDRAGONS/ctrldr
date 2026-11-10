"""Bottom-up LZ77 ("BLZ") as used for ExeFS .code."""

from .util import LoaderError, u32


def footer(data, total_len=None):
    """
    Return (header_len, compressed_len, extra_len) if data ends in a BLZ
    footer. data may be just the tail of the stream when total_len is given.
    """
    total_len = len(data) if total_len is None else total_len
    if len(data) < 8:
        return None
    word = u32(data, len(data) - 8)
    extra = u32(data, len(data) - 4)
    hdr_len = word >> 24
    comp_len = word & 0xFFFFFF
    if not 8 <= hdr_len <= 0xB or comp_len > total_len or comp_len < hdr_len:
        return None
    if extra == 0 or extra > 0x4000000:
        return None
    # The footer is padded with 0xFF up to the header length.
    if any(x != 0xFF for x in data[len(data) - hdr_len:len(data) - 8]):
        return None
    return hdr_len, comp_len, extra


def decompress(data):
    ft = footer(data)
    if ft is None:
        raise LoaderError("no BLZ footer")
    hdr_len, comp_len, extra = ft
    out = bytearray(len(data) + extra)
    out[:len(data)] = data
    src = len(data) - hdr_len
    dst = len(out)
    end = len(data) - comp_len
    while src > end:
        src -= 1
        ctrl = out[src]
        for _ in range(8):
            if src <= end:
                break
            if ctrl & 0x80:
                src -= 2
                pair = out[src] | (out[src + 1] << 8)
                dist = (pair & 0x0FFF) + 3
                count = (pair >> 12) + 3
                if dist >= count:
                    out[dst - count:dst] = out[dst - count + dist:dst + dist]
                    dst -= count
                else:
                    for _ in range(count):
                        dst -= 1
                        out[dst] = out[dst + dist]
            else:
                src -= 1
                dst -= 1
                out[dst] = out[src]
            ctrl = (ctrl << 1) & 0xFF
    if dst < 0:
        raise LoaderError("corrupt BLZ stream")
    return bytes(out)
