"""Print what ctrldr recovers for a file: python3 -m ctrldr path [--exheader path] [--cro-base addr]."""

import argparse
import sys

from . import Source, detect_format, load_image


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ctrldr", description=__doc__)
    ap.add_argument("path")
    ap.add_argument("--exheader", help="use this ExHeader instead of searching beside the input")
    ap.add_argument("--no-exheader", action="store_true",
                    help="ignore any ExHeader beside the input and infer the layout")
    ap.add_argument("--cro-base", type=lambda v: int(v, 0), default=0,
                    help="address to map a CRO module at (default 0: addresses are file offsets)")
    args = ap.parse_args(argv)
    with open(args.path, "rb") as f:
        src = Source(f)
        fmt = detect_format(src, args.path)
        if fmt is None:
            print("unrecognized format", file=sys.stderr)
            return 1
        img = load_image(src, args.path, fmt, args.exheader, not args.no_exheader, args.cro_base)
    print(f"format: {fmt}  layout: {img.layout_source}  compressed: {img.compressed}")
    for s in img.sections:
        print(f"  {s.name:8} 0x{s.start:08X}-0x{s.start + s.size:08X} size 0x{s.size:X}")
    for ea, name in sorted(img.symbols.items()):
        print(f"  sym 0x{ea:08X} {name}{' (thumb)' if ea in img.thumb else ''}")
    print(f"  {len(img.call_targets)} call targets, {len(img.fixups)} fixups, "
          f"{len(img.comments)} comments")
    if img.externs:
        print(f"  extern segment at 0x{img.extern_base:08X}: {len(img.externs)} imports")
        for i, e in enumerate(img.externs):
            print(f"    0x{img.extern_base + 4 * i:08X} {e.name}  ; {e.comment}")
    for line in img.info:
        print("  " + line)
    for n in img.notes:
        print("  note:", n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
