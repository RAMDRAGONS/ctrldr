r"""
Build FLIRT signatures for 3DS executables from the CTR-SDK, ARMCC and
middleware packages.

    python3 -I tools/build_ctr_sigs.py \
        --sdk  "Nintendo 3DS - CTR-SDK (World) (11_6_1-20180622).zip" \
        --sdk  "Nintendo 3DS - CTR-SDK (World) (4_2_8-20130828).zip" \
        --armcc "Nintendo 3DS - ARM Compiler - ARMCC for Nintendo (World) (4_1_nintendo-b1454-20150227).zip" \
        --lib nw "Nintendo 3DS - NintendoWare for CTR (World) (3_7_6-SDK11_4_0-20170428).zip" \
        --lib nex "Nintendo 3DS - CTR-NEX (World) (4_6_0-S1150-20180626).zip"

Writes ctr_sdk.sig (the nn:: libraries and crt0), ctr_armcc.sig (the ARM C
and C++ runtime) and one ctr_NAME.sig per --lib name to sig/arm in the IDA
user directory ($IDAUSR, else %APPDATA%\Hex-Rays\IDA Pro on Windows or
~/.idapro elsewhere), where the ctrldr loader applies them. pelf and sigmake
come from the FLAIR tools in <IDA>/tools/flair; the IDA directory is taken
from --flair, $IDADIR or the usual install locations.

--sdk takes a No-Intro CTR-SDK zip, the CTR_SDK-*.zip inside it, an SDK
tarball, or an extracted CTR_SDK directory. --armcc takes a No-Intro ARMCC
zip, the zip or MSI inside it, or an extracted ARMCC directory (the one
holding lib/armlib). Unpacking an ARMCC MSI needs the full 7-Zip (7z or 7zz;
--sevenzip to override). --lib takes a name and any package laid out like
the SDK (NintendoWare, CTR-NEX, CTR-Pia, nlib, the CTR_MW middleware): its
CTR-TS.Process.MPCore release libraries are used, sample programs excepted.

Every option may repeat, and packages given the same --lib name share one
signature; patterns from all inputs are merged, and a function that is
identical across versions keeps its name. Byte-identical functions under
different names are dropped when short; longer ones stay as nameless
modules (unknown_libname in IDA) and their candidate names go to
ctr_*.candidates beside the signatures.
"""

import argparse
from collections import Counter
import fnmatch
import glob
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

SDK_LIB_DIR = "libraries/CTR-TS.Process.MPCore/release/"
# Middleware packages (NintendoWare, CTR-NEX, Pia, nlib, ...) follow the SDK
# build layout under their own roots.
RELEASE_LIB_DIR = "/ctr-ts.process.mpcore/release/"
# Sample programs build their own copies of libraries; matched against
# paths that include the names of nested archives.
SAMPLE_PATH = re.compile(r"sampledemo|/samples?/|/demos?/|[-_]demos?[-_./]", re.I)
ARCHIVE_SUFFIXES = (".zip", ".7z", ".tgz", ".tar.gz", ".tar")
# The product a library belongs to, from the package root nearest to it.
FAMILY_MARKERS = [
    ("sdk", re.compile(r"(?:^|/)ctr[_-]sdk[^/]*/", re.I)),
    ("nw", re.compile(r"(?:^|/)(?:nintendoware|nw_ctr|nw4c)[^/]*/", re.I)),
    ("nex", re.compile(r"(?:^|/)ctr_nex[^/]*/", re.I)),
    ("pia", re.compile(r"(?:^|/)ctr_pia[^/]*/", re.I)),
    ("nlib", re.compile(r"(?:^|/)nlib[^/]*/", re.I)),
    ("mw", re.compile(r"(?:^|/)ctr_mw-[^/]*/", re.I)),
]
FAMILY_PRODUCTS = {
    "sdk": "CTR-SDK", "nw": "NintendoWare", "nex": "CTR-NEX", "pia": "CTR-Pia",
    "nlib": "nlib", "mw": "CTR middleware",
}
LIB_NAME = re.compile(r"[A-Za-z0-9_]+")

# armlib/cpplib variants for an ARMv5TE+ little-endian, non-PIC, 16-bit
# wchar_t target, which is what armlink picks for --cpu MPCore. The suffix
# letters are decoded in lib/armlib/libattrs.map: e = RWPI, f = FPIC and
# u = 32-bit wchar_t are never used by CTR-SDK builds.
ARMCC_LIB_GLOBS = [
    "armlib/c_5*.l", "armlib/h_5*.l", "armlib/f_5*.l", "armlib/fz_5*.l",
    "armlib/fj_5*.l", "armlib/g_5*.l", "armlib/m_5*.l", "armlib/vfpsupport.l",
    "cpplib/cpp_5*.l", "cpplib/cpprt_5*.l",
]
ARMCC_EXCLUDED_FLAGS = set("efu")


def log(msg):
    print(f"[build_ctr_sigs] {msg}", flush=True)


EXE = ".exe" if os.name == "nt" else ""


def _ida_install_dirs():
    """Likely IDA installation directories, newest-looking first."""
    dirs = []
    for env in ("IDADIR", "IDA_DIR"):
        if os.environ.get(env):
            dirs.append(os.environ[env])
    patterns = [str(Path.home() / "ida*"), str(Path.home() / "IDA*")]
    system = platform.system()
    if system == "Windows":
        for env in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
            if os.environ.get(env):
                patterns.append(os.path.join(os.environ[env], "IDA*"))
                patterns.append(os.path.join(os.environ[env], "Programs", "IDA*"))
    elif system == "Darwin":
        patterns.append("/Applications/IDA*.app/Contents/MacOS")
    else:
        patterns += ["/opt/ida*", "/opt/IDA*", "/usr/local/ida*"]
    for pat in patterns:
        dirs += sorted(glob.glob(pat), reverse=True)
    return dirs


def find_flair(explicit):
    candidates = [explicit] if explicit else []
    candidates += [os.path.join(d, "tools", "flair") for d in _ida_install_dirs()]
    for c in candidates:
        if c and all(os.path.isfile(os.path.join(c, t + EXE)) for t in ("pelf", "sigmake")):
            return c
    sys.exit("FLAIR tools (pelf, sigmake) not found; pass --flair <IDA>/tools/flair")


def flair_tool(flair, name):
    return os.path.join(flair, name + EXE)


def find_sevenzip(explicit):
    if explicit:
        return explicit
    for name in ("7z", "7zz"):
        found = shutil.which(name)
        if found:
            return found
    if os.name == "nt":
        for env in ("ProgramFiles", "ProgramFiles(x86)"):
            path = os.path.join(os.environ.get(env, ""), "7-Zip", "7z.exe")
            if os.path.isfile(path):
                return path
    return None


def default_sig_dir():
    base = os.environ.get("IDAUSR", "").split(os.pathsep)[0]
    if not base:
        if os.name == "nt" and os.environ.get("APPDATA"):
            base = os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro")
        else:
            base = str(Path.home() / ".idapro")
    return os.path.join(base, "sig", "arm")


def run_tool(args):
    return subprocess.run(args, capture_output=True, text=True, errors="replace")


# Archive access

def open_nested_zip(path, work):
    """
    Open a zip, descending into a single inner zip as No-Intro packages wrap
    them. The inner zip is unpacked to disk first: seeking inside a deflated
    member restarts decompression, which makes direct access very slow.
    """
    z = zipfile.ZipFile(path)
    names = [n for n in z.namelist() if not n.endswith("/")]
    if len(names) == 1 and names[0].lower().endswith(".zip"):
        inner = Path(work) / Path(names[0]).name
        with z.open(names[0]) as fsrc, open(inner, "wb") as fdst:
            shutil.copyfileobj(fsrc, fdst, 1 << 20)
        z.close()
        return zipfile.ZipFile(inner)
    return z


def unique_target(dest, name):
    """dest/name, numbered when packages ship same-named libraries in several modules."""
    target = Path(dest) / name
    n = 1
    while target.exists():
        n += 1
        target = Path(dest) / f"{Path(name).stem}_{n}{Path(name).suffix}"
    return target


def is_archive(name):
    return name.lower().endswith(ARCHIVE_SUFFIXES)


class PackageWalker:
    """
    Copy files out of a package: a directory, zip, tarball or 7z archive,
    descending into the archives nested in it. Each file is identified by a
    path that runs through the names of the archives holding it.
    """

    def __init__(self, work, sevenzip):
        self.work = Path(work)
        self.sevenzip = sevenzip
        self.nested = self.work / "nested"

    def collect(self, src, wanted, dest):
        """[(path, copied file)] for the files of src that wanted(path) accepts."""
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        self.nested.mkdir(parents=True, exist_ok=True)
        out = []
        self._walk(Path(src), "", wanted, dest, out)
        return sorted(out)

    def _walk(self, src, prefix, wanted, dest, out):
        if src.is_dir():
            for f in sorted(src.rglob("*")):
                if f.is_file():
                    self._file(prefix + f.relative_to(src).as_posix(), f, wanted, dest, out)
        elif zipfile.is_zipfile(src):
            self._zip(src, prefix, wanted, dest, out)
        elif src.name.lower().endswith(".7z"):
            self._sevenzip(src, prefix, wanted, dest, out)
        elif tarfile.is_tarfile(src):
            self._tar(src, prefix, wanted, dest, out)
        else:
            log(f"not an archive: {prefix or src}")

    def _wants_archive(self, path):
        return is_archive(path) and not SAMPLE_PATH.search("/" + path)

    def _file(self, path, f, wanted, dest, out):
        if wanted(path):
            target = unique_target(dest, f.name)
            shutil.copy2(f, target)
            out.append((path, target))
        elif self._wants_archive(path):
            self._walk(f, path + "/", wanted, dest, out)

    def _descend(self, path, opener, wanted, dest, out):
        """Unpack a nested archive to disk and walk it; seeking within a
        compressed member would restart decompression for every read."""
        tmp = unique_target(self.nested, Path(path).name)
        with opener() as fsrc, open(tmp, "wb") as fdst:
            shutil.copyfileobj(fsrc, fdst, 1 << 20)
        try:
            self._walk(tmp, path + "/", wanted, dest, out)
        finally:
            tmp.unlink()

    def _zip(self, src, prefix, wanted, dest, out):
        with zipfile.ZipFile(src) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                path = prefix + info.filename.replace("\\", "/")
                if wanted(path):
                    target = unique_target(dest, Path(path).name)
                    with z.open(info) as fsrc, open(target, "wb") as fdst:
                        shutil.copyfileobj(fsrc, fdst)
                    out.append((path, target))
                elif self._wants_archive(path):
                    self._descend(path, lambda i=info: z.open(i), wanted, dest, out)

    def _tar(self, src, prefix, wanted, dest, out):
        with tarfile.open(src) as t:
            for m in t:
                if not m.isfile():
                    continue
                path = prefix + m.name
                if wanted(path):
                    target = unique_target(dest, Path(path).name)
                    with t.extractfile(m) as fsrc, open(target, "wb") as fdst:
                        shutil.copyfileobj(fsrc, fdst)
                    out.append((path, target))
                elif self._wants_archive(path):
                    self._descend(path, lambda m=m: t.extractfile(m), wanted, dest, out)

    def _sevenzip(self, src, prefix, wanted, dest, out):
        if not self.sevenzip:
            sys.exit(f"7-Zip is required to read {src}; install it or pass --sevenzip")
        listing = subprocess.run([self.sevenzip, "l", "-slt", "-ba", str(src)], check=True,
                                 capture_output=True, text=True, errors="replace").stdout
        members, path, is_dir = [], None, False
        for line in listing.splitlines() + [""]:
            if line.startswith("Path = "):
                path = line[7:].replace("\\", "/")
            elif line.startswith("Folder = "):
                is_dir = line.endswith("+")
            elif not line.strip() and path is not None:
                if not is_dir:
                    members.append(path)
                path, is_dir = None, False
        picked = [m for m in members
                  if wanted(prefix + m) or self._wants_archive(prefix + m)]
        if not picked:
            return
        tmp = Path(tempfile.mkdtemp(dir=self.nested))
        try:
            names = tmp / "names.txt"
            names.write_text("\n".join(picked) + "\n", encoding="utf-8")
            tree = tmp / "tree"
            subprocess.run([self.sevenzip, "x", "-y", "-scsUTF-8", f"-o{tree}", f"-i@{names}",
                            str(src)], check=True, stdout=subprocess.DEVNULL)
            for m in picked:
                f = tree / m
                if f.is_file():
                    self._file(prefix + m, f, wanted, dest, out)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def release_library(path, lib_dir=RELEASE_LIB_DIR):
    """Whether path is a library straight inside a CTR-TS.Process.MPCore release directory."""
    n = "/" + path
    i = n.lower().find(lib_dir)
    if i < 0 or SAMPLE_PATH.search(n[:i + 1]):
        return False
    return "/" not in n[i + len(lib_dir):]


def sdk_libraries(walker, src, work):
    """The release MPCore libraries and crt0 objects of one SDK."""
    def wanted(path):
        leaf = path.rsplit("/", 1)[-1]
        return release_library(path, "/" + SDK_LIB_DIR.lower()) and (
            leaf.endswith(".a") or leaf.startswith("crt0"))

    return [f for _, f in walker.collect(src, lambda p: wanted(p.lower()), work)]


def package_libraries(walker, src, work):
    """The release MPCore libraries of a middleware package, samples excepted."""
    return [f for _, f in walker.collect(
        src, lambda p: release_library(p) and p.endswith(".a"), work)]


def library_family(path):
    """The family whose package root is nearest to the library, or None."""
    best, pos = None, -1
    for name, marker in FAMILY_MARKERS:
        for m in marker.finditer(path):
            if m.start() > pos:
                best, pos = name, m.start()
    return best


def bundle_libraries(walker, src, work):
    """
    Every release MPCore library in a bundle of packages, grouped by family
    and by the innermost archive holding it: {family: {package: [file]}}.
    The crt0 objects count when they sit in an SDK.
    """
    def wanted(path):
        leaf = path.rsplit("/", 1)[-1].lower()
        return release_library(path) and (leaf.endswith(".a") or
                                           (leaf.startswith("crt0") and library_family(path) == "sdk"))

    found, unknown = {}, []
    for path, f in walker.collect(src, wanted, work):
        family = library_family(path)
        if family is None:
            unknown.append(path)
            f.unlink()
            continue
        parts = path.split("/")
        archives = [x for x in parts[:-1] if is_archive(x)]
        package = archives[-1] if archives else Path(src).name
        found.setdefault(family, {}).setdefault(package, []).append(f)
    if unknown:
        log(f"{Path(src).name}: {len(unknown)} libraries of no known product skipped, "
            f"such as {unknown[0]}; give such packages with --lib")
    return found


def package_version(src):
    """The last parenthesised part of a No-Intro name, else the file name."""
    name = Path(src).name
    groups = re.findall(r"\(([^()]*)\)", name)
    if groups:
        return groups[-1]
    return re.sub(r"(\.(zip|7z|tgz|tar\.gz|tar))$", "", name, flags=re.I)


def sdk_version(src):
    name = re.sub(r"\.(zip|7z|tgz|tar\.gz|tar)$", "", Path(src).name, flags=re.I)
    m = (re.search(r"(\d+_\d+(?:_\d+)?(?:-\d{8})?)", name) or re.search(r"(SNAPSHOT-\d{8})", name)
         or re.search(r"(\d+(?:\.\d+)+)", name))
    return m.group(1) if m else package_version(src)


# ARMCC MSI unpacking

def msi_file_paths(stream_dir):
    """
    Map the hashed file keys inside an MSI's cabinets to install paths, using
    the File, Component and Directory tables that 7z exposes as streams.
    """
    d = Path(stream_dir)

    def stream(name):
        return (d / f"!{name}").read_bytes()

    pool, data = stream("_StringPool"), stream("_StringData")
    codepage = struct.unpack_from("<I", pool, 0)[0]
    idx_size = 3 if codepage & 0x80000000 else 2
    strings = [""]
    off = 0
    i = 4
    while i < len(pool):
        length, refs = struct.unpack_from("<HH", pool, i)
        i += 4
        if length == 0 and refs != 0:
            # A string of 64 KiB or more spans two pool entries but keeps a
            # single id; the second entry holds its length.
            lo, hi = struct.unpack_from("<HH", pool, i)
            i += 4
            length = (hi << 16) | lo
        strings.append(data[off:off + length].decode("latin-1"))
        off += length

    def table(name, cols):
        raw = stream(name)
        width = {"s": idx_size, "i2": 2, "i4": 4}
        row = sum(width[c] for c in cols)
        n = len(raw) // row
        rows = [[None] * len(cols) for _ in range(n)]
        p = 0
        for ci, c in enumerate(cols):
            for r in range(n):
                v = int.from_bytes(raw[p:p + width[c]], "little")
                rows[r][ci] = strings[v] if c == "s" else v
                p += width[c]
        return rows

    files = table("File", ["s", "s", "s", "i4", "s", "s", "i2", "i4"])
    components = {r[0]: r[2] for r in table("Component", ["s", "s", "s", "i2", "s", "s"])}
    directories = {r[0]: (r[1], r[2]) for r in table("Directory", ["s", "s", "s"])}

    def long_name(n):
        # "target:source" pairs name the installed and the media directory;
        # each side may be "short|long".
        return n.split(":")[0].split("|")[-1]

    def dir_path(key):
        parts = []
        while key in directories:
            parent, default = directories[key]
            name = long_name(default)
            if name not in (".", "SourceDir"):
                parts.append(name)
            if not parent or parent == key:
                break
            key = parent
        return "/".join(reversed(parts))

    return {f[0]: f"{dir_path(components.get(f[1], ''))}/{long_name(f[2])}" for f in files}


def unpack_msi(msi, dest, sevenzip):
    if not sevenzip:
        sys.exit("7-Zip is required to unpack the ARMCC MSI; install it or pass --sevenzip")
    streams = Path(dest) / "msi"
    cabs = Path(dest) / "cab"
    tree = Path(dest) / "tree"
    for p in (streams, cabs, tree):
        p.mkdir(parents=True, exist_ok=True)
    # Without the type, 7-Zip opens an MSI holding one cabinet as that
    # cabinet and hides the tables.
    subprocess.run([sevenzip, "x", "-y", "-tCompound", f"-o{streams}", str(msi)], check=True,
                   stdout=subprocess.DEVNULL)
    for cab in streams.glob("*.cab"):
        subprocess.run([sevenzip, "x", "-y", f"-o{cabs}", str(cab)], check=True,
                       stdout=subprocess.DEVNULL)
    for key, rel in msi_file_paths(streams).items():
        if "/lib/" not in f"/{rel}":
            continue
        src = cabs / key
        if src.is_file():
            target = tree / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)
    libs = [p for p in tree.rglob("armlib") if p.is_dir()]
    if not libs:
        sys.exit(f"no lib/armlib inside {msi}")
    return libs[0].parent


def armcc_lib_root(src, work, sevenzip):
    """Return the ARMCC lib directory (holding armlib/ and cpplib/) for src."""
    p = Path(src)
    Path(work).mkdir(parents=True, exist_ok=True)
    if p.is_dir():
        hits = [d.parent for d in p.rglob("armlib") if d.is_dir()]
        if not hits:
            sys.exit(f"no lib/armlib under {src}")
        return hits[0]
    if p.suffix.lower() == ".msi":
        return unpack_msi(p, work, sevenzip)
    z = open_nested_zip(p, work)
    msis = [n for n in z.namelist() if n.lower().endswith(".msi")]
    if not msis:
        sys.exit(f"no MSI inside {src}")
    msi_path = Path(work) / Path(msis[0]).name
    with z.open(msis[0]) as fsrc, open(msi_path, "wb") as fdst:
        shutil.copyfileobj(fsrc, fdst)
    z.close()
    return unpack_msi(msi_path, work, sevenzip)


def armcc_libraries(lib_root):
    out = []
    for pattern in ARMCC_LIB_GLOBS:
        sub, glob = pattern.split("/")
        for f in sorted((Path(lib_root) / sub).glob("*")):
            if not fnmatch.fnmatch(f.name, glob):
                continue
            flags = f.stem.split("_", 1)[1][1:] if "_" in f.stem else ""
            if ARMCC_EXCLUDED_FLAGS & set(flags):
                continue
            out.append(f)
    return out


# FLAIR

# ARMCC tags every section with local build attribute and tag symbols; they
# name nothing, and a module left with only those shows up as unknown_libname.
NOISE_SYMBOL = re.compile(r"^(BuildAttributes\$\$|__tagsym\$\$)")
MIN_DEFINED_BYTES = 10
# ARMCC library variants append tags to the symbol (__aeabi_uidiv$div0,
# _printf$int$ll); every variant is the same routine as far as naming goes.
# $Sub$$ and Image$$ style linker names do not match.
VARIANT_SUFFIX = re.compile(r"^([A-Za-z_][^$]*)\$[A-Za-z]\w*(?:\$\w+)*$")


def base_symbol(name):
    m = VARIANT_SUFFIX.match(name)
    return m.group(1) if m else name


def filter_pattern_line(line):
    """
    Drop ARMCC noise symbols from a pelf pattern line and strip variant tags
    from the rest. Returns None when the module keeps no public name, or when
    it has so few fixed bytes (one or two instruction stubs such as
    "b target") that it would match anywhere.
    """
    tokens = line.split(" ")
    if len(tokens) < 6:
        return line
    head, rest = tokens[:4], tokens[4:]
    kept, tail = [], []
    seen = set()
    public = 0
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok.startswith((":", "^")) and i + 1 < len(rest):
            name, sep, mask = rest[i + 1].partition(":")
            if not NOISE_SYMBOL.match(name):
                name = base_symbol(name)
                if (tok, name) not in seen:
                    seen.add((tok, name))
                    kept += [tok, name + sep + mask]
                    if tok.startswith(":") and not tok.endswith("@"):
                        public += 1
            i += 2
        else:
            tail.append(tok)
            i += 1
    if not public:
        return None
    defined = sum(1 for k in range(0, len(head[0]), 2) if head[0][k] != ".")
    defined += sum(1 for t in tail for k in range(0, len(t), 2) if t[k] != ".")
    if defined < MIN_DEFINED_BYTES:
        return None
    return " ".join(head + kept + tail)


def pattern_names(line):
    """Public names of a pattern line, in order."""
    tokens = line.split(" ")
    return [tokens[i + 1] for i in range(4, len(tokens) - 1)
            if tokens[i].startswith(":") and not tokens[i].endswith("@")]


def _refs(tokens):
    return tuple(f"{tokens[i]} {tokens[i + 1]}" for i in range(len(tokens) - 1)
                 if tokens[i].startswith("^"))


def collision_key(name, pattern, crc_len, crc, tokens):
    """
    What sigmake shows of a module in its .exc file: first name, leading
    pattern, CRC and references. Versions of a function that differ only
    past that still share a key.
    """
    return (name, pattern, crc_len, crc, _refs(tokens))


def pattern_keys(line):
    t = line.split(" ")
    return [collision_key(n, t[0], t[1], t[2], t[4:]) for n in pattern_names(line)]


def exc_key(name, exc_pattern):
    t = exc_pattern.split(" ")
    return collision_key(name, t[2], t[0], t[1], t[3:])


def make_patterns(flair, libs, pat_dir):
    pats = []
    for lib in libs:
        pat = Path(pat_dir) / f"{lib.parent.name}_{lib.name}.pat"
        r = run_tool([flair_tool(flair, "pelf"), str(lib), str(pat)])
        if r.returncode != 0 or not pat.is_file():
            log(f"pelf failed on {lib.name}: {(r.stdout + r.stderr).strip()[-200:]}")
            continue
        lines = pat.read_text(encoding="latin-1").splitlines()
        out = []
        for ln in lines:
            if ln == "---":
                break
            ln = filter_pattern_line(ln)
            if ln is not None:
                out.append(ln)
        if not out:
            continue
        pat.write_text("\n".join(out + ["---"]) + "\n", encoding="latin-1")
        pats.append(pat)
    return pats


def alias_base(name):
    """
    ARMCC exports C runtime entry points under several spellings: __ARM_x and
    __x, __softfp_x and x, or x, _x and the printf/scanf feature levels
    __0x, __1x, __2x and __c89x. C++ constructors and destructors come as
    complete and base object variants (C1/C2, D1/D2) with identical code, and
    SDK versions move functions in and out of the CTR namespace
    (nn::os::GetAppMemorySize, nn::os::CTR::GetAppMemorySize).
    """
    if name.startswith("_Z"):
        name = re.sub(r"(?<=[A-Za-z_])([CD])[0-2]E", r"\1E", name)
        return re.sub(r"(?<!\d)3CTR(?=\d)", "", name)
    return re.sub(r"^(__ARM_|__softfp_|__\d|__c89|_+)", "", name)


def mangled_path(name):
    """Identifiers of a plain Itanium nested name, or None for anything else."""
    m = re.match(r"_ZN[KVr]*", name)
    if not m:
        return None
    pos, parts = m.end(), []
    while pos < len(name) and name[pos].isdigit():
        n = re.match(r"\d+", name[pos:]).group()
        pos += len(n)
        parts.append(name[pos:pos + int(n)])
        pos += int(n)
    return parts if pos < len(name) and name[pos] == "E" and parts else None


def canonical_name(names, counts=None):
    """
    The name to keep when every candidate is one function: aliases as above,
    or a C++ method next to the C API wrapper the SDK builds from it
    (nndbgPanic for nn::dbg::Panic), where the mangled name is kept for its
    types. Among aliases the one most library versions use wins, then the
    shortest. None when the names are different functions.
    """
    counts = counts or {}
    names = set(names)
    mangled = {n for n in names if n.startswith("_Z")}
    plain = names - mangled
    if mangled and plain:
        if len({alias_base(n) for n in mangled}) != 1:
            return None
        # The C names leave out the CTR platform namespace.
        paths = [p for p in map(mangled_path, mangled) if p]
        flat = {"".join(p) for p in paths} | {"".join(x for x in p if x != "CTR") for p in paths}
        if not flat or not all(n in flat for n in plain):
            return None
        names = mangled
    elif len({alias_base(n) for n in names}) != 1:
        return None
    return min(names, key=lambda n: (-counts.get(n, 0), len(n), n))


def read_collisions(exc_path):
    """
    Parse sigmake's .exc file into groups of [marker, name, pattern] rows,
    where marker is the selection prefix sigmake may already have set.
    """
    groups, group = [], []
    for ln in Path(exc_path).read_text(encoding="latin-1").splitlines():
        if ln.startswith(";"):
            continue
        if not ln.strip():
            if group:
                groups.append(group)
                group = []
            continue
        name, _, pattern = ln.partition("\t")
        name = name.rstrip()
        marker = name[0] if name[:1] in "+-^" else ""
        group.append([marker, name[len(marker):], pattern])
    if group:
        groups.append(group)
    return groups


def collision_group_key(group):
    return tuple(sorted((name, pattern) for _, name, pattern in group))


def resolve_collisions(exc_path, pattern_lines, failed):
    """
    Settle sigmake's collision groups. Rows sigmake already selected (told
    apart by their references) stay selected. Among the rest, one routine
    under several names (an identical function from other library builds,
    or ARMCC aliases) is selected under its plainest name.

    sigmake lists a group again, in the .exc it extends, when a selection
    in it cannot be built after all; such groups go into failed and lose
    every selection from then on.

    Returns the pattern lines of the genuinely ambiguous groups, which
    sigmake keeps as nameless modules for the loader to settle.
    """
    ambiguous = set()
    groups, seen = [], set()
    for group in read_collisions(exc_path):
        key = collision_group_key(group)
        if key in seen:
            failed.add(key)
            continue
        seen.add(key)
        groups.append(group)
    for group in groups:
        if collision_group_key(group) in failed:
            for row in group:
                row[0] = ""
            open_rows = group
        else:
            open_rows = [row for row in group if not row[0]]
            if not open_rows:
                continue
            best = canonical_name({row[1] for row in open_rows},
                                  Counter(row[1] for row in open_rows))
            if best:
                next(row for row in open_rows if row[1] == best)[0] = "+"
                continue
        for row in open_rows:
            ambiguous |= pattern_lines.get(exc_key(row[1], row[2]), set())
    with open(exc_path, "w", encoding="latin-1", newline="\n") as out:
        for group in groups:
            for marker, name, pattern in group:
                out.write(f"{marker}{name}\t{pattern}\n")
            out.write("\n")
    return ambiguous


def make_sig(flair, pats, sig_path, title, pat_versions=None):
    """
    Run sigmake, resolving collisions from its .exc file between passes.
    sigmake surfaces further collision groups once earlier ones are settled,
    many times over when several library versions are merged, so this
    repeats until the signature appears or a pass reports nothing new.

    Patterns of the ambiguous modules kept in the signature are written to a
    .candidates file beside it, so the loader can list what such a match
    could be. pat_versions maps pattern files to the library version they
    come from; with more than one version, the candidates carry the versions
    holding them, and a .versions file lists every function whose code
    differs between versions, from which the loader tells which version a
    program links.
    """
    sig_path = Path(sig_path)
    exc = sig_path.with_suffix(".exc")
    err = sig_path.with_suffix(".err")
    candidates = sig_path.with_suffix(".candidates")
    versions_index = sig_path.with_suffix(".versions")
    for stale in (exc, sig_path, candidates, versions_index):
        if stale.exists():
            stale.unlink()
    lines, line_versions = [], {}
    for pat in pats:
        version = (pat_versions or {}).get(str(pat))
        for ln in Path(pat).read_text(encoding="latin-1").splitlines():
            if ln == "---":
                continue
            lines.append(ln)
            if version is not None:
                line_versions.setdefault(ln, set()).add(version)
    multi_version = len({v for vs in line_versions.values() for v in vs}) > 1

    def tagged(ln):
        if not multi_version or ln not in line_versions:
            return ln
        return ln + "\t" + "|".join(sorted(line_versions[ln]))

    by_key = {}
    for ln in lines:
        for key in pattern_keys(ln):
            by_key.setdefault(key, set()).add(ln)
    # One merged pattern file keeps the command line short; hundreds of
    # library paths overflow the Windows limit.
    merged = sig_path.with_suffix(".pat")
    # Processor id 13 is ARM; without it sigmake tags the file as x86.
    args = [flair_tool(flair, "sigmake"), "-p13", f"-n{title}", str(merged), str(sig_path)]
    merged.write_text("\n".join(lines + ["---"]) + "\n", encoding="latin-1", newline="\n")
    ambiguous, failed = set(), set()
    settled = None
    while True:
        r = run_tool(args)
        if sig_path.is_file():
            break
        if not exc.exists():
            sys.exit(f"sigmake failed: {r.stdout}{r.stderr}")
        if exc.read_bytes() == settled:
            sys.exit(f"sigmake reports collisions that cannot be settled: {r.stdout}{r.stderr}")
        ambiguous |= resolve_collisions(exc, by_key, failed)
        settled = exc.read_bytes()
    if ambiguous:
        candidates.write_text("\n".join([tagged(ln) for ln in sorted(ambiguous)] + ["---"]) + "\n",
                              encoding="latin-1", newline="\n")
    log(f"{sig_path.name}: {len(ambiguous)} ambiguous patterns kept nameless")
    if multi_version:
        variants = {}
        for ln in line_versions:
            for name in pattern_names(ln):
                variants.setdefault(name, set()).add(ln)
        changed = sorted({ln for lns in variants.values() if len(lns) > 1 for ln in lns})
        versions_index.write_text("\n".join([tagged(ln) for ln in changed] + ["---"]) + "\n",
                                  encoding="latin-1", newline="\n")
        log(f"{sig_path.name}: {len(changed)} version-specific patterns indexed")
    for f in (exc, err, merged):
        if f.exists():
            f.unlink()


# sigmake rejects longer library names.
MAX_TITLE = 100


def package_title(product, versions):
    title = f"{product} " + ", ".join(versions)
    if len(title) <= MAX_TITLE:
        return title
    # Most versions end in their build date, which orders them.
    dated = sorted((re.findall(r"\d{8}", v)[-1], v) for v in versions if re.search(r"\d{8}", v))
    if dated:
        title = f"{product} {dated[0][1]} to {dated[-1][1]} ({len(versions)} versions)"
        if len(title) <= MAX_TITLE:
            return title
    return f"{product} ({len(versions)} versions)"


def build_family_sig(flair, name, entries, work, out_dir):
    """Patterns from every (version, libraries) entry of one family, merged into ctr_<name>.sig."""
    product = FAMILY_PRODUCTS.get(name, name)
    pats, versions, pat_versions = [], [], {}
    for i, (version, libs) in enumerate(entries):
        versions.append(version)
        if not libs:
            log(f"{product} {version}: no CTR-TS.Process.MPCore release libraries found")
            continue
        log(f"{product} {version}: {len(libs)} libraries")
        pat_dir = work / f"{name}-{i}" / "pat"
        pat_dir.mkdir(parents=True, exist_ok=True)
        new = make_patterns(flair, libs, pat_dir)
        pat_versions.update((str(pat), version) for pat in new)
        pats += new
    if not pats:
        log(f"{product}: nothing to build")
        return
    out = Path(out_dir) / f"ctr_{name}.sig"
    make_sig(flair, pats, out, package_title(product, sorted(set(versions), key=versions.index)),
             pat_versions)
    log(f"wrote {out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sdk", action="append", default=[], help="CTR-SDK zip or directory")
    ap.add_argument("--armcc", action="append", default=[], help="ARMCC zip, MSI or directory")
    ap.add_argument("--lib", nargs=2, action="append", default=[], metavar=("NAME", "PACKAGE"),
                    help="middleware package for ctr_NAME.sig")
    ap.add_argument("--bundle", action="append", default=[], metavar="PACKAGE",
                    help="archive or directory of several packages, sorted by product")
    ap.add_argument("--out-dir", default=default_sig_dir())
    ap.add_argument("--flair", help="directory holding pelf and sigmake")
    ap.add_argument("--sevenzip", help="7-Zip executable, for ARMCC MSI packages")
    ap.add_argument("--work-dir", help="keep intermediate files here instead of a temp dir")
    args = ap.parse_args()
    if not (args.sdk or args.armcc or args.lib or args.bundle):
        ap.error("give at least one --sdk, --armcc, --lib or --bundle")
    for name, _ in args.lib:
        if not LIB_NAME.fullmatch(name) or name.lower() == "armcc":
            ap.error(f"--lib name {name!r}: use letters, digits and _, other than armcc")
    flair = find_flair(args.flair)
    os.makedirs(args.out_dir, exist_ok=True)

    work_ctx = tempfile.TemporaryDirectory(prefix="ctr_sigs_") if not args.work_dir else None
    work = Path(args.work_dir or work_ctx.name)
    work.mkdir(parents=True, exist_ok=True)
    try:
        walker = PackageWalker(work, find_sevenzip(args.sevenzip))
        families = {}
        n = 0

        def lib_dir():
            nonlocal n
            n += 1
            return work / f"pkg{n}"

        for pkg in args.sdk:
            families.setdefault("sdk", []).append(
                (sdk_version(pkg), sdk_libraries(walker, pkg, lib_dir())))
        for name, pkg in args.lib:
            families.setdefault(name.lower(), []).append(
                (package_version(pkg), package_libraries(walker, pkg, lib_dir())))
        for pkg in args.bundle:
            for family, packages in bundle_libraries(walker, pkg, lib_dir()).items():
                for package, libs in packages.items():
                    version = sdk_version(package) if family == "sdk" else package_version(package)
                    families.setdefault(family, []).append((version, libs))
        for name, entries in families.items():
            build_family_sig(flair, name, entries, work, args.out_dir)
        if args.armcc:
            pats, armcc_versions = [], {}
            for i, pkg in enumerate(args.armcc):
                root = armcc_lib_root(pkg, work / f"armcc{i}", find_sevenzip(args.sevenzip))
                libs = armcc_libraries(root)
                log(f"ARMCC {Path(pkg).name}: {len(libs)} libraries")
                pat_dir = work / f"armcc{i}" / "pat"
                pat_dir.mkdir(parents=True, exist_ok=True)
                new = make_patterns(flair, libs, pat_dir)
                armcc_versions.update((str(pat), package_version(pkg)) for pat in new)
                pats += new
            out = Path(args.out_dir) / "ctr_armcc.sig"
            make_sig(flair, pats, out, "ARMCC runtime for CTR", armcc_versions)
            log(f"wrote {out}")
    finally:
        if work_ctx is not None:
            work_ctx.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
