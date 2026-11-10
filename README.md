# ctrldr

IDA 9.x loader for Nintendo 3DS (CTR) executables, aimed at getting a usable
database from a bare `code.bin` with no manual setup.

## Inputs

- ExeFS `.code` / `code.bin`, BLZ-compressed or not
- ExeFS images (the `.code` inside is used)
- 3DSX homebrew (relocations applied) and 3GX plugins

An ExHeader is used when one sits in the same directory as the input
(`exheader.bin`, `extheader.bin`, `exh.bin`, `<name>.exheader`). Without one,
the code set is recovered from the image:

- `.bss` from the ZI clear loop that crt0's `nninitRegion` runs (or the
  libctru crt0 equivalent).
- The end of `.text` from ARM/Thumb code density, call targets and the
  ARMCC `.init_array` tail.
- The `.rodata`/`.data` split from page-boundary zero padding, bounded above
  by the lowest address code writes through and below by vtables (ARMCC keeps
  them in `.rodata`).

FIRM system modules (sm, fs, pm, loader, pxi) pack their code set without page
alignment and need an ExHeader.

## What a load sets up

- Segments `.text`, `.rodata`, `.data`, `.bss`, plus the kernel config page,
  shared page (typed) and the VRAM/DSP mappings (from the ExHeader when
  present).
- ARM processor, GNU EABI compiler model, Itanium demangling, `armv12` TIL and
  the 3DS kernel types in `loaders/ctrldr/ctr_types.h`.
- crt0 names (`__ctr_start`, `nninitRegion`, `nnMain`, ...), entry point and
  `main`, functions seeded from call targets.
- FLIRT signatures `ctr_*.sig` from `sig/arm`, applied automatically. A
  match on a module several library functions share (`unknown_libname`) gets
  the possible names from `ctr_*.candidates` as a comment, and is renamed
  when the library functions calling, called by or next to it share a
  namespace with exactly one of them.
- After auto-analysis: every SVC commented, small SVC wrappers named, IPC
  request functions commented with their command header and named
  `IpcRequest_<header>`, and ARMCC `__ARM_switch8` byte tables turned into
  switches.
- With Hex-Rays: SVCs decompile as typed calls with their kernel register ABI,
  the CP15 TLS read becomes `getThreadLocalStorage()` (a `ThreadLocalStorage *`,
  so command buffer writes read as `tls->commandBuffer[n]`), CP15 barriers
  become `__dsb`/`__dmb`/`__isb`, and FPSCR moves become
  `__set_FPSCR`/`__get_FPSCR`.
- ExHeader metadata (title, program ID, stack, dependencies, services, kernel
  capabilities) as comments at the top of `.text`.

## Install

Copy, or symlink, into the IDA user directory (`$IDAUSR`, otherwise
`%APPDATA%\Hex-Rays\IDA Pro` on Windows and `~/.idapro` elsewhere):

| From                                          | To                    |
| --------------------------------------------- | --------------------- |
| `loaders/ctrldr-ida.py` and `loaders/ctrldr/` | `<user dir>/loaders/` |
| `plugins/ctrldr_hexrays.py`                   | `<user dir>/plugins/` |
| generated `ctr_*.sig`, `ctr_*.candidates`     | `<user dir>/sig/arm/` |

## Signatures

`tools/build_ctr_sigs.py` builds the FLIRT signatures with IDA's FLAIR tools
(`pelf`, `sigmake` from `<IDA>/tools/flair`), so they are not shipped here:

```
python tools/build_ctr_sigs.py \
    --sdk   "Nintendo 3DS - CTR-SDK (World) (11_6_1-20180622).zip" \
    --sdk   CTR_SDK-SNAPSHOT-20110930-1405-complete.tgz \
    --armcc "Nintendo 3DS - ARM Compiler - ARMCC for Nintendo (World) (4_1_nintendo-b1454-20150227).zip"
```

- `--sdk` accepts the No-Intro zip, the inner `CTR_SDK-*.zip`, a tarball or
  an extracted `CTR_SDK` directory; the MPCore release libraries and crt0 are
  used.
- `--armcc` accepts the No-Intro zip, its inner zip or MSI, or an extracted
  directory holding `lib/armlib`. MSIs are unpacked with 7-Zip (`7z`/`7zz` on
  `PATH`, the default Windows install, or `--sevenzip`).
- Both options repeat. Several SDK versions widen coverage; a function that is
  identical across versions keeps its name.
- Identical code under different names is resolved where the names are one
  function: ARMCC variant tags (`__aeabi_uidiv$div0`) and alias spellings
  (`__ARM_x`, `__0x`, `__c89x`, ...), C++ constructor/destructor variants,
  and the SDK's C wrappers of C++ methods (`nndbgPanic`). Otherwise short
  functions are dropped, since game accessors share their bytes, and longer
  ones stay as nameless modules with their names listed in
  `ctr_*.candidates`.
- `--flair` and `--out-dir` override the FLAIR and output locations, which
  default to `$IDADIR` or the usual install paths and to the user `sig/arm`.

## Checking layouts outside IDA

```
cd loaders && python -m ctrldr path/to/code.bin [--exheader path] [--no-exheader]
```
