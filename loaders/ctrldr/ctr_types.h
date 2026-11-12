// Horizon (3DS ARM11 userland) kernel ABI types used by the SVC prototypes
// and the kernel-mapped pages. Layouts follow the kernel interface, not any
// particular SDK header.

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed char s8;
typedef short s16;
typedef int s32;
typedef long long s64;
typedef u8 bit8;
typedef u16 bit16;
typedef u32 bit32;
typedef u64 bit64;

typedef u32 Handle;
typedef s32 Result;
typedef void (*ThreadFunc)(u32);

enum PseudoHandle : u32
{
  CUR_THREAD_HANDLE = 0xFFFF8000,
  CUR_PROCESS_HANDLE = 0xFFFF8001,
};

enum MemOp : u32
{
  MEMOP_FREE = 1,
  MEMOP_RESERVE = 2,
  MEMOP_ALLOC = 3,
  MEMOP_MAP = 4,
  MEMOP_UNMAP = 5,
  MEMOP_PROT = 6,
  MEMOP_REGION_APP = 0x100,
  MEMOP_REGION_SYSTEM = 0x200,
  MEMOP_REGION_BASE = 0x300,
  MEMOP_LINEAR_FLAG = 0x10000,
};

enum MemPerm : u32
{
  MEMPERM_NONE = 0,
  MEMPERM_READ = 1,
  MEMPERM_WRITE = 2,
  MEMPERM_READWRITE = 3,
  MEMPERM_EXECUTE = 4,
  MEMPERM_READEXECUTE = 5,
  MEMPERM_DONTCARE = 0x10000000,
};

enum MemState : u32
{
  MEMSTATE_FREE = 0,
  MEMSTATE_RESERVED = 1,
  MEMSTATE_IO = 2,
  MEMSTATE_STATIC = 3,
  MEMSTATE_CODE = 4,
  MEMSTATE_PRIVATE = 5,
  MEMSTATE_SHARED = 6,
  MEMSTATE_CONTINUOUS = 7,
  MEMSTATE_ALIASED = 8,
  MEMSTATE_ALIAS = 9,
  MEMSTATE_ALIASCODE = 10,
  MEMSTATE_LOCKED = 11,
};

struct MemInfo
{
  u32 base_addr;
  u32 size;
  MemPerm perm;
  MemState state;
};

struct PageInfo
{
  u32 flags;
};

enum ResetType : u32
{
  RESET_ONESHOT = 0,
  RESET_STICKY = 1,
  RESET_PULSE = 2,
};

enum ArbitrationType : u32
{
  ARBITRATION_SIGNAL = 0,
  ARBITRATION_WAIT_IF_LESS_THAN = 1,
  ARBITRATION_DECREMENT_AND_WAIT_IF_LESS_THAN = 2,
  ARBITRATION_WAIT_IF_LESS_THAN_TIMEOUT = 3,
  ARBITRATION_DECREMENT_AND_WAIT_IF_LESS_THAN_TIMEOUT = 4,
};

enum ResourceLimitType : u32
{
  RESLIMIT_PRIORITY = 0,
  RESLIMIT_COMMIT = 1,
  RESLIMIT_THREAD = 2,
  RESLIMIT_EVENT = 3,
  RESLIMIT_MUTEX = 4,
  RESLIMIT_SEMAPHORE = 5,
  RESLIMIT_TIMER = 6,
  RESLIMIT_SHAREDMEMORY = 7,
  RESLIMIT_ADDRESSARBITER = 8,
  RESLIMIT_CPUTIME = 9,
};

enum UserBreakType : u32
{
  USERBREAK_PANIC = 0,
  USERBREAK_ASSERT = 1,
  USERBREAK_USER = 2,
  USERBREAK_LOAD_RO = 3,
  USERBREAK_UNLOAD_RO = 4,
};

enum PerfCounterOperation : u32
{
  PERFCOUNTEROP_ENABLE = 0,
  PERFCOUNTEROP_DISABLE = 1,
  PERFCOUNTEROP_GET_VALUE = 2,
  PERFCOUNTEROP_SET_VALUE = 3,
  PERFCOUNTEROP_GET_OVERFLOW_FLAGS = 4,
  PERFCOUNTEROP_RESET = 5,
  PERFCOUNTEROP_GET_EVENT = 6,
  PERFCOUNTEROP_SET_EVENT = 7,
  PERFCOUNTEROP_SET_VIRTUAL_COUNTER_ENABLED = 8,
};

enum DebugThreadParameter : u32
{
  DBGTHREAD_PARAMETER_PRIORITY = 0,
  DBGTHREAD_PARAMETER_SCHEDULING_MASK_LOW = 1,
  DBGTHREAD_PARAMETER_CPU_IDEAL = 2,
  DBGTHREAD_PARAMETER_CPU_CREATOR = 3,
};

struct DmaDeviceConfig
{
  s8 deviceId;
  s8 allowedAlignments;
  s16 burstSize;
  s16 transferSize;
  s16 burstStride;
  s16 transferStride;
};

struct DmaConfig
{
  s8 channelId;
  s8 endianSwapSize;
  u8 flags;
  u8 padding;
  DmaDeviceConfig srcCfg;
  DmaDeviceConfig dstCfg;
};

struct CpuRegisters
{
  u32 r[13];
  u32 sp;
  u32 lr;
  u32 pc;
  u32 cpsr;
};

struct FpuRegisters
{
  float s[32];
  u32 fpscr;
  u32 fpexc;
};

struct ThreadContext
{
  CpuRegisters cpu_registers;
  FpuRegisters fpu_registers;
};

struct CodeSetHeader
{
  u8 name[8];
  u16 version;
  u16 padding[3];
  u32 text_addr;
  u32 text_size;
  u32 ro_addr;
  u32 ro_size;
  u32 rw_addr;
  u32 rw_size;
  u32 text_size_total;
  u32 ro_size_total;
  u32 rw_size_total;
  u32 padding2;
  u64 program_id;
};

// Multi-register SVC results: r0 is the Result, the rest follow in order.
struct SvcResult8
{
  Result result;
  u8 value;
};

struct SvcResult32
{
  Result result;
  u32 value;
};

#pragma pack(push, 4)
struct SvcResult64
{
  Result result;
  s64 value;
};
#pragma pack(pop)

struct SvcResultHandle
{
  Result result;
  Handle handle;
};

struct SvcResultHandlePair
{
  Result result;
  Handle handle1;
  Handle handle2;
};

struct SvcResultQueryMemory
{
  Result result;
  MemInfo mem_info;
  PageInfo page_info;
};

#pragma pack(push, 4)
struct SvcResultDebugThreadParam
{
  Result result;
  s64 unused;
  u32 out;
};
#pragma pack(pop)

struct IpcStaticBuffer
{
  u32 descriptor;
  void *pointer;
};

// Thread local storage, read with "mrc p15, 0, rN, c13, c0, 3". The command
// buffer carries IPC requests and replies for svcSendSyncRequest.
struct ThreadLocalStorage
{
  u32 userStorage[0x10];
  u32 exceptionHandler;
  u32 exceptionStackTop;
  u32 exceptionContext;
  u32 reserved[0xD];
  u32 commandBuffer[0x40];
  IpcStaticBuffer staticBuffers[0x10];
};

struct CtrDateTime
{
  u64 msSince1900;
  u64 systemTick;
  u32 unk10;
  u32 unk14;
  u32 unk18;
  u32 unk1C;
};

#pragma pack(push, 4)
// Kernel configuration page at 0x1FF80000.
struct CtrConfigMem
{
  u32 kernelUnk;
  u8 kernelVersionRevision;
  u8 kernelVersionMinor;
  u8 kernelVersionMajor;
  u8 pad07;
  u32 updateFlag;
  u64 nsTid;
  u32 sysCoreVer;
  u8 envInfo;
  u8 unitInfo;
  u8 bootEnv;
  u8 pad1B;
  u32 kernelCtrSdkVersion;
  u8 pad20[0x10];
  u32 appMemType;
  u8 pad34[0xC];
  u32 appMemAlloc;
  u32 sysMemAlloc;
  u32 baseMemAlloc;
  u8 pad4C[0x14];
  u32 firmUnk;
  u8 firmVersionRevision;
  u8 firmVersionMinor;
  u8 firmVersionMajor;
  u8 pad67;
  u32 firmSysCoreVer;
  u32 firmCtrSdkVersion;
  u8 pad70[0xF90];
};
#pragma pack(pop)

// Shared page at 0x1FF81000, written by the kernel and system modules.
struct CtrSharedPage
{
  u32 dateTimeSelector;
  u8 runningHw;
  u8 mcuHwInfo;
  u8 pad06[0x1A];
  CtrDateTime dateTime0;
  CtrDateTime dateTime1;
  u8 wifiMacAddr[6];
  s8 wifiLinkLevel;
  u8 wifiUnk;
  u8 pad68[0x18];
  float slider3d;
  u8 led3d;
  u8 ledBattery;
  u8 unk86;
  u8 pad87[0x19];
  u64 homeMenuTid;
  u8 padA8[0x18];
  u8 headsetConnected;
  u8 padC1[0xF3F];
};

// nn::ro modules (CRO) and the static module description (CRS). Everything
// the tables point at is a segment offset: (offset << 4) | segment index.
struct CroHeader
{
  u32 magic;                      // "CRO0"
  u32 nameOffset;
  u32 next;                       // loaded module list, filled in by nn::ro
  u32 previous;
  u32 fileSize;
  u32 bssSize;
  u32 fixedSize;
  u32 unk1C;
  u32 controlObject;              // segment offset of nnroControlObject_
  u32 onLoad;                     // segment offset of nnroProlog
  u32 onExit;                     // segment offset of nnroEpilog
  u32 onUnresolved;               // segment offset of nnroUnresolved
  u32 codeOffset;
  u32 codeSize;
  u32 dataOffset;
  u32 dataSize;
  u32 moduleNameOffset;
  u32 moduleNameSize;
  u32 segmentTableOffset;
  u32 segmentCount;
  u32 namedExportTableOffset;
  u32 namedExportCount;
  u32 indexedExportTableOffset;
  u32 indexedExportCount;
  u32 exportStringsOffset;
  u32 exportStringsSize;
  u32 exportTreeOffset;
  u32 exportTreeCount;
  u32 importModuleTableOffset;
  u32 importModuleCount;
  u32 importPatchesOffset;
  u32 importPatchCount;
  u32 namedImportTableOffset;
  u32 namedImportCount;
  u32 indexedImportTableOffset;
  u32 indexedImportCount;
  u32 anonymousImportTableOffset;
  u32 anonymousImportCount;
  u32 importStringsOffset;
  u32 importStringsSize;
  u32 unk8Offset;
  u32 unk8Count;
  u32 relocationPatchesOffset;
  u32 relocationPatchCount;
  u32 unkPatchesOffset;
  u32 unkPatchCount;
};

struct CroSegment
{
  u32 offset;                     // file offset; a CRS holds load addresses
  u32 size;
  u32 id;                         // 0 .text, 1 .rodata, 2 .data, 3 .bss
};

struct CroNamedExport
{
  u32 nameOffset;
  u32 segmentOffset;
};

struct CroImportModule
{
  u32 nameOffset;
  u32 indexedImportsOffset;
  u32 indexedImportCount;
  u32 anonymousImportsOffset;
  u32 anonymousImportCount;
};

struct CroNamedImport
{
  u32 nameOffset;
  u32 patchesOffset;              // first entry of this import's patch list
};

struct CroIndexedImport
{
  u32 exportIndex;
  u32 patchesOffset;
};

struct CroAnonymousImport
{
  u32 segmentOffset;              // in the exporting module
  u32 patchesOffset;
};

struct CroPatch
{
  u32 segmentOffset;              // word to patch
  u8 type;                        // R_ARM_ABS32 (2), R_ARM_REL32 (3), ...
  u8 segmentOrLast;               // relocations: base segment; imports: last entry of the list
  u8 applied;
  u8 unk7;
  u32 addend;
};
