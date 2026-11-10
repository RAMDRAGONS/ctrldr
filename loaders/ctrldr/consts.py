"""Fixed 3DS facts shared by the layout code and the IDA loader."""

CONFIG_MEM = 0x1FF80000
SHARED_PAGE = 0x1FF81000

# fs, loader, pm, sm and pxi are started by the kernel from FIRM. Their code
# sets are packed back to back in .code rather than page aligned.
FIRM_MODULE_IDS = {0x1002, 0x1102, 0x1202, 0x1302, 0x1402}

LOADER_NAME = "ctrldr"
NETNODE_NAME = "$ ctrldr"
FMT_PREFIX = "Nintendo 3DS executable"

SYSMODULE_NAMES = {
    0x1002: "sm", 0x1102: "fs", 0x1202: "pm", 0x1302: "loader",
    0x1402: "pxi", 0x1502: "am", 0x1602: "camera", 0x1702: "cfg",
    0x1802: "codec", 0x1A02: "dsp", 0x1B02: "gpio", 0x1C02: "gsp",
    0x1D02: "hid", 0x1E02: "i2c", 0x1F02: "mcu", 0x2002: "mic",
    0x2102: "pdn", 0x2202: "ptm", 0x2302: "spi", 0x2402: "ac",
    0x2602: "cecd", 0x2702: "csnd", 0x2802: "dlp", 0x2902: "http",
    0x2A02: "mp", 0x2B02: "ndm", 0x2C02: "nim", 0x2D02: "nwm",
    0x2E02: "socket", 0x2F02: "ssl", 0x3102: "friends", 0x3202: "ir",
    0x3302: "boss", 0x3402: "news", 0x3702: "ro", 0x3802: "act",
    0x4002: "nfc", 0x4102: "mvd", 0x4202: "qtm", 0x8002: "ns",
}

# Mappings every application ExHeader produced by the SDK requests (DSP shared
# memory windows and VRAM). Used when no ExHeader is available.
DEFAULT_APP_MAPPINGS = [
    (0x1FF50000, 0x1FF58000, False),
    (0x1FF70000, 0x1FF78000, False),
    (0x1F000000, 0x1F600000, True),
]

# crt0 __ctr_start calls these in order, unchanged from the 2011-09 SDK
# snapshot through 11.6, then tail-branches to nn::svc::ExitProcess. Earlier
# SDKs make one more call; for those only the first and last are named.
CTR_START_CALLS = [
    "nninitRegion", "nninitLocale", "nninitSystem", "nninitStartUp",
    "__cpp_initialize__aeabi_", "nninitCallStaticInitializers",
    "nninitSetup", "nnMain",
]
CTR_START_EXIT = "_ZN2nn3svc11ExitProcessEv"
