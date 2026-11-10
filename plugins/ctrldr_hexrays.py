"""
Activates the ctrldr Hex-Rays filters (typed SVCs, TLS and barrier
intrinsics) in databases created by the ctrldr loader. The filters live in
the ctrldr package installed beside the loader.
"""

import os
import sys

import ida_diskio
import ida_idaapi
import ida_netnode


def _import_ctrldr():
    for base in (ida_diskio.get_user_idadir(), ida_diskio.idadir("")):
        path = os.path.join(base, "loaders")
        if os.path.isdir(os.path.join(path, "ctrldr")) and path not in sys.path:
            sys.path.insert(0, path)
    from ctrldr import consts, hexrays
    return consts, hexrays


class CtrldrHexraysPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    comment = "Hex-Rays filters for 3DS executables loaded by ctrldr"
    help = ""
    wanted_name = "ctrldr Hex-Rays filters"
    wanted_hotkey = ""

    def init(self):
        try:
            consts, hexrays = _import_ctrldr()
        except ImportError:
            return ida_idaapi.PLUGIN_SKIP
        if ida_netnode.netnode(consts.NETNODE_NAME).index() == ida_netnode.BADNODE:
            return ida_idaapi.PLUGIN_SKIP
        if not hexrays.install():
            return ida_idaapi.PLUGIN_SKIP
        self.hexrays = hexrays
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        self.hexrays.uninstall()


def PLUGIN_ENTRY():
    return CtrldrHexraysPlugin()
