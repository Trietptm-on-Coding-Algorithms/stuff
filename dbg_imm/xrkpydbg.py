# -*- coding: utf-8 -*-

"""
    debugger
"""

import xrklog
import xrkwin32
import xrkwin32def
from ctypes.wintypes import POINTER


class xrkpydbg:
    def __init__(self):
        """
            init xrkpydbg
        """
        self.bp_int3_list = []
        self.bp_mm_list = []
        self.bp_hw_list = []
        sys_info = xrkwin32def.SYSTEM_INFO()
        xrkwin32.GetSystemInfo(POINTER(sys_info))
        self.page_size = sys_info.dwPageSize

        self.cbks = []

        xrklog.info("init xrkpydbg...")

    # ---------------------------------------------------------------------------
    # xx

    def attach(self, pid):
        """
            attach to active process by pid

            @param: pid: INT, pid of sepcified process
        """
        xrklog.info("attach to pid: %d" % pid)

        self.pid = pid

        xrkwin32.acquire_debug_priviledges()
        self.h_proc = xrkwin32.OpenProcess(xrkwin32def.PROCESS_ALL_ACCESS, False, pid)

        if not xrkwin32.DebugActiveProcess(pid):

            xrkwin32.DebugSetProcessKillOnExit(False)

            threads = xrkwin32.get_threads_list(pid)
            for thread in threads:
                pass
        else:
            xrklog.error("DebugActiveProcess fail")

    def detach(self):
        pass

    def load(self, exe_path, cmd_line):
        pass

    def exit(self):
        pass

    def run(self):
        pass

    def dbgloop(self):
        """
        """
        pass

    # ---------------------------------------------------------------------------
    # set xx

    def set_cbk(self):
        pass

    def set_regs(self):
        pass

    # ---------------------------------------------------------------------------
    # get

    def get_sysdll(self):
        pass

    def get_sysdll_by_addr(self, addr):
        pass

    def get_md_by_addr(self, addr):
        pass

    def get_md_list(self):
        pass

    def get_proc_list(self):
        pass

    def get_addr_sysdll(self):
        pass

    def get_addr_pe(self):
        pass

    def get_func_arg(self):
        pass

    def get_ctx(self):
        pass

    def get_ctx_list(self):
        pass

    def get_instruction(self):
        pass

    # ---------------------------------------------------------------------------
    # bp - int3

    def bp_int3_add(self):
        pass

    def bp_int3_del(self):
        pass

    def bp_int3_del_all(self):
        pass

    def bp_int3_is_mine(self):
        pass

    # ---------------------------------------------------------------------------
    # bp - hw

    def bp_hw_add(self):
        pass

    def bp_hw_del(self):
        pass

    def bp_hw_del_all(self):
        pass

    def bp_hw_is_mine(self):
        pass

    # ---------------------------------------------------------------------------
    # bp - mm

    def bp_mm_add(self):
        pass

    def bp_mm_del(self):
        pass

    def bp_mm_del_all(self):
        pass

    def bp_mm_is_mine(self):
        pass

    # ---------------------------------------------------------------------------
    # thread

    def get_threads_list(self):
        """
            get threads list

            @param: LIST: list of TID
        """
        pass

    def thread_suspend(self):
        pass

    def thread_suspend_all(self):
        pass

    def thread_resume(self):
        pass

    def thread_resume_all(self):
        pass

    def get_thread_ctx(self):
        pass

    def set_thread_ctx(self):
        pass

    # ---------------------------------------------------------------------------
    # stack

    def get_stack_range(self):
        pass

    def is_addr_on_stack(self):
        pass

    def stack_unwind(self):
        pass

    # ---------------------------------------------------------------------------
    # seh

    def seh_unwind(self):
        pass

    # ---------------------------------------------------------------------------
    # pt

    def pt_regs(self):
        pass

    def pt_guarded_pages(self):
        pass

    # ---------------------------------------------------------------------------
    # disasm

    def disasm(self):
        pass

    def disasm_around(self):
        pass

    # ---------------------------------------------------------------------------
    # evt - non excep

    def evt_create_proc(self):
        pass

    def evt_create_thread(self):
        pass

    def evt_exit_proc(self):
        pass

    def evt_exit_thread(self):
        pass

    def evt_load_dll(self):
        pass

    def evt_unload_dll(self):
        pass

    # ---------------------------------------------------------------------------
    # evt - excep

    def evt_excep_access_violation(self):
        pass

    def evt_excep_bp_hit(self):
        pass

    def evt_excep_bp_hit_single_step(self):
        pass

    def evt_excep_guard_page(self):
        pass

    def evt_excep_single_step(self):
        pass

    # ---------------------------------------------------------------------------
    # dbg

    def dbg_read(self):
        pass

    def dbg_read_msr(self):
        pass

    def dbg_write(self):
        pass

    def dbg_write_msr(self):
        pass

    def dbg_alloc(self):
        pass

    def dbg_free(self):
        pass

    def dbg_mm_protect(self):
        pass

    def dbg_mm_query(self):
        pass

    # ---------------------------------------------------------------------------
    # dump

    def dump_hex(self):
        pass

    def dump_snapshot(self):
        pass

    # ---------------------------------------------------------------------------
    # misc

    def extract_ascii_str(self, data):
        pass

    def extract_unicode_str(self, data):
        pass

    def extract_printable_str(self):
        pass

    def hide_dbg(self):
        pass

    def flip_endian(self):
        pass

    def flip_endian_dword(self):
        pass

    def page_guard_clear(self):
        pass

    def page_guard_restore(self):
        pass

    def smart_dereference(self):
        pass

    def to_binary(self):
        pass

    def to_decimal(self):
        pass

    # ---------------------------------------------------------------------------
    # END OF XRKPYDBG
    # ---------------------------------------------------------------------------
