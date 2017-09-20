# -*- coding: utf-8 -*-

"""
    pydbg utility
"""

import xrklog
import xrkwin32
import xrkwin32def
# import ctypes
from ctypes.wintypes import HANDLE, byref, sizeof


# ---------------------------------------------------------------------------
# util
# ---------------------------------------------------------------------------


def acquire_debug_priviledges():
    """
        acquire debug priviledge for current process

        @return: BOOL: is operation success
    """
    h_token = HANDLE()
    # TOKEN_ADJUST_PRIVILEGES        = 0x00000020
    if xrkwin32.OpenProcessToken(xrkwin32.GetCurrentProcess(), 0x00000020, byref(h_token)):

        luid = xrkwin32def.LUID()
        if xrkwin32.LookupPrivilegeValueW("", "seDebugPrivilege", byref(luid)):

            priv = xrkwin32def.TOKEN_PRIVILEGES()
            priv.PrivilegeCount = 1
            priv.Privileges[0].Luid = luid
            # SE_PRIVILEGE_ENABLED           = 0x00000002
            priv.Privileges[0].Attributes = 0x00000002
            if xrkwin32.AdjustTokenPrivileges(h_token, False, byref(priv), sizeof(priv), None, None):

                return True
    return False


def get_ps_list():
    """
        get process list on pc

        @return: LIST: a list of TUPLE, like: [(pid_1, exe_path_1), (pid_2, exe_path_2), ...]
    """
    # use python module: psutil
    pass


def get_tid_list(pid):
    """
        get thread list of specifed process by pid

        @param: pid: pid of specified process

        @return: LIST: a list of tid
                 None
    """
    # TH32CS_SNAPTHREAD   = 0x00000004
    snapshot = xrkwin32.CreateToolhelp32Snapshot(0x00000004, pid)
    if snapshot:

        entry = xrkwin32def.THREADENTRY32()
        entry.dwSize = sizeof(entry)
        tmp = xrkwin32.Thread32First(snapshot, byref(entry))
        if tmp:
            ret = []
            while tmp:
                if entry.th32OwnerProcessID == pid:
                    ret.append(entry.th32ThreadID)
                tmp = xrkwin32.Thread32Next(snapshot, byref(entry))

            xrkwin32.CloseHandle(snapshot)
            return ret
        else:
            xrklog.error("get tid list of pid %d, get first thread fail" % pid)

        xrkwin32.CloseHandle(snapshot)
        return None

    xrklog.error("get tid list of pid %d, create snapshot fail" % pid)
    return None
