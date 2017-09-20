# -*- coding: utf-8 -*-

"""
    cfg defines
"""

import os
import sys
import inspect
import traceback

try:
    pass
except:
    this_path = os.path.split(os.path.realpath(inspect.stack()[-1][1]))[0]
    sys.path.append(this_path)
    try:
        pass
    except Exception, e:
        import immlib as dbglib
        dbg = dbglib.Debugger()
        dbg.log("xrkmon cfg def import error: %s" % e, highlight=1)
        error = traceback.format_exc()
        while len(error) > 200:
            tmp = error[:200]
            dbg.log("  %s" % tmp, highlight=1)
            error = error[200:]
        dbg.log("  %s" % error, highlight=1)

        assert False


def __format_list_as_param(list_):
    """
        format a list of apis to 1 string, splited by ","

        @param: list_ : LIST : a list of api names

        @return: STRING :
    """
    assert len(list_) != 0

    if len(list_) == 1:
        return list_[0]

    else:
        return ",".join('%s' % i for i in list_)


# ---------------------------------------------------------------------------
# config - ws2_32
# ---------------------------------------------------------------------------


#
# connect redirect
#
v_xxx_connect_tar_ip = "192.168.1.174"
v_cmd_connect_redirect = "-x --api connect,WSAConnect --attrs is_cdl_redirect:True;redirect_ip:%s" % v_xxx_connect_tar_ip, "redirect connect address when api connect and WSAConnect"

#
# ws2_32 all success
#
v_cmd_ws2_32_all_always_success = "-x --cat ws2_32 -l optional -a add --attr is_always_success --true", "ws2_32 all apis always success"

#
# ws2_32 critical success
#
v_cmd_ws2_32_critical_always_success = "-x --cat ws2_32 -a add --attr is_always_success --true", "ws2_32 critical apis always success"


# ---------------------------------------------------------------------------
# config - wininet
# ---------------------------------------------------------------------------


#
# wininet all
#
v_cmd_wininet_all_hook = "-x --cat wininet -l optional -a add", "hook all wininet apis"
v_cmd_wininet_all_pause = "-x --cat wininet -l optional --attr shall_pause --true", "pause at all wininet apis"
v_cmd_wininet_all_hook_pause = "-x --cat wininet -l optional -a add --attr shall_pause --true", "hook and pause at all wininet apis"


# ---------------------------------------------------------------------------
# config - winhttp
# ---------------------------------------------------------------------------


#
# winhttp all
#
v_cmd_winhttp_all_hook = "-x --cat winhttp -l optional -a add", "hook all winhttp apis"
v_cmd_winhttp_all_pause = "-x --cat winhttp -l optional --attr shall_pause --true", "pause at all winhttp apis"
v_cmd_winhttp_all_hook_pause = "-x --cat winhttp -l optional -a add --attr shall_pause --true", "hook and pause at all winhttp apis"


# ---------------------------------------------------------------------------
# config - proc
# ---------------------------------------------------------------------------


#
# proc create
#
v_xxx_proc_create_apis = ["CreateProcessW",
                          "CreateProcessInternalA",
                          "CreateProcessInternalW"]
v_xxx_proc_create_apis_str = __format_list_as_param(v_xxx_proc_create_apis)
v_cmd_proc_create_hook = "-x --api %s -a add" % v_xxx_proc_create_apis_str, "hook apis when (maybe) proc create"
v_cmd_proc_create_pause = "-x --api %s --attr shall_pause --true" % v_xxx_proc_create_apis_str, "pause at apis when (maybe) proc create"
v_cmd_proc_create_hook_pause = "-x --api %s -a add --attr shall_pause --true" % v_xxx_proc_create_apis_str, "hook and pause at apis when (maybe) proc replace"


#
# proc replace
#
v_xxx_proc_replace_apis = ["CreateProcessW",
                           "CreateProcessInternalA",
                           "CreateProcessInternalW",
                           "GetThreadContext",
                           "ResumeThread",
                           "WriteProcessMemory"]
v_xxx_proc_replace_apis_str = __format_list_as_param(v_xxx_proc_replace_apis)
v_cmd_proc_replace_hook = "-x --api %s -a add" % v_xxx_proc_replace_apis_str, "hook apis when (maybe) proc replace"
v_cmd_proc_replace_pause = "-x --api %s --attr shall_pause --true" % v_xxx_proc_replace_apis_str, "pause at apis when (maybe) proc replace"
v_cmd_proc_replace_hook_pause = "-x --api %s -a add --attr shall_pause --true" % v_xxx_proc_replace_apis_str, "hook and pause at apis when (maybe) proc replace"


#
# proc exit
#
v_xxx_proc_exit_apis = ["ExitProcess", "TerminateProcess"]
v_xxx_proc_exit_apis_str = __format_list_as_param(v_xxx_proc_exit_apis)
v_cmd_proc_exit_hook = "-x --api %s -a add" % v_xxx_proc_exit_apis_str, "hook apis when (maybe) proc exit"
v_cmd_proc_exit_pause = "-x --api %s --attr shall_pause --true" % v_xxx_proc_exit_apis_str, "pause at apis when (maybe) proc exit"
v_cmd_proc_exit_hook_pause = "-x --api %s -a add --attr shall_pause --true" % v_xxx_proc_exit_apis_str, "hook and pause at apis when (maybe) proc exit"


# ---------------------------------------------------------------------------
# config - file
# ---------------------------------------------------------------------------


#
# backup del file/dirs
#
v_xxx_file_dir_backup_apis = ["DeleteFileW", "RemoveDirectoryW"]
v_xxx_file_dir_backup_str = __format_list_as_param(v_xxx_file_dir_backup_apis)
v_cmd_file_dir_backup_hook = "-x --api %s -a add" % v_xxx_file_dir_backup_str, "hook apis that del files/dirs(files/dirs will backup if default setting)"
v_cmd_file_dir_backup_pause = "-x --api %s --attr shall_pause --true" % v_xxx_file_dir_backup_str, "pause at apis that del files/dirs(files/dirs will backup if default setting)"
v_cmd_file_dir_backup_hook_pause = "-x --api %s -a add --attr shall_pause --true" % v_xxx_file_dir_backup_str, "hook and pause at apis that del files/dirs(files/dirs will backup if default setting)"


#
# write file
#
v_xxx_write_file_apis = ["WriteFile",
                         "WriteFileEx",
                         "CopyFileExW",
                         "MoveFileWithProgressW",
                         "CreateDirectoryW",
                         "CreateDirectoryExW",
                         "RemoveDirectoryW",
                         "ReplaceFileW",
                         "DeleteFileW",
                         "SetFileAttributesW",
                         "SetFileTime"]
v_xxx_write_file_apis_str = __format_list_as_param(v_xxx_write_file_apis)
v_cmd_write_file_hook = "-x --api %s -a add" % v_xxx_write_file_apis_str, "hook apis when (maybe) write file"
v_cmd_write_file_pause = "-x --api %s --attr shall_pause --true" % v_xxx_write_file_apis_str, "pause at apis when (maybe) write file"
v_cmd_write_file_hook_pause = "-x --api %s -a add --attr shall_pause --true" % v_xxx_write_file_apis_str, "hook and pause at apis when (maybe) write file"


# ---------------------------------------------------------------------------
# config - default
# ---------------------------------------------------------------------------


#
# default pause apis
#
v_xxx_default_pause_apis = ["CreateProcessInternalW",
                            "ExitProcess",
                            "send",
                            "sendto",
                            "WSASend",
                            "WSASendTo",
                            "recv",
                            "recvfrom",
                            "WSARecv",
                            "WSARecvFrom",
                            "InternetOpenA",
                            "RaiseException"]
v_xxx_default_pause_apis_str = __format_list_as_param(v_xxx_default_pause_apis)
v_cmd_default_pause_apis_str_hook_pause = "-x --api %s -a add --attr shall_pause --true" % v_xxx_default_pause_apis_str, "hook and pause default apis, and convrt to pause hook"


v_cmd_dft_all_k = "-k all -a dft", "clean all cloud"
v_cmd_clr_all_hooks = "-x --cat all --level optional -a dft", "clean all hooks, (!+ will not change any config of any apis)"
v_cmd_hook_default = "-x --cat all -a add", "default hooks"


# ---------------------------------------------------------------------------
# config - misc
# ---------------------------------------------------------------------------


#
# code inject
#
v_xxx_code_inject_apis = ["CreateRemoteThread", "QueueUserAPC"]
v_xxx_code_inject_apis_str = __format_list_as_param(v_xxx_code_inject_apis)
v_cmd_code_inject_hook = "-x --api %s -a add" % v_xxx_code_inject_apis_str, "hook apis when (maybe) code inject"
v_cmd_code_inject_pause = "-x --api %s --attr shall_pause --true" % v_xxx_code_inject_apis_str, "pause at apis when (maybe) code inject"
v_cmd_code_inject_hook_pause = "-x --api %s -a add --attr shall_pause --true" % v_xxx_code_inject_apis_str, "hook and pause at apis when (maybe) code inject"


#
# pt cstk
#
v_cmd_all_pt_cstk = "-x --cat all --attr is_pt_cstk --true", "all apis print cstk"
v_cmd_all_pt_cstk_not = "-x --cat all --attr is_pt_cstk --false", "all apis don't print cstk"


#
# shorten SleepEx
#
v_cmd_shorten_sleep = "-x --api SleepEx -a add --attr shorten_edge --vi 100", "shorten SleepEx"
v_cmd_no_shorten_sleep = "-x --api SleepEx --attr shorten_edge --vi 0", "do not shorten SleepEx(default will shorten)"


#
# mm load pe
#
v_xxx_memory_load_pe_apis = ["LoadLibraryExW",
                             "GetProcAddress",
                             "VirtualProtectEx"]
v_xxx_memory_load_pe_apis_str = __format_list_as_param(v_xxx_memory_load_pe_apis)
v_cmd_memory_load_pe_hook = "-x --api %s -a add" % v_xxx_memory_load_pe_apis_str, "hook apis when (maybe) memory load pe"
v_cmd_memory_load_pe_pause = "-x --api %s --attr shall_pause --true" % v_xxx_memory_load_pe_apis_str, "pause at apis when (maybe) memory load pe"
v_cmd_memory_load_pe_hook_pause = "-x --api %s -a add --attr shall_pause --true" % v_xxx_memory_load_pe_apis_str, "hook and pause at apis when (maybe) memory load pe"


# ---------------------------------------------------------------------------
# config - list
# ---------------------------------------------------------------------------


# cbk_list: a list of xrkdef.cbkStruct() objects


class configItem:
    # ---------------------------------------------------------------------------
    # config item
    # ---------------------------------------------------------------------------
    def __init__(self, name, desc, inner_cfg_name_list=[], cmd_list=[], cbk_list=[]):
        """
            @param: name                : STRING : name, work as key
            @param: desc                : STRING : description
            @param: inner_cfg_name_list : LIST   : a list of configItem name: [cfg_name_1, cfg_name_2, ...]
            @param: cmd_list            : LIST   : a list of TUPLE: [(cmd_1, cmd_desc_1), (cmd_2, cmd_desc_2), ...]
            @param: cbk_list            : LIST   : a list of xrkdef.cbkStruct: [cbk_obj_1, cbk_obj_2, ...]
        """
        self.name = name
        self.desc = desc
        self.inner_cfg_name_list = inner_cfg_name_list
        self.cmd_list = cmd_list
        self.cbk_list = cbk_list


v_config_list = [
    configItem("shorten_sleep", "change SleepEx params to shorten sleep time", cmd_list=[v_cmd_shorten_sleep]),
    configItem("ws2_32_all_success", "change all ws2_32 function returns to success", cmd_list=[v_cmd_ws2_32_all_always_success]),
    configItem("ws2_32_critical_success", "change critical ws2_32 function return to success", cmd_list=[v_cmd_ws2_32_critical_always_success]),
    configItem("modify_file_system", "pause at all apis that modify file system", cmd_list=[v_cmd_write_file_hook_pause]),
    configItem("create_proc", "pause at all create process apis", cmd_list=[v_cmd_proc_create_hook_pause]),
    configItem("code_inject", "pause at (possible) code injection apis", cmd_list=[v_cmd_code_inject_hook_pause]),
    configItem("wininet", "pause at all wininet apis", cmd_list=[v_cmd_wininet_all_hook_pause]),
    configItem("winhttp", "pause at all winhttp apis", cmd_list=[v_cmd_winhttp_all_hook_pause]),
    configItem("test", "test", inner_cfg_name_list=[
        "shorten_sleep",
        "ws2_32_all_success",
        "create_proc",
        "code_inject",
        "wininet",
        "modify_file_system"]),
    configItem("place_holder", "place_holder")]
