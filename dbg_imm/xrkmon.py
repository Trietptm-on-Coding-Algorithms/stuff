# -*- coding: utf-8 -*-

"""
xrkmon entry point
"""

import os
import sys
import inspect
import traceback
# import threading
import optparse as optlib

try:
    import xrkdef
    import xrklog
    import xrkdbg
    import xrkutil
    import xrkmoncfg
    import xrkmonapis
    import xrkmonctrl
except:
    this_path = os.path.split(os.path.realpath(inspect.stack()[-1][1]))[0]
    sys.path.append(this_path)
    try:
        import xrkdef
        import xrklog
        import xrkdbg
        import xrkutil
        import xrkmoncfg
        import xrkmonapis
        import xrkmonctrl
    except Exception, e:
        import immlib as dbglib
        dbg = dbglib.Debugger()
        dbg.log("xrkmon main import error: %s" % e, highlight=1)
        error = traceback.format_exc()
        while len(error) > 200:
            tmp = error[:200]
            dbg.log("  %s" % tmp, highlight=1)
            error = error[200:]
        dbg.log("  %s" % error, highlight=1)

        assert False


# ---------------------------------------------------------------------------
# misc
# ---------------------------------------------------------------------------


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
    configItem("test", "test", inner_cfg_name_list=[
        "shorten_sleep",
        "ws2_32_all_success",
        "create_proc",
        "code_inject",
        "wininet"]),
    configItem("place_holder", "place_holder")]


# ---------------------------------------------------------------------------
# config operate
# ---------------------------------------------------------------------------


def __pt_config_details():
    """
        ---------------------------------------------------------------------------
        | 0 (tmp) | empty cmd list
        ---------------------------------------------------------------------------
        | 1 (haha) | --dft_all                        | default all
        |          | --x --cat all -l optional -a add | hook all apis
        |          | --x --api api1,api2,api3,api4,ap | pause at default pause apis
        |          | i5,api6,api7 --attr shall_pause  |
        |          | --true                           |
        ---------------------------------------------------------------------------
        | 2 (hehe) | xx
        ---------------------------------------------------------------------------
    """
    spliter = "-" * 255
    lines = ["config items count: %s" % len(xrkmoncfg.v_config_list)]
    lines.append(spliter)
    index = 0

    for cfg in xrkmoncfg.v_config_list:

        index = index + 1

        # cfg: xrkmoncfg.configItem

        col_1 = "%-30s" % ("| %d (%s) " % (index, cfg.name))
        spa_col_1 = "|" + " " * (len(col_1) - 1)

        # inner configs
        if cfg.inner_cfg_name_list is not None and len(cfg.inner_cfg_name_list) != 0:
            lines.append("%s| inner cfg: %d" % (col_1, len(cfg.inner_cfg_name_list)))
            for inner_cfg_name in cfg.inner_cfg_name_list:
                lines.append("%s|     %s" % (spa_col_1, inner_cfg_name))

        # cmds
        cmds_only = []
        for cmd in cfg.cmd_list:
            cmds_only.append(cmd[0])

        if len(cmds_only) != 0:
            cmd_len_max = len(sorted(cmds_only, key=len)[-1])
            col_2_len_cmd = min(cmd_len_max, 80)
            for cmd in cfg.cmd_list:

                # cmd: "-x --api .....", "this is desc"
                if len(cmd[0]) > col_2_len_cmd:
                    sub_lines = xrklog.split_into_lines(cmd[0], col_len=col_2_len_cmd)
                    for i in range(len(sub_lines)):

                        if i == 0:
                            lines.append("%s| %s | %s" % (col_1, sub_lines[i], cmd[1]))

                        else:
                            spa_col_2 = " " * (col_2_len_cmd - len(sub_lines[i]))
                            lines.append("%s| %s%s |" % (spa_col_1, sub_lines[i], spa_col_2))

                else:
                    if len(cmds_only) != 1:
                        # more than 1 cmd, this can be any cmd
                        spa_col_2 = " " * (col_2_len_cmd - len(cmd[0]))
                        lines.append("%s| %s%s | %s" % (spa_col_1, cmd[0], spa_col_2, cmd[1]))

                    else:
                        # only 1 cmd
                        spa_col_2 = " " * (col_2_len_cmd - len(cmd[0]))
                        lines.append("%s| %s%s | %s" % (col_1, cmd[0], spa_col_2, cmd[1]))

        else:
            # lines.append("%s| empty command list" % spa_col_1)
            pass

        # cbks
        cbks_only = []
        for cbk in cfg.cbk_list:
            cbks_only.append(cbk[0])
        if len(cbks_only) != 0:
            pass
        else:
            # lines.append("%s| empty cbk list" % spa_col_1)
            pass

        # add spliter
        lines.append(spliter)

    # pt
    xrklog.infos(lines)


def __apply_config_by_key(key):
    """
        apply pre-defined config by key.

        @param: key: STRING: config key to apply

        @return: None

        1. check if key valid
        2. print cmd list
        3. exec:
            a. cmd_list
            b. cbk_list
    """
    for cfg_item in xrkmoncfg.v_config_list:

        if cfg_item.name == key:

            # we found the config

            lines = ["apply config, key: %s(%s)" % (cfg_item.name, cfg_item.desc)]

            if len(cfg_item.inner_cfg_name_list) != 0:

                # apply inner configs

                lines.append("    apply inner config, count: %d" % (len(cfg_item.inner_cfg_name_list)))
                for inner_cfg_name in cfg_item.inner_cfg_name_list:
                    lines.append("        apply inner config: %s" % inner_cfg_name)
                    __apply_config_by_key(inner_cfg_name)

            if len(cfg_item.cmd_list) != 0:

                # apply cmd list

                lines.append("    apply cmd list, count: %d" % (len(cfg_item.cmd_list)))
                for cmd in cfg_item.cmd_list:
                    lines.append("        apply cmd: %s" % (cmd[0]))
                    exec_args_str(cmd[0])

            if len(cfg_item.cbk_list) != 0:

                # apply cbk list
                # currently not used, might cause error

                lines.append("    apply cbk list, count: %d" % (len(cfg_item.cbk_list)))
                for cbk in cfg_item.cbk_list:
                    cbk.invoke()

            xrklog.infos(lines)

            return True

    xrklog.error("invalid config key: %s" % xrkutil.value_desc(key))
    return False


def __apply_config_by_index(index):
    """
        apply config by index

        @param: index : INT : index(start from 1)
    """
    if index > len(xrkmoncfg.v_config_list) + 1:
        xrklog.error("invalid config index: %d" % index)

    __apply_config_by_key(xrkmoncfg.v_config_list[index - 1].name)


def __operate_config(opts):
    """
        operate on config list

        valid input:

            --config -u/--usage
            --config --key shorten_sleep
            --config --index 1,2,3
    """
    if not opts.usage and not opts.key and not opts.index:

        # invalid input
        xrklog.error("--config -u/--usage to get help")
        return

    if opts.usage:
        # print pre-defined config list details
        __pt_config_details()

    if opts.key:

        # apply configs by key
        keys = opts.key.split(",")
        for key in keys:
            __apply_config_by_key(key)

    if opts.index:

        # apply config by index(only one)
        __apply_config_by_index(opts.index)


# ---------------------------------------------------------------------------
# knowledge list
# ---------------------------------------------------------------------------


# cloud keys u can operate on execpte "all"
# ["global", "md_names", "tid", "param_sum", "call_sum", "itd", "api", "dll_cbk"]
v_all_knowledges_except_all = [
    "global",
    "md_names",
    "tid",
    "param_sum",
    "call_sum",
    "itd",
    "api",
    "dll_cbk"]


# ---------------------------------------------------------------------------
# operate knowledge
# ---------------------------------------------------------------------------


def __get_apis_from_opts(opts):
    """
        get apis list from opts

        @param: opts: parsed options

        @return: LIST: a list of api names
    """
    level = opts.level is not None and opts.level or "default"
    apis = []

    if opts.cats:
        # categories
        apis = xrkutil.merge_list(apis, xrkmonapis.get_apis_by_cats(opts.cats.split(","), level=level))[0]

    if opts.apis:
        # apis
        apis = xrkutil.merge_list(apis, opts.apis.split(","))[0]

    if opts.include:
        # include apis/categories
        apis = xrkutil.merge_list(apis, xrkmonapis.get_apis_by_cats_and_apis(opts.include.split(","), level=level))[0]

    if opts.exclude:
        # exclude apis/categories
        apis = xrkutil.exclude_list(apis, xrkmonapis.get_apis_by_cats_and_apis(opts.exclude.split(","), level=level))[0]

    if opts.hk_type:

        # hooked or hooking...
        if opts.hk_type == "hooked":

            apis = xrkutil.merge_list(apis, xrkmonctrl.get_api_hooks_manager().get_hooked_apis())[0]

        elif opts.hk_type == "hooking":

            apis = xrkutil.merge_list(apis, xrkmonctrl.get_api_hooks_manager().get_hooking_apis())[0]

    # ---------------------------------------------------------------------------
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    #
    # this sorted() here is very critical. because of imm bug:
    #     if add hook "VirutalAllocEx" first, add hook "VirtualAlloc" second, the second will not be added.
    #     if add hook "VirtualAlloc" first, add hook "VirtualAlloc" second, both hooks will be added.
    # so, "FREQUENTLY" sort api names is recommanded! haha~~
    #
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    # ---------------------------------------------------------------------------
    return sorted(apis)


def __pt_usage_k(k_str):
    """
        print usage by k_str
    """
    usage_cmn = []
    usage_cmn.append("knowledge - %s:" % k_str)
    usage_cmn.append("")
    usage_cmn.append("-u/--usage                    print %s usage" % k_str)
    usage_cmn.append("-a usage                      print %s sage" % k_str)
    usage_cmn.append("-a dft                        set %s as default" % k_str)
    usage_cmn.append("-a pt                         print %s details" % k_str)

    usage = []
    if k_str == "main":

        """
        __  ______  _  ____  __  ___  _   _
        \ \/ /  _ \| |/ /  \/  |/ _ \| \ | |
         \  /| |_) | ' /| |\/| | | | |  \| |
         /  \|  _ <| . \| |  | | |_| | |\  |
        /_/\_\_| \_\_|\_\_|  |_|\___/|_| \_|
        """

        # imm does not print "_", what a pity!
        header = []
        spa = " " * 10
        header.append("%s |--------------------------------------|" % spa)
        # header.append("%s |                                      |" % spa)
        header.append("%s | __  ______  _  ____  __  ___  _   _  |" % spa)
        header.append("%s | \ \/ /  _ \| |/ /  \/  |/ _ \| \ | | |" % spa)
        header.append("%s |  \  /| |_) | ' /| |\/| | | | |  \| | |" % spa)
        header.append("%s |  /  \|  _ <| . \| |  | | |_| | |\  | |" % spa)
        header.append("%s | /_/\_\_| \_\_|\_\_|  |_|\___/|_| \_| |" % spa)
        # header.append("%s |                                      |" % spa)
        header.append("%s | -------------------------------------|" % spa)
        header.append("")

        xrklog.highs(header)

        usage.append("---------------------------------------------------------------------------")
        usage.append("         -u/--usage                            print usage")
        usage.append("---------------------------------------------------------------------------")
        usage.append("pre-defined configs:")
        usage.append("         --config -u/--usage                   print config usage and config list details")
        usage.append("         --config --key shorten_sleep          apply config by key")
        usage.append("         --config --index 1,2,3                apply config by index")
        usage.append("---------------------------------------------------------------------------")

        usage.append("all cloud: %s" % (", ".join("%s" % s for s in v_all_knowledges_except_all)))
        usage.append("")
        usage.append("to operate on cloud, u should:")
        usage.append("")
        usage.append("1. select cloud, like:")
        usage.append("         -k all [-e global[,itd]]              select all cloud, [except global_cfgs [and itd]]")
        usage.append("         -k global[,itd]                       select global_cfgs [and itd]")
        usage.append("         -k itd --kk lib[,file]                select itd --> intersted lib names [and file names]")
        usage.append("")
        usage.append("2. specify action to operate, like:")
        usage.append("         --usage                               print usage info of selected cloud")
        usage.append("         -a usage/pt/dft/add/remove            action: print usage/print detail/add/remove")
        usage.append("         --attr is_care                        \"is_care\" attribute to set on selected cloud")
        usage.append("")
        usage.append("3. speicfy action params, like:(some actions don't need params, like: clear)")
        usage.append("         --vi 111[,222]                        int value: 111 [and 222]")
        usage.append("         --vh 0x111[,0x222]                    int(hex) value: 0x111 [and 0x222]")
        usage.append("         --vs 111[,222]                        string value: \"111\" [and \"222\"]")
        usage.append("         --true/false                          bool value true/false")
        usage.append("---------------------------------------------------------------------------")

        usage.append("to control api hooking, u should:")
        usage.append("")
        usage.append("1. specify for hooking control, by this:")
        usage.append("         -x                                    specify this cmd is for hooking control")
        usage.append("")
        usage.append("2. select apis/cats to operate, like:")
        usage.append("         --cat all -e ws2_32 [--type hooked/hooking]  -l/--level critical/middle/optional     operate on all [or hooked/hooking] apis")
        usage.append("         --api GetProcAddress[,CreateFileExW]  -l/--level critical/middle/optional            operate on api: GetProcAddress [and CreateFileExW]")
        usage.append("         --cat ws2_32 [--api GetProcAddress]  -l/--level critical/middle/optional             operate on cat: ws2_32 [and api: GetProcAddress]")
        usage.append("         --cat ws2_32 [-e connect] [-i InternetOpenA]  -l/--level critical/middle/optional    operate on cat: ws2_32, [except connect] [include InternetOpenA]")
        usage.append("")
        usage.append("3. specify action to opeartion, like:")
        usage.append("         --usage                               print usage info of hooking")
        usage.append("         -a usage/pt/dft                       action: print usage/detail/set default")
        usage.append("         -a add/remove/pause/unpause           action: add/remove/set pause/set unpause")
        usage.append("4.1. speicfy attribute to set, like:")
        usage.append("         --attr is_pt_cstk                     specify is_pt_cstk(of cmn) attribute for selected api")
        usage.append("         --attr shorten_edge                   specify shorten_edge attribute of api SleepEx")
        usage.append("4.2. speicfy action params, like:")
        usage.append("         --vi 111                              int value: 111")
        usage.append("         --true/false                          bool value true/false")
        usage.append("---------------------------------------------------------------------------")

    elif k_str == "global":
        usage = usage_cmn
        usage = usage + xrkmonctrl. get_cloud_monCtrl().get_global_cfgs_attr_types_desc()

    elif k_str == "md_names":
        usage = usage_cmn
        usage.append("-a add --vs 111[,222]         add \"111\" [and \"222\"] to md_names")
        usage.append("-a remove --vs 111[,222]      remove \"111\" [and \"222\"] from md_names")
        usage.append("-a clear                      clear md_names")
        usage.append("")
        usage = usage + xrkmonctrl. get_cloud_monCtrl().get_md_names_attr_types_desc()

    elif k_str == "tid":
        usage = usage_cmn
        usage.append("-a clear                                              clear both include and exclude tids")
        usage.append("--kk include/exclude -a add/remove --vi 111,222       add/remove value 111 and 222 to include/exclude tids")
        usage.append("--kk include/exclude -a add/remove --vh 0x111,0x222   add/remove value 0x111 and 0x222 to include/exclude tids")
        usage.append("--kk include/exclude -a clear                         clear include/exclude tids")
        usage.append("")
        usage = usage + xrkmonctrl. get_cloud_monCtrl().get_tid_attr_types_desc()

    elif k_str == "param_sum":
        usage = usage_cmn
        usage.append("-a clear                      clear param summary")
        usage.append("-a save                       save param summary to file")
        usage.append("--v1 True/true/trUe           print only param summary that passed filters")

    elif k_str == "call_sum":
        usage = usage_cmn
        usage.append("-a clear                      clear call summary")
        usage.append("-a save                       save call summary to file")
        usage.append("--v1 True/true/trUe           print only call summary that passed filters")

    elif k_str == "itd":
        usage = usage_cmn
        usage.append("--kk str/file/reg -a add/remove --vs 111[,222]       add/remove string \"111\" and \"222\" to itd str/file/reg")
        usage.append("")
        usage = usage + xrkmonctrl. get_cloud_monCtrl().get_itd_list_attr_types_desc()

    elif k_str == "api":
        usage = usage_cmn
        usage.append("--cat svc[,ws2_32] [--api GetProcAddress[,LoadLibraryExW]] -a dft      set default to apis belong to category svc [and ws2_32] [and api GetProcAddress [and LoadLibraryExW]]")
        usage.append("")
        usage = usage + xrkmonctrl. get_cloud_monCtrl().get_itd_list_attr_types_desc()

    elif k_str == "dll_cbk":
        pass
    else:
        assert False
    xrklog.infos(usage, addr=0)


def __pt_usage_x(apis=None):
    """
        print usage of hook
    """
    usage = []
    if apis is None or len(apis) == 0:
        usage.append("1. select apis(optional)")
        usage.append("--cat all -e ws2_32 [--type hooked/hooking]  [-l/--level critical/middle/optional]")
        usage.append("--api GetProcAddress[,CreateFileExW]  [-l/--level critical/middle/optional]")
        usage.append("--cat ws2_32[,reg] [--api GetProcAddress]  [-l/--level critical/middle/optional]")
        usage.append("--cat ws2_32[,file] [-e connect[,send]] [-i InternetOpenA[,recv]]  [-l/--level critical/middle/optional]    ")
        usage.append("")
        usage.append("2. specify action")
        usage.append("-u/--usage                                    if no api selected, print usage of hooking. or print usage of selected apis")
        usage.append("-a usage                                      if no api selected, print usage of hooking. or print usage of selected apis")
        usage.append("-a pt                                         if no api selected, print all hooked/hooking apis. or print detail of selected apis")
        usage.append("-a dft                                        if no api selected, remove all hookings, and reset default hookings. or reset config of selected apis")
        usage.append("-a add/remove/pause/unpause                   apis needed, add/remove/pause/unpause for selected apis")
        usage.append("")
        usage.append("3.1. specify attribute")
        usage.append("--attr is_pt_cstk                             specify is_pt_cstk(of cmn) attribute for selected api")
        usage.append("--attr shorten_edge                           specify shorten_edge attribute of api SleepEx")
        usage.append("")
        usage.append("3.2. speicfy attribute value")
        usage.append("--vi 111                                      int value: 111")
        usage.append("--true/false                                  bool value true/false")
    else:
        k_api_config = xrkmonctrl. get_cloud_monCtrl().get_api_config()
        dict_ = {}
        cmn_only_apis = []
        for api in apis:
            if api not in k_api_config:
                xrklog.error("this api has no config: %s" % api)
            else:
                config = k_api_config[api]
                if len(config) == 1:
                    cmn_only_apis.append(api)
                else:
                    # will not update to cloud
                    del config["cmn"]
                    dict_[api] = xrkutil.value_type_desc(config)
        # dict_["common_usage_apis"] = cmn_only_apis
        usage = xrklog.get_dict_str_as_table(dict_, header="apis usages")
    xrklog.infos(usage, addr=0)


def __pt_detail_k(k_str, opts):
    """
        xx
    """
    details = []
    if k_str == "global":
        details = xrkmonctrl. get_cloud_monCtrl().get_global_cfgs_attr_details_desc()

    elif k_str == "md_names":
        details = xrkmonctrl. get_cloud_monCtrl().get_md_names_attr_details_desc()

    elif k_str == "tid":
        details = xrkmonctrl. get_cloud_monCtrl().get_tid_attr_details_desc()

    elif k_str == "param_sum":
        only_ok = (opts.v1 is not None and opts.v1.lower() == "true") and True or False
        details = xrkmonctrl. get_cloud_monCtrl().get_param_summary_attr_details_desc(only_ok=only_ok)

    elif k_str == "call_sum":
        only_ok = (opts.v1 is not None and opts.v1.lower() == "true") and True or False
        details = xrkmonctrl. get_cloud_monCtrl().get_call_summary_attr_details_desc(only_ok=only_ok)

    elif k_str == "itd":
        details = xrkmonctrl. get_cloud_monCtrl().get_itd_list_attr_details_desc()

    elif k_str == "api":
        details = xrkmonctrl. get_cloud_monCtrl().get_api_config_attr_details_desc()

    elif k_str == "dll_cbk":
        details = xrkmonctrl. get_cloud_monCtrl().get_load_dll_hks_attr_details_desc()

    else:
        assert False

    xrklog.infos(details, addr=0)


def __dft_k(k_str):
    """
        xx
    """
    if k_str == "global":
        xrkmonctrl. get_cloud_monCtrl().dft_global_cfgs()

    elif k_str == "md_names":
        xrkmonctrl. get_cloud_monCtrl().dft_md_names()

    elif k_str == "tid":
        xrkmonctrl. get_cloud_monCtrl().dft_tid()

    elif k_str == "param_sum":
        xrkmonctrl. get_cloud_monCtrl().dft_param_summary()

    elif k_str == "call_sum":
        xrkmonctrl. get_cloud_monCtrl().dft_call_summary()

    elif k_str == "itd":
        xrkmonctrl. get_cloud_monCtrl().dft_itd_list()

    elif k_str == "api":
        xrkmonctrl. get_cloud_monCtrl().dft_api_config()

    elif k_str == "dll_cbk":
        xrkmonctrl. get_cloud_monCtrl().dft_load_dll_hks()

    else:
        xrklog.highlight("dft_k, invalid k_str: %s" % k_str)
        assert False


def __opt_type_to_value(type_, opts):
    """
        xx
    """
    if type_ == str:
        return opts.value_str

    elif type_ == int:
        return opts.value_int

    elif type_ == bool:
        return opts.value_bool

    else:
        assert False


def __update_attr_k(k_str, opts):
    """
        update knowledge attribute
    """
    assert opts.attribute is not None
    func_get_value_type = None
    func_update = None
    k = xrkmonctrl. get_cloud_monCtrl()

    if k_str == "global":
        func_get_value_type = k.get_global_cfgs_key_value_type
        func_update = k.update_global_cfgs

    elif k_str == "md_names":
        func_get_value_type = k.get_md_names_key_value_type
        func_update = k.update_md_names

    elif k_str == "tid":
        func_get_value_type = k.get_tid_key_value_type
        func_update = k.update_tid

    elif k_str == "param_sum":
        assert False

    elif k_str == "call_sum":
        assert False

    elif k_str == "itd":
        func_get_value_type = k.get_itd_list_key_value_type
        func_update = k.update_itd_list

    elif k_str == "api":
        func_get_value_type = k.get_api_config_key_value_type
        func_update = k.update_api_config

    elif k_str == "dll_cbk":
        assert False

    else:
        assert False

    value_type = None
    if opts.kk is not None:
        value_type = func_get_value_type(opts.attribute, opts.kk)

    else:
        value_type = func_get_value_type(opts.attribute)

    if value_type is not None:

        xrklog.info("attribute value and type: %s - %s" % (opts.attribute, value_type.__name__))

        if opts.kk is None:
            func_update({opts.attribute: __opt_type_to_value(value_type, opts)})

        else:
            func_update({opts.kk: {opts.attribute: __opt_type_to_value(value_type, opts)}})

    else:
        xrklog.error("invalid attribute: %s" % opts.attribute, add_prefix=True)


def __check_knowledge_common(k_str, opts):
    """
        check common opts:
            usage    --> __pt_usage_k()
            dft      --> __dft_k()
            pt       --> __pt_detail_k()
            set_attr --> __update_attr_k()

        @param: k_str : STRING : knowledge string, one of the following: ["global", "md_names", "tid", "param_sum", "call_sum", "itd", "api", "dll_cbk"]
    """
    if k_str not in v_all_knowledges_except_all:
        raise Exception("invalid k_str: %s" % k_str)

    if opts.usage:
        __pt_usage_k(k_str)

    if opts.action is not None:

        action = opts.action
        # no need to print usage again
        if action == "usage" and opts.usage is not True:
            __pt_usage_k(k_str)

        elif action == "dft":
            __dft_k(k_str)

        elif action == "pt":
            __pt_detail_k(k_str, opts)

        else:
            pass

    elif opts.usage:

        # we pinted usage before, so do nothing here
        pass

    else:
        assert opts.attribute is not None

    # might update attribute also
    if opts.attribute is not None:
        __update_attr_k(k_str, opts)


def __operate_knowledge_global(opts):
    """
        operate knowledge on global

        !+ nothing special, proxy to __check_knowledge_common()
    """
    __check_knowledge_common("global", opts)


def __operate_knowledge_md_names(opts):
    """
        xx
    """
    raise Exception("not implemented")


def __operate_knowledge_tid(opts):
    """
        xx
    """
    raise Exception("not implemented")


def __operate_knowledge_param_sum(opts):
    """
        xx
    """
    raise Exception("not implemented")


def __operate_knowledge_call_summary(opts):
    """
        xx
    """
    raise Exception("not implemented")


def __operate_knowledge_itd(opts):
    """
        xx
    """
    raise Exception("not implemented")


def __operate_knowledge_api(opts):
    """
        operate knowledge on api

        usages:
            --cat svc[,ws2_32] [--api GetProcAddress[,LoadLibraryExW]] -a dft
            --api GetProcAddress -a add/remove
    """
    __check_knowledge_common("api", opts)

    if opts.action is not None and opts.action not in ["usage", "dft", "pt"]:
        xrklog.error("operate k api, invalid action: %s" % opts.action)

    elif opts.usage:
        # already printed usage
        pass

    else:
        # apis = __get_apis_from_opts(opts)
        pass

    """
    print detail:
    k_api_config = xrkmonctrl. get_cloud_monCtrl().get_api_config()
    dict_ = {}
    for api in apis:
        if api not in k_api_config:
            xrklog.error("this api has no config: %s" % api)
        else:
            config = k_api_config[api]
            dict_[api] = config["cmn"].to_dict()
            # will not update to cloud
            del config["cmn"]
            if len(config) != 0:
                dict_[api] = xrkutil.update_dict(dict_[api], config)
    usage = xrklog.get_dict_as_table(dict_, header="apis usages")
    xrklog.infos(usage, addr=0)
    """


def __operate_knowledge(opts):
    """
        operate on cloud

        1. get operate knowledge list
        2. operate on each knowledge
    """
    assert opts.usage is True or opts.action is not None or opts.attribute is not None
    ks = opts.knowledge.split(",")

    if "all" in ks:
        ks.remove("all")
        ks = xrkutil.merge_list(ks, v_all_knowledges_except_all)[0]
    if opts.include:
        includes = opts.include.split(",")
        ks = xrkutil.merge_list(ks, includes)[0]
    if opts.exclude:
        excludes = opts.exclude.split(",")
        ks = xrkutil.exclude_list(ks, excludes)[0]

    for k in ks:
        if k not in v_all_knowledges_except_all:
            xrklog.error("invalid knowledge: %s" % k)
            ks.remove(k)

    if "global" in ks:
        __operate_knowledge_global(opts)

    if "md_names" in ks:
        __operate_knowledge_md_names(opts)

    if "tid" in ks:
        __operate_knowledge_tid(opts)

    if "param_sum" in ks:
        __operate_knowledge_param_sum(opts)

    if "call_sum" in ks:
        __operate_knowledge_call_summary(opts)

    if "itd" in ks:
        __operate_knowledge_itd(opts)

    if "api" in ks:
        __operate_knowledge_api(opts)


# ---------------------------------------------------------------------------
# operate hook
# ---------------------------------------------------------------------------


def __operate_hook_print_details(apis):
    """
        print hook detail of apis
    """
    lines = xrkmonctrl.get_api_hooks_manager().get_all_apis_desc()
    xrklog.infos(lines)


def __operate_hook_set_default(apis):
    """
        1. if no apis: remove all hooked/hooking
        2. if has apis: remove apecified apis hooked or hooking

        !+ will not change any config of any apis
    """
    if len(apis) == 0:
        xrkmonctrl.get_api_hooks_manager().remove_all()
        xrklog.info("hook set default(remove all) finish" % len(apis))
    else:
        xrkmonctrl.get_api_hooks_manager().remove_apis(apis)
        xrklog.info("hook set %d apis default finish" % len(apis))


def __operate_hook_add(apis):
    """
        add apis hook
    """
    already_added_apis = xrkmonctrl.get_api_hooks_manager().add_apis(apis)
    if len(already_added_apis) != 0:
        lines = ["already added apis: %d" % len(already_added_apis)] + xrklog.list_to_lines(already_added_apis)
        xrklog.errors(lines)
    xrklog.info("add apis hook finish, all: %d, installed: %d, ignored: %d" % (len(apis), len(apis) - len(already_added_apis), len(already_added_apis)))


def __operate_hook_remove(apis):
    """
        remove api hook
    """
    not_added_apis = xrkmonctrl.get_api_hooks_manager().remove_apis(apis)
    if len(not_added_apis) != 0:
        lines = ["not added apis: %d" % len(not_added_apis)] + xrklog.list_to_lines(not_added_apis)
        xrklog.errors(lines)
    xrklog.info("remove apis hook finish: %d" % (len(apis) - len(not_added_apis)))


def __operate_hook_pause(apis):
    """
        set pause apis by specified api names

        1. set pause to all hooked/hooking apis
        2. set pause to all not hooked/hooking apis
            if api is hooked/hooking afterwards, it will take effec
            buf, we don't care how it is hooked/hooking
    """
    """
    not_installed_apis = api_hooks_container_method(apiHooksManager.set_pause_apis, apis)
    if len(not_installed_apis) != 0:
        lines = ["set pause apis: %d apis not installed: " % len(not_installed_apis)]
        for api in not_installed_apis:
            lines.append("%s" % api)
        xrklog.errors_ex(lines)
    xrklog.info("pause apis finish")
    """
    pass


def __operate_hook_un_pause(apis):
    """
        set un pause apis by specified api names

        1. set pause to all hooked/hooking apis
        2. set pause to all not hooked/hooking apis
            if api is hooked/hooking afterwards, it will take effec
            buf, we don't care how it is hooked/hooking
    """
    """
    not_installed_apis = api_hooks_container_method(apiHooksManager.set_un_pause_apis, apis)
    if len(not_installed_apis) != 0:
        lines = ["set un pause apis: %d apis not installed: " % len(not_installed_apis)]
        for api in not_installed_apis:
            lines.append("%s" % api)
        xrklog.errors_ex(lines)
    xrklog.info("un pause apis finish")
    """
    pass


def __operate_hook_set_attr(apis, opts):
    """
        set attribute

        1. update to cloud
        2. suck special attributes, like:
            shall_pause: we need to call PausableHook func: pause()/un_pause()

        if apis list is empty, we take it as: all apis.
    """
    assert opts.attribute is not None
    if len(apis) != 1:

        if xrkmonctrl.ctrlCmn().check_has_cfg(opts.attribute):

            assert opts.value_bool is not None
            k = xrkmonctrl. get_cloud_monCtrl()
            k_api_config = k.get_api_config()
            if len(apis) == 0:
                # to all apis
                for (d, x) in k_api_config.items():
                    x["cmn"].update_from_dict({opts.attribute: opts.value_bool})
                k.update()

            else:
                # to specified apis
                for (d, x) in k_api_config.items():
                    if d in apis:
                        x["cmn"].update_from_dict({opts.attribute: opts.value_bool})
                k.update()

        else:
            xrklog.error("operate hook, invalid attribute: %s" % opts.attribute)
    else:
        k = xrkmonctrl. get_cloud_monCtrl()
        k_api_config = k.get_api_config()
        if xrkmonctrl.ctrlCmn().check_has_cfg(opts.attribute):
            assert opts.value_bool is not None
            k_api_config[apis[0]]["cmn"].update_from_dict({opts.attribute: opts.value_bool})
            k.update()

        else:
            # TODO: special apis, we need to check value type
            pass

    # for special attributes
    if len(apis) == 0:
        if opts.attribute == "shall_pause":
            if opts.value_bool:
                xrkmonctrl.get_api_hooks_manager().set_pause_all()
            else:
                xrkmonctrl.get_api_hooks_manager().set_un_pause_all()
    else:
        if opts.attribute == "shall_pause":
            if opts.value_bool:
                xrkmonctrl.get_api_hooks_manager().set_pause_apis(apis)
            else:
                xrkmonctrl.get_api_hooks_manager().set_un_pause_apis(apis)


def __operate_hook(opts):
    """
        operate hooks

        1. get api list
        2. operate apis
            a. 1 api
            b. n apis
        3. operate on mds

        usage.append("1. select apis: ")
        usage.append("--cat all -e ws2_32 [--type hooked/hooking]  [-l/--level critical/middle/optional]")
        usage.append("--api GetProcAddress[,CreateFileExW]  [-l/--level critical/middle/optional]")
        usage.append("--cat ws2_32[,reg] [--api GetProcAddress]  [-l/--level critical/middle/optional]")
        usage.append("--cat ws2_32[,file] [-e connect[,send]] [-i InternetOpenA[,recv]]  [-l/--level critical/middle/optional]    ")
        usage.append("")
        usage.append("2. specify action")
        usage.append("-u/--usage                                    if no api selected, print usage of hooking. or print usage of selected apis")
        usage.append("-a usage                                      if no api selected, print usage of hooking. or print usage of selected apis")
        usage.append("-a pt                                         if no api selected, print all hooked/hooking apis. or print detail of selected apis")
        usage.append("-a dft                                        if no api selected, remove all hookings, and reset default hookings. or reset config of selected apis")
        usage.append("-a add/remove/pause/unpause                   apis needed, add/remove/pause/unpause for selected apis")
        usage.append("3.1. specify attribute")
        usage.append("--attr is_pt_cstk                             specify is_pt_cstk(of cmn) attribute for selected api")
        usage.append("--attr shorten_edge                           specify shorten_edge attribute of api SleepEx")
        usage.append("3.2. speicfy attribute value")
        usage.append("--vi 111                                      int value: 111")

    """
    if not opts.usage and opts.action is None and opts.attribute is None:
        xrklog.error("invalid options. check out usage: ")
        __pt_usage_x()
        return

    apis = __get_apis_from_opts(opts)
    if opts.usage:
        if len(apis) == 0:
            __pt_usage_x()
        else:
            __pt_usage_x(apis)

    if opts.action is not None:
        action = opts.action
        if action == "usage" and opts.usage is not True:
            if len(apis) == 0:
                __pt_usage_x()
            else:
                __pt_usage_x(apis)
        elif action == "pt":
            __operate_hook_print_details(apis)
        elif action == "dft":
            __operate_hook_set_default(apis)
        elif action == "add":
            __operate_hook_add(apis)
        elif action == "remove":
            __operate_hook_remove(apis)
        elif action == "pause":
            __operate_hook_pause(apis)
        elif action == "unpause":
            __operate_hook_un_pause(apis)
        else:
            xrklog.error("invalid action: %s" % (action))

    if opts.attribute:
        __operate_hook_set_attr(apis, opts)


# ---------------------------------------------------------------------------
# operate modules
# ---------------------------------------------------------------------------


def __operate_mds_pt_usage():
    """
        xx
    """
    usage = []
    usage.append("---------------------------------------------------------------------------")
    usage.append("operate on module exports, no matter module is loaded or not")
    usage.append("1. specify md_names: (!+ make sure to provide md_name with extensions, or will cause exception)")
    usage.append("-m dnsapi.dll[,kernel32.dll]")
    usage.append("2. (optional) exclude some export items by names: ")
    usage.append("-e DnsQuery_W[,LoadLibraryExW]")
    usage.append("3. (optional) set pause or unpause(default is un pause. param will be ignored)")
    usage.append("--pause")
    usage.append("4. (optonal) has oep(default is false)")
    usage.append("--has_oep")
    usage.append("---------------------------------------------------------------------------")

    xrklog.infos(usage, addr=0)


def __operate_mds(opts):
    """
        -m dnsapi[kernel32] -e DnsQuery_W[,LoadLibraryExW] [--pause] [--has_oep]

        !+ module might not be loaded
    """
    if opts.usage:
        pass

    excludes = []
    if opts.exclude:
        excludes = opts.exclude.split(",")

    mds = opts.mds.split(",")
    eats = xrkutil.get_mds_eats(mds)

    # for now, we assume module is loaded
    bps = {}
    for (d, x) in eats.items():
        if opts.has_oep:
            bps[x["oep"]] = "%s_oep" % d
        for (dd, xx) in x.items():
            if dd != "oep" and dd not in excludes:
                bps[xx] = dd

    # set bp
    if opts.pause:
        for (d, x) in bps.items():
            xrkdbg.setComment(d, x)
            xrkdbg.setBreakpoint(d)
            xrklog.info("set bp: 0x%.8X - %s" % (d, x))
    else:
        for (d, x) in bps.items():
            xrkdbg.setComment(d, x)
            if not xrkutil.check_has_hook(x):
                # might already be hooked
                h = xrkdef.logCommentHook()
                h.add(x, d)
                xrklog.info("add log comment hook: 0x%.8X - %s" % (d, x))
            else:
                xrklog.error("md export already been hooked: 0x%.8X - %s" % (d, x))


def __operate_flags(opts):
    """
        operate flags
    """
    flags = opts.flags.split(",")

    # reset everything
    if "reset" in flags:
        xrklog.high("reset everything first")
        xrkdbg.cleanUp()

    # hide debug
    if "hide" in flags:
        import hidedebug
        xrklog.high("using hidedebug.py to hide debugger, ALL_DEBUG")
        hidedebug.main(["ALL_DEBUG"])

    # print saved api log
    if "pt_call_sum" in flags:

        lines = ["call log summary:"]

        import xrkmonrun
        k, kx = xrkmonrun.parse_api_log()
        if k is not None and kx is not None:
            lines.append(str(k))
            lines.append(str(kx))

        xrklog.infos(lines)


# ---------------------------------------------------------------------------
# parse args
# ---------------------------------------------------------------------------


def __parse_args(args):
    """
        parse args using optlib.OptionParser()

        @param: args : LIST : a list of strings

        @return: TUPLE : (opts, args_remain)
    """
    pr = optlib.OptionParser(usage="xrkmon usage")

    same_group = optlib.OptionGroup(pr, "same group", "share between groups, but have same meaning for all group")
    same_group.add_option("-u", "--usage", dest="usage", action="store_true", help="show usage")
    same_group.add_option("-t", "--test", dest="test", action="store_true", help="invoke test() method")
    same_group.add_option("-f", "--file", dest="file", help="file to use, like: save log file")
    # flags: hide,reset,pt_call_sum
    same_group.add_option("", "--flags", dest="flags", help="flags, shall be splited by \",\"")
    pr.add_option_group(same_group)

    share_group = optlib.OptionGroup(pr, "share group", "share between different group, but have different meanings or value")
    share_group.add_option("-a", "--action", dest="action", help="operation name to take")
    share_group.add_option("-i", "--include", dest="include", help="include stuff, like: api_name, dll_name, cat_name")
    share_group.add_option("-e", "--exclude", dest="exclude", help="exclude stuff, like: api_name, dll_name, cat_name")
    share_group.add_option("", "--hk_type", dest="hk_type", help="api hook type: hooked/hooking, dll hook type: import/export, etc")
    pr.add_option_group(share_group)

    config_group = optlib.OptionGroup(pr, "config group", "manages config")
    config_group.add_option("", "--config", dest="config", action="store_true", help="operate on config")
    config_group.add_option("", "--key", dest="key", help="string key to something, like config. for config, this means apply config by key")
    config_group.add_option("", "--index", dest="index", type="int", help="int key to something, like config. for config, this means apply config by index")
    pr.add_option_group(config_group)

    knowledge_group = optlib.OptionGroup(pr, "knowledge group", "manages all cloud")
    knowledge_group.add_option("-k", "--knowledge", dest="knowledge", help="knowledge to take operation")
    knowledge_group.add_option("", "--kk", dest="kk", help="sub knowledge key to take opeartion")
    knowledge_group.add_option("", "--attr", dest="attribute", help="attribute to set")
    knowledge_group.add_option("", "--attrs", dest="attributes", help="set many attributes at the same time. format: a1:v1;a2:v2;a3:v3")
    pr.add_option_group(knowledge_group)

    hook_group = optlib.OptionGroup(pr, "hook group", "manages all hooks")
    hook_group.add_option("-x", "--hook", dest="hook", action="store_true", help="take opeartion for hooks")
    hook_group.add_option("-l", "--level", dest="level", default="default", help="api level")
    hook_group.add_option("", "--api", dest="apis", help="api to take operation")
    hook_group.add_option("", "--cat", dest="cats", help="category to take operation")
    pr.add_option_group(hook_group)

    dll_group = optlib.OptionGroup(pr, "module group", "operate on modules")
    dll_group.add_option("-m", "--md", dest="mds", help="modules to take operation")
    dll_group.add_option("", "--pause", dest="pause", action="store_true", help="modules to take operation")
    dll_group.add_option("", "--has_oep", dest="has_oep", action="store_true", help="modules to take operation")
    pr.add_option_group(dll_group)

    value_group = optlib.OptionGroup(pr, "value group", "all kinds of values")
    value_group.add_option("", "--true", dest="value_bool", action="store_true", help="value of bool")
    value_group.add_option("", "--false", dest="value_bool", action="store_false", help="value of bool")
    value_group.add_option("", "--vi", dest="value_int", type="int", help="value of int")
    value_group.add_option("", "--vh", dest="value_hex", type="string", help="value of int in hex mode(str, convert to hex in code)")
    value_group.add_option("", "--vs", dest="value_str", type="string", help="value of str")
    value_group.add_option("", "--v1", dest="v1", help="value 1, can be anything, convert by yourself")
    value_group.add_option("", "--v2", dest="v2", help="value 2, can be anything, convert by yourself")
    value_group.add_option("", "--v3", dest="v3", help="value 3, can be anything, convert by yourself")
    value_group.add_option("", "--v4", dest="v4", help="value 4, can be anything, convert by yourself")
    pr.add_option_group(value_group)

    alone_flags = optlib.OptionGroup(pr, "stand alone flags", "manage overall/global standalone flags")
    # alone_flags.add_option("", "--verbose", dest="verbose", action="store_true", default="false", help="is log verbose")
    pr.add_option_group(alone_flags)

    return pr.parse_args(args=args)


def test():
    """
        test
    """
    xrklog.highlight("test")

    k_api_config = xrkmonctrl.get_cloud_monCtrl().get_api_config()
    lines = []
    for (d, x) in k_api_config.items():
        if xrkmonapis.get_dll_name_by_api_name(d).lower() == "kernel32.dll":
            lines.append("\"%s\"," % d)
    xrklog.infos(lines)

    # xrkmonctrl.get_api_hooks_manager().add_apis()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def exec_args(args):
    """
        call interfaces of hook_ctrl/hook_run according to parsed args

        @param: args : LIST : a list of strings

        @return: BOOL : if parse and exec sucess
    """
    if len(args) == 0:
        xrklog.error("no param, -u/--usage for usage")
        return False

    try:
        # import datetime
        # start = datetime.datetime.now()

        opts, args_remain = __parse_args(args)

        #
        # if opts.verbose:
        #    # set verbose flag
        #    pass
        #

        # flags
        if opts.flags:
            __operate_flags(opts)

        # only has 1 args: -u/--usage
        if opts.usage and len(args) == 1:

            __pt_usage_k("main")
            if len(args) != 1:
                xrklog.error("other param be negelected")

            return True

        # test
        if opts.test:
            test()

        # apply/print pre-defined config cmds
        if opts.config:
            __operate_config(opts)

        # monCtrl
        if opts.knowledge:
            __operate_knowledge(opts)

        # apiHooksManager
        if opts.hook:
            __operate_hook(opts)

        # dlls
        if opts.mds:
            __operate_mds(opts)

        # end = datetime.datetime.now()
        # xrklog.highlight("exec_args, time: %s, args: %s" % ((end - start), args))

        return True

    except Exception, e:
        log = []
        log.append("parse args exception, plase check your params")
        log.append("exception: ")
        log.append("           type: %s" % type(e))
        log.append("           detail: %s" % (e))

        e_str = "%s" % e
        e_type_str = "%s" % type(e)

        # <type 'exceptions.AttributeError'>
        # 'module' object has no attribute 'argv'

        if "AttributeError" in e_type_str and "object has no attribute" in e_str and "argv" in e_str:
            log.append("           maybe, u should provide args for your option(s)")

        # type: <type 'exceptions.TypeError'>
        # detail: 'list' object is not callable
        elif "TypeError" in e_type_str and "object is not callable" in e_str:
            log.append("           maybe, u should check if function name and variable name conflicts")

        # type: <type 'exceptions.AssertionError'>
        elif "AssertionError" in e_type_str:
            log.append("           this is not easy to check. un-comment try-except block to check call stack")
        else:
            pass
        xrklog.errors(log)

        xrkutil.cstk()
        return False


def exec_args_str(str_):
    """
        split str_ by " " then proxy to exec_args()
        this if for external usage.

        @param: str_ : STRING : exec string

        @return: BOOL : cmd parse and exec result
    """
    import datetime
    start = datetime.datetime.now()

    # exec
    ret = exec_args(str_.split(" "))

    end = datetime.datetime.now()
    xrklog.highlight("exec_args_str: %s" % ((end - start)))

    return ret


# ? if __name__ == "__main__":
def main(args):

    exec_args(args)

    xrkdbg.logLines("")
    return "xrkmon main finish"

# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
