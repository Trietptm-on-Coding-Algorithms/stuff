# -*- coding: utf-8 -*-

"""
    xrkmon run
"""

import os
import sys
import inspect
import datetime
import debugger
import traceback

try:
    # import xrksym
    import xrklog
    import xrkdbg
    import xrkutil
    import xrkcstk
    import xrkhook
    import xrkcloud
    import xrkmonctrl
    import xrkmonapis
except:
    this_path = os.path.split(os.path.realpath(inspect.stack()[-1][1]))[0]
    sys.path.append(this_path)
    try:
        # import xrksym
        import xrklog
        import xrkdbg
        import xrkutil
        import xrkcstk
        import xrkhook
        import xrkcloud
        import xrkmonctrl
        import xrkmonapis
    except Exception, e:
        import immlib as dbglib
        dbg = dbglib.Debugger()
        dbg.log("xrkmonrun import error: %s" % e, highlight=1)
        error = traceback.format_exc()
        while len(error) > 200:
            tmp = error[:200]
            dbg.log("  %s" % tmp, highlight=1)
            error = error[200:]
        dbg.log("  %s" % error, highlight=1)

        assert False


# -------------------------------------------------------------------------
# misc
# -------------------------------------------------------------------------


def __get_api_config(api_name):
    """
        get api config

        @param: api_name : STRING : api name
        @return: DICT : a dict like this: {"cmn": ctrlCmn(), "xx": xx, ...}
    """
    return xrkmonctrl.get_cloud_monCtrl().get_api_config()[api_name]

#
# api filters:
#   1. filter call stack
#   2. filter thread id
#   3. check common: this only check conditional pause and pt_cstk
#   x. shall be some method to ignore some types of filters
#


def __filter_caller_fast(caller_name, offset):
    """
        filter caller fast, by calledfrom of stacks[0]

        @param: caller_name : STRING : caller name
        @param: offset      : INT    : offset

        @return: BOOL : True if fulfills, or stack empty, otherwise False
    """
    stacks = xrkdbg.callStack()
    if stacks is None or len(stacks) == 0:
        return False

    return stacks[0].calledfrom == (xrkdbg.getAddress(caller_name) + offset)


# -------------------------------------------------------------------------
# all sucks
# -------------------------------------------------------------------------


def __check_cstk(k, api_name, regs):
    """
        check call stack

        @param: k        : obj    : obj of xrkmonctrl.monCtrl
        @param: api_name : STRING : api name to check
        @param: regs     : DICT   : reg dict

        @return: BOOL : True  : this api call here, shall be "ignored"
                        False : this api call here, shall not be "ignored"

        1. A --> W
        2. send <-- InternetXX
    """
    # we're insterested in these apis, so, we give it a "True"
    if api_name in ["CreateRemoteThread", "CreateProcessInternalW"]:
        return True

    k_md_names = k.get_md_names()
    if not k_md_names["is_care"] or xrkcstk.check_cstk_uppers_in_md_names(api_name, k_md_names["md_names"], is_no_stack_as_true=k_md_names["is_no_stack_as_true"], is_no_md_as_true=k_md_names["is_no_md_as_true"]):

        # check if ws2_32.dll apis come from wininet.dll or winhttp.dll
        if xrkmonapis.get_dll_name_by_api_name(api_name).lower() == "ws2_32.dll":
            return not xrkcstk.check_cstk_uppers_has_strs(["wininet", "winhttp"], 2)

        return True

    # ---------------------------------------------------------------------------
    # log to dbg view
    xrkcstk.dbgview_cstk_procedures(api_name, pt_addr=True, pt_called_from=True, pt_frame=True)

    return False


def __apply_cmn(k, api_name, regs, param_pairs=None, is_ok_cstk=True, is_ok_tid=True):
    """
        update k_api_config[api_name]["cmn"]

        @param: k           : obj    : obj of xrkmonctrl.monCtrl
        @param: api_name    : STRING : api name
        @param: regs        : DICT   : reg dict
        @param: param_pairs : DICT   : param dict
        @param: is_ok_cstk  : BOOL   : is pass call stack check
        @param: is_ok_tid   : BOOL   : is pass tid check
    """
    api_cfg_cmn = k.get_api_config()[api_name]["cmn"]

    # 1. conditional pause
    if api_cfg_cmn.cdl_pause is not None and api_cfg_cmn.cdl_pause(regs):
        xrkutil.pause()

    # 2. pt call stack
    if api_cfg_cmn.is_pt_cstk or (api_cfg_cmn.cdl_pt_cstk is not None and api_cfg_cmn.cdl_pt_cstk(regs)):
        xrkcstk.pt_cstk(pt_args=True)

    # 3. pt call details
    if api_cfg_cmn.is_pt_call:
        __log_api_call_params_cstk(api_name, param_pairs)


def __log_api_call_params_cstk(api_name, param_pairs):
    """
        log api call and params and cstk
    """
    lines = []
    # 25 for api_name, 5 for " <-- "
    spa = " " * (25 + 5)
    # header and params
    cstk_str = xrkcstk.get_calledfrom_sym_strs_as_str(all_cstk=False, has__=False, has_at=False, has_dis=False)
    lines.append("%25s <-- %s" % (api_name, cstk_str))

    if param_pairs is not None:

        param_desc_all = ""
        param_pair_descs = []
        for (d, x) in param_pairs.items():

            param_desc_tmp = "%s : %s" % (d, xrkutil.value_desc(x))
            param_pair_descs.append(param_desc_tmp)
            param_desc_all = param_desc_all + param_desc_tmp + "; "

        # change max col accordingly
        # 150 for laptop, xx for desktop
        if len(lines[0]) + len(param_desc_all) < 150:
            lines[0] = "%s || %s" % (lines[0], param_desc_all)

        else:
            for param_desc in param_pair_descs:
                lines.append("%s: %s" % (spa, param_desc))

    xrklog.highs(lines, add_prefix=True)
    """
    # pass both call stack check and tid check, or is api we're interested in
    if (is_ok_cstk and is_ok_tid) or api_name in ["IsDebuggerPresent"]:
        xrklog.highs(lines, addr=regs["EIP"], add_prefix=True)

    else:
        xrklog.warns(lines, addr=regs["EIP"], add_prefix=True)
    """

# -------------------------------------------------------------------------
# api log
# -------------------------------------------------------------------------

#
# structure of api log:
#       [{"record_time": xx, "analyse_material": (api_name, regs, param_pairs, cstks), "analyse_result": xx},
#        {"record_time": xx, "analyse_material": (api_name, regs, param_pairs, cstks), "analyse_result": xx},
#        ...]
#
v_id_api_log = "id_api_log"


def add_api_log(api_name, regs, param_pairs=None):
    """
        add api log to cloud, and pt sometime

        @param: api_name    : STRING : api name
        @param: regs        : DICT   : reg dict
        @param: param_pairs : DICT   : param dict
    """
    k = xrkcloud.cloud_get(v_id_api_log, default=[])
    k.append({"record_time": datetime.datetime.now(),
              # "tid": tid,
              "analyse_material": (api_name, regs, param_pairs, xrkdbg.callStack()),
              "analyse_result": None})

    xrkcloud.cloud_set(v_id_api_log, k)


def clear_api_log():
    """
        clear api log in cloud
    """
    xrkcloud.cloud_set(v_id_api_log, [])


def parse_api_log():
    """
        parse api log in cloud

        results we need:
            for each api log:
                is_ok_cstk
                is_ok_tid
                stacks_sym
                stacks_str # A <-- B <-- C
                has_itd_str
                has_itd_file
                has_itd_lib
                has_itd_reg
                has_itd_mm_size
            for all api logs:
                all_strs
                all_files
                all_libs
                all_regs
                all_mm_sizes

        @return: TUPLE: (k, kx)
            k:  LIST: parsed api log list
            kx: DICT: parsed all api logs summary: {"all_strs": xx, "all_libs"}
    """
    k = xrkcloud.cloud_get(v_id_api_log)
    if k is None or len(k) == 0:
        xrklog.error("no api log to parse")
        return None, None

    kx = {"all_strs": [], "all_files": [], "all_libs": [], "all_regs": [], "all_mm_sizes": []}

    is_changed = False
    for i in range(len(k)):
        materials = k[i]["analyse_material"]
        result = k[i]["analyse_result"]
        if result is None:
            result = {}
            # stacks = materials[3]
            result["is_ok_cstk"] = __check_cstk()
            # result["is_ok_tid"] = __check_tid()
            # result["stacks_sym"] = __get_stacks_sym()
            # result["stacks_str"] = __get_stacks_str()
            # result["has_itd_str"] = __itd_str_check()
            # ...
            k[i]["analyse_result"] = result
            is_changed = True

        params = materials[2]
        if params is not None and len(params) != 0:
            pass

    if is_changed:
        xrkcloud.cloud_set(v_id_api_log, k)

    return k, kx

# -------------------------------------------------------------------------
# suck api
# -------------------------------------------------------------------------


def xrk_api_call(api_name, regs, param_pairs=None):
    """
        operate on each api call

        @param: api_name    : STRING : api name
        @param: regs        : DICT   : reg dict
        @param: param_pairs : DICT   : param dict

        !+ at frist, we tried to handle everything(filter/symbol/analysis), and the cbk alone take about 800 msecs,
           with the addition of debugger calling pyc, each api take about 1 secs, which is un-tolerable!
           so, we only print call detail and add to knowledge, which take about 80 msecs.
    """
    if param_pairs is not None and "handle" in param_pairs:
        param_pairs["handle_name"] = xrkutil.get_name_by_handle(param_pairs["handle"])
        del param_pairs["handle"]

    k_ctrl = xrkmonctrl.get_cloud_monCtrl()
    mode = k_ctrl.get_global_cfgs()["work_mode"]

    try:

        if mode == "debug":

            # 100 msecs
            # is_ok_cstk = __check_cstk(k, api_name, regs)

            # 0-10 msecs
            # is_ok_tid = __check_tid(k, api_name, regs)

            # 30 msecs
            # __add_call_summary(k, api_name, regs, is_ok_cstk=is_ok_cstk, is_ok_tid=is_ok_tid)

            # 10 mescs
            # __add_param_summary(k, api_name, param_pairs, is_ok_cstk=is_ok_cstk, is_ok_tid=is_ok_tid)

            # 90 msecs
            # __apply_cmn(k, api_name, regs, param_pairs=param_pairs, is_ok_cstk=is_ok_cstk, is_ok_tid=is_ok_tid)

            lines = []
            # 25 for api_name, 5 for " <-- "
            spa = " " * (25 + 5)

            if k_ctrl.get_global_cfgs()["is_log_cstk"]:
                cstk_str = xrkcstk.get_calledfrom_sym_strs_as_str(all_cstk=False, has__=False, has_at=False, has_dis=False)
                lines.append("%25s <-- %s" % (api_name, cstk_str))
            else:
                lines.append("%25s" % (api_name))

            if k_ctrl.get_global_cfgs()["is_log_params"] and param_pairs is not None:

                param_desc_all = ""
                param_pair_descs = []
                for (d, x) in param_pairs.items():

                    param_desc_tmp = "%s : %s" % (d, xrkutil.value_desc(x))
                    param_pair_descs.append(param_desc_tmp)
                    param_desc_all = param_desc_all + param_desc_tmp + "; "

                # change max col accordingly
                # 150 for laptop, xx for desktop
                if len(lines[0]) + len(param_desc_all) < 150:
                    lines[0] = "%s || %s" % (lines[0], param_desc_all)

                else:
                    for param_desc in param_pair_descs:
                        lines.append("%s: %s" % (spa, param_desc))

            xrklog.highs(lines, add_prefix=True)

        elif mode == "log":
            add_api_log(api_name, regs, param_pairs)

        else:
            raise Exception("invalid work mode: %s" % mode)

    except Exception, e:
        xrklog.error("api call log exception: %s - %s" % (api_name, e))
        xrklog.error("%s" % str(param_pairs))


# -------------------------------------------------------------------------
# ADVAPI32.DLL --> REG
# shlwapi.SHGetValueA/SHDeleteKeyA --> advapi32.xxxx
# -------------------------------------------------------------------------


def run_RegCreateKeyExA(regs):
    """
        advapi32.RegCreateKeyExA

        RegCreateKeyA-->RegCreateKeyExA-->BaseRegCreateKey/LocalBaseRegCreateKey

          _In_       HKEY                  hKey,
          _In_       LPCTSTR               lpSubKey,
          _Reserved_ DWORD                 Reserved,
          _In_opt_   LPTSTR                lpClass,
          _In_       DWORD                 dwOptions,
          _In_       REGSAM                samDesired,
          _In_opt_   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
          _Out_      PHKEY                 phkResult,
          _Out_opt_  LPDWORD               lpdwDisposition
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    reg_sub_key = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("RegCreateKeyExA", regs, {"handle": handle, "reg_sub_key": reg_sub_key})


def run_RegCreateKeyExW(regs):
    """
        advapi32.RegCreateKeyExW

        RegCreateKeyW-->RegCreateKeyExW-->BaseRegCreateKey/LocalBaseRegCreateKey

          _In_       HKEY                  hKey,
          _In_       LPCTSTR               lpSubKey,
          _Reserved_ DWORD                 Reserved,
          _In_opt_   LPTSTR                lpClass,
          _In_       DWORD                 dwOptions,
          _In_       REGSAM                samDesired,
          _In_opt_   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
          _Out_      PHKEY                 phkResult,
          _Out_opt_  LPDWORD               lpdwDisposition
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    reg_sub_key = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("RegCreateKeyExW", regs, {"handle": handle, "reg_sub_key": reg_sub_key})


def run_RegOpenKeyExA(regs):
    """
        advapi32.RegOpenKeyExA

        RegOpenKeyA-->RegOpenKeyExA-->BaseRegOpenKey/LocalBaseRegOpenKey

          _In_     HKEY    hKey,
          _In_opt_ LPCTSTR lpSubKey,
          _In_     DWORD   ulOptions,
          _In_     REGSAM  samDesired,
          _Out_    PHKEY   phkResult
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    reg_sub_key = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("RegOpenKeyExA", regs, {"handle": handle, "reg_sub_key": reg_sub_key})


def run_RegOpenKeyExW(regs):
    """
        advapi32.RegOpenKeyExW

        RegOpenKeyW-->RegOpenKeyExW-->BaseRegOpenKey/LocalBaseRegOpenKey

          _In_     HKEY    hKey,
          _In_opt_ LPCTSTR lpSubKey,
          _In_     DWORD   ulOptions,
          _In_     REGSAM  samDesired,
          _Out_    PHKEY   phkResult
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    reg_sub_key = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("RegOpenKeyExW", regs, {"handle": handle, "reg_sub_key": reg_sub_key})


def run_RegConnectRegistryW(regs):
    """
        advapi32.RegConnectRegistryW

        RegConnectRegistryA-->RegConnectRegistryW

          _In_opt_ LPCTSTR lpMachineName,
          _In_     HKEY    hKey,
          _Out_    PHKEY   phkResult
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 8)
    reg_machine = xrkutil.dbg_read_pstring(esp + 4)

    xrk_api_call("RegConnectRegistryW", regs, {"handle": handle, "reg_machine": reg_machine})


def run_RegSetValueExA(regs):
    """
        advapi32.RegSetValueExA

        RegSetValueA-->RegSetValueExA-->BaseRegSetValue/LocalBaseRegSetValue

          _In_             HKEY    hKey,
          _In_opt_         LPCTSTR lpValueName,
          _Reserved_       DWORD   Reserved,
          _In_             DWORD   dwType,
          _In_       const BYTE    *lpData,
          _In_             DWORD   cbData
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    reg_value = xrkutil.dbg_read_pstring(esp + 8)
    type_ = xrkdbg.readLong(esp + 0x10)
    pdata = xrkdbg.readLong(esp + 0x14)
    data_size = xrkdbg.readLong(esp + 0x18)
    type_str, reg_data = xrkutil.get_reg_data(type_, pdata, data_size)

    xrk_api_call("RegSetValueExA", regs, {"handle": handle, "reg_value": reg_value, "type": type_str, "reg_data": reg_data, "data_size": data_size})


def run_RegSetValueExW(regs):
    """
        advapi32.RegSetValueExW

        RegSetValueW-->RegSetValueExW-->BaseRegSetValue/LocalBaseRegSetValue

          _In_             HKEY    hKey,
          _In_opt_         LPCTSTR lpValueName,
          _Reserved_       DWORD   Reserved,
          _In_             DWORD   dwType,
          _In_       const BYTE    *lpData,
          _In_             DWORD   cbData
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    reg_value = xrkutil.dbg_read_pwstring(esp + 8)
    esp = regs["ESP"]
    type_ = xrkdbg.readLong(esp + 0x10)
    pdata = xrkdbg.readLong(esp + 0x14)
    data_size = xrkdbg.readLong(esp + 0x18)
    type_str, reg_data = xrkutil.get_reg_data_w(type_, pdata, data_size)

    xrk_api_call("RegSetValueExW", regs, {"handle": handle, "reg_value": reg_value, "type": type_str, "reg_data": reg_data, "data_size": data_size})


def run_RegDeleteKeyA(regs):
    """
        advapi32.RegDeleteKeyA

        RegDeleteKeyA-->BaseRegDeleteKey/LocalBaseRegDeleteKey

          _In_ HKEY    hKey,
          _In_ LPCTSTR lpSubKey
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    reg_sub_key = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("RegDeleteKeyA", regs, {"handle": handle, "reg_sub_key": reg_sub_key})


def run_RegDeleteKeyW(regs):
    """
        advapi32.RegDeleteKeyW

        RegDeleteKeyW-->BaseRegDeleteKey/BaseRegDeleteKey

          _In_ HKEY    hKey,
          _In_ LPCTSTR lpSubKey
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    reg_sub_key = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("RegDeleteKeyW", regs, {"handle": handle, "reg_sub_key": reg_sub_key})


def run_RegDeleteValueA(regs):
    """
        advapi32.RegDeleteValueA

        RegDeleteValueA-->BaseRegDeleteValue/LocalBaseRegDeleteValue

          _In_     HKEY    hKey,
          _In_opt_ LPCTSTR lpValueName
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    reg_value_name = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("RegDeleteValueA", regs, {"handle": handle, "reg_value_name": reg_value_name})


def run_RegDeleteValueW(regs):
    """
        advapi32.RegDeleteValueW

        RegDeleteValueW-->BaseRegDeleteValue/LocalBaseRegDeleteValue

          _In_     HKEY    hKey,
          _In_opt_ LPCTSTR lpValueName
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    reg_value_name = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("RegDeleteValueW", regs, {"handle": handle, "reg_value_name": reg_value_name})


def run_RegSaveKeyExA(regs):
    """
        advapi32.RegSaveKeyExA

        RegSaveKeyExA-->BaseRegSaveKeyEx/LocalBaseRegSaveKeyEx

          _In_     HKEY                  hKey,
          _In_     LPCTSTR               lpFile,
          _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
          _In_     DWORD                 Flags
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    file = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("RegSaveKeyExA", regs, {"handle": handle, "file": file})


def run_RegSaveKeyExW(regs):
    """
        advapi32.RegSaveKeyExW

        RegSaveKeyExW-->BaseRegSaveKeyEx/LocalBaseRegSaveKeyEx

          _In_     HKEY                  hKey,
          _In_     LPCTSTR               lpFile,
          _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
          _In_     DWORD                 Flags
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    file = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("RegSaveKeyExW", regs, {"handle": handle, "file": file})


def run_RegSaveKeyA(regs):
    """
        advapi32.RegSaveKeyA

        RegSaveKeyA-->BaseRegSaveKey/LocalBaseRegSaveKey

          _In_     HKEY                  hKey,
          _In_     LPCTSTR               lpFile,
          _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    file = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("RegSaveKeyA", regs, {"handle": handle, "file": file})


def run_RegSaveKeyW(regs):
    """
        advapi32.RegSaveKeyW

        RegSaveKeyW-->BaseRegSaveKey/LocalBaseRegSaveKey

          _In_     HKEY                  hKey,
          _In_     LPCTSTR               lpFile,
          _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    file = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("RegSaveKeyW", regs, {"handle": handle, "file": file})


def run_RegQueryInfoKeyA(regs):
    """
        advapi32.RegQueryInfoKeyA

        RegQueryInfoKeyA-->BaseRegQueryInfoKey/LocalBaseRegQueryInfoKey

          _In_        HKEY      hKey,
          _Out_opt_   LPTSTR    lpClass,
          _Inout_opt_ LPDWORD   lpcClass,
          _Reserved_  LPDWORD   lpReserved,
          _Out_opt_   LPDWORD   lpcSubKeys,
          _Out_opt_   LPDWORD   lpcMaxSubKeyLen,
          _Out_opt_   LPDWORD   lpcMaxClassLen,
          _Out_opt_   LPDWORD   lpcValues,
          _Out_opt_   LPDWORD   lpcMaxValueNameLen,
          _Out_opt_   LPDWORD   lpcMaxValueLen,
          _Out_opt_   LPDWORD   lpcbSecurityDescriptor,
          _Out_opt_   PFILETIME lpftLastWriteTime
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("RegQueryInfoKeyA", regs, {"handle": handle})


def run_RegQueryInfoKeyW(regs):
    """
        advapi32.RegQueryInfoKeyW

        RegQueryInfoKeyW-->BaseRegQueryInfoKey/LocalBaseRegQueryInfoKey

          _In_        HKEY      hKey,
          _Out_opt_   LPTSTR    lpClass,
          _Inout_opt_ LPDWORD   lpcClass,
          _Reserved_  LPDWORD   lpReserved,
          _Out_opt_   LPDWORD   lpcSubKeys,
          _Out_opt_   LPDWORD   lpcMaxSubKeyLen,
          _Out_opt_   LPDWORD   lpcMaxClassLen,
          _Out_opt_   LPDWORD   lpcValues,
          _Out_opt_   LPDWORD   lpcMaxValueNameLen,
          _Out_opt_   LPDWORD   lpcMaxValueLen,
          _Out_opt_   LPDWORD   lpcbSecurityDescriptor,
          _Out_opt_   PFILETIME lpftLastWriteTime
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("RegQueryInfoKeyW", regs, {"handle": handle})


def run_RegQueryMultipleValuesA(regs):
    """
        advapi32.RegQueryMultipleValuesA

        RegQueryMultipleValuesA-->BaseRegQueryMultipleValues/LocalBaseRegQueryMultipleValues

          _In_        HKEY    hKey,
          _Out_       PVALENT val_list,
          _In_        DWORD   num_vals,
          _Out_opt_   LPTSTR  lpValueBuf,
          _Inout_opt_ LPDWORD ldwTotsize
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("RegQueryMultipleValuesA", regs, {"handle": handle})


def run_RegQueryMultipleValuesW(regs):
    """
        advapi32.RegQueryMultipleValuesW

        RegQueryMultipleValuesW-->BaseRegQueryMultipleValues/LocalBaseRegQueryMultipleValues

          _In_        HKEY    hKey,
          _Out_       PVALENT val_list,
          _In_        DWORD   num_vals,
          _Out_opt_   LPTSTR  lpValueBuf,
          _Inout_opt_ LPDWORD ldwTotsize
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("RegQueryMultipleValuesW", regs, {"handle": handle})


def run_RegQueryValueExA(regs):
    """
        advapi32.RegQueryValueExA

        RegQueryValueA-->RegQueryValueExA-->BaseRegQueryValue/LocalBaseRegQueryValue

          _In_        HKEY    hKey,
          _In_opt_    LPCTSTR lpValueName,
          _Reserved_  LPDWORD lpReserved,
          _Out_opt_   LPDWORD lpType,
          _Out_opt_   LPBYTE  lpData,
          _Inout_opt_ LPDWORD lpcbData
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    reg_value_name = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("RegQueryValueExA", regs, {"handle": handle, "reg_value_name": reg_value_name})


def run_RegQueryValueExW(regs):
    """
        advapi32.RegQueryValueExW

        RegQueryValueW-->RegQueryValueExW-->BaseRegQueryValue/LocalBaseRegQueryValue

          _In_        HKEY    hKey,
          _In_opt_    LPCTSTR lpValueName,
          _Reserved_  LPDWORD lpReserved,
          _Out_opt_   LPDWORD lpType,
          _Out_opt_   LPBYTE  lpData,
          _Inout_opt_ LPDWORD lpcbData
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    reg_value_name = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("RegQueryValueExW", regs, {"handle": handle, "reg_value_name": reg_value_name})


def run_RegReplaceKeyA(regs):
    """
        advapi32.RegReplaceKeyA

        RegReplaceKeyA-->BaseRegReplaceKey/LocalBaseRegReplaceKey

          _In_     HKEY    hKey,
          _In_opt_ LPCTSTR lpSubKey,
          _In_     LPCTSTR lpNewFile,
          _In_     LPCTSTR lpOldFile
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    reg_sub_key = xrkutil.dbg_read_pstring(esp + 8)
    file_new = xrkutil.dbg_read_pstring(esp + 0xC)
    file_old = xrkutil.dbg_read_pstring(esp + 0x10)

    xrk_api_call("RegReplaceKeyA", regs, {"handle": handle, "reg_sub_key": reg_sub_key, "file_new": file_new, "file_old": file_old})


def run_RegReplaceKeyW(regs):
    """
        advapi32.RegReplaceKeyW

        RegReplaceKeyW-->BaseRegReplaceKey/LocalBaseRegReplaceKey

          _In_     HKEY    hKey,
          _In_opt_ LPCTSTR lpSubKey,
          _In_     LPCTSTR lpNewFile,
          _In_     LPCTSTR lpOldFile
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    reg_sub_key = xrkutil.dbg_read_pwstring(esp + 8)
    file_new = xrkutil.dbg_read_pwstring(esp + 0xC)
    file_old = xrkutil.dbg_read_pwstring(esp + 0x10)

    xrk_api_call("RegReplaceKeyW", regs, {"handle": handle, "reg_sub_key": reg_sub_key, "file_new": file_new, "file_old": file_old})


def run_RegRestoreKeyA(regs):
    """
        advapi32.RegRestoreKeyA

        RegRestoreKeyA-->BaseRegRestoreKey/LocalBaseRegRestoreKey

          _In_ HKEY    hKey,
          _In_ LPCTSTR lpFile,
          _In_ DWORD   dwFlags
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    file = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("RegRestoreKeyA", regs, {"handle": handle, "file": file})


def run_RegRestoreKeyW(regs):
    """
        advapi32.RegRestoreKeyW

        RegRestoreKeyW-->BaseRegRestoreKey/LocalBaseRegRestoreKey

          _In_ HKEY    hKey,
          _In_ LPCTSTR lpFile,
          _In_ DWORD   dwFlags
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    file = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("RegRestoreKeyW", regs, {"handle": handle, "file": file})


def run_RegEnumKeyExA(regs):
    """
        advapi32.RegEnumKeyExA

        RegEnumKeyA-->RegEnumKeyExA-->BaseRegEnumKey/LocalBaseRegEnumKey

          _In_        HKEY      hKey,
          _In_        DWORD     dwIndex,
          _Out_       LPTSTR    lpName,
          _Inout_     LPDWORD   lpcName,
          _Reserved_  LPDWORD   lpReserved,
          _Inout_     LPTSTR    lpClass,
          _Inout_opt_ LPDWORD   lpcClass,
          _Out_opt_   PFILETIME lpftLastWriteTime
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("RegEnumKeyExA", regs, {"handle": handle})


def run_RegEnumKeyW(regs):
    """
        advapi32.RegEnumKeyW

        RegEnumKeyW-->BaseRegEnumKey/LocalBaseRegEnumKey

          _In_        HKEY      hKey,
          _In_        DWORD     dwIndex,
          _Out_       LPTSTR    lpName,
          _Inout_     LPDWORD   lpcName,
          _Reserved_  LPDWORD   lpReserved,
          _Inout_     LPTSTR    lpClass,
          _Inout_opt_ LPDWORD   lpcClass,
          _Out_opt_   PFILETIME lpftLastWriteTime
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("RegEnumKeyW", regs, {"handle": handle})


def run_RegEnumKeyExW(regs):
    """
        advapi32.RegEnumKeyExW

        RegEnumKeyExW-->BaseRegEnumKey/LocalBaseRegEnumKey

          _In_        HKEY      hKey,
          _In_        DWORD     dwIndex,
          _Out_       LPTSTR    lpName,
          _Inout_     LPDWORD   lpcName,
          _Reserved_  LPDWORD   lpReserved,
          _Inout_     LPTSTR    lpClass,
          _Inout_opt_ LPDWORD   lpcClass,
          _Out_opt_   PFILETIME lpftLastWriteTime
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("RegEnumKeyExW", regs, {"handle": handle})


def run_RegEnumValueA(regs):
    """
        advapi32.RegEnumValueA

        RegEnumValueA-->BaseRegEnumValue/LocalBaseRegEnumValue

          _In_        HKEY    hKey,
          _In_        DWORD   dwIndex,
          _Out_       LPTSTR  lpValueName,
          _Inout_     LPDWORD lpcchValueName,
          _Reserved_  LPDWORD lpReserved,
          _Out_opt_   LPDWORD lpType,
          _Out_opt_   LPBYTE  lpData,
          _Inout_opt_ LPDWORD lpcbData
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("RegEnumValueA", regs, {"handle": handle})


def run_RegEnumValueW(regs):
    """
        advapi32.RegEnumValueW

        RegEnumValueW-->BaseRegEnumValue/LocalBaseRegEnumValue

          _In_        HKEY    hKey,
          _In_        DWORD   dwIndex,
          _Out_       LPTSTR  lpValueName,
          _Inout_     LPDWORD lpcchValueName,
          _Reserved_  LPDWORD lpReserved,
          _Out_opt_   LPDWORD lpType,
          _Out_opt_   LPBYTE  lpData,
          _Inout_opt_ LPDWORD lpcbData
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("RegEnumValueW", regs, {"handle": handle})


def run_RegLoadKeyA(regs):
    """
        advapi32.RegLoadKeyA

        RegLoadKeyA-->BaseRegLoadKey/LocalBaseRegLoadKey

          _In_     HKEY    hKey,
          _In_opt_ LPCTSTR lpSubKey,
          _In_     LPCTSTR lpFile
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    reg_sub_key = xrkutil.dbg_read_pstring(esp + 8)
    file = xrkutil.dbg_read_pstring(esp + 0xC)

    xrk_api_call("RegLoadKeyA", regs, {"handle": handle, "reg_sub_key": reg_sub_key, "file": file})


def run_RegLoadKeyW(regs):
    """
        advapi32.RegLoadKeyW

        RegLoadKeyW-->BaseRegLoadKey/LocalBaseRegLoadKey

          _In_     HKEY    hKey,
          _In_opt_ LPCTSTR lpSubKey,
          _In_     LPCTSTR lpFile
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    reg_sub_key = xrkutil.dbg_read_pwstring(esp + 8)
    file = xrkutil.dbg_read_pwstring(esp + 0xC)

    xrk_api_call("RegLoadKeyW", regs, {"handle": handle, "reg_sub_key": reg_sub_key, "file": file})


# -------------------------------------------------------------------------
# DNSAPI.DLL
# -------------------------------------------------------------------------


def run_DnsQuery_W(regs):
    """
        dnsapi.DnsQuery_W

        DnsQuery_A-->privateNarrowToWideQuery-->DnsQuery_W-->DnsXXX
        DnsQueryExA-->CombinedQueryEx-->ShimDnsQueryEx-->DnsQuery_W==>>||
        DnsQueryExW-->CombinedQueryEx==>>||
        DnsQueryExUTF8-->CombinedQueryEx==>>||

            DNS_STATUS WINAPI DnsQuery(
              _In_        PCTSTR      lpstrName,
              _In_        WORD        wType,
              _In_        DWORD       Options,
              _Inout_opt_ PVOID       pExtra,
              _Out_opt_   PDNS_RECORD *ppQueryResultsSet,
              _Out_opt_   PVOID       *pReserved
            );
    """
    esp = regs["ESP"]
    name = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("DnsQuery_W", regs, {"name": name})


def run_DnsQuery_UTF8(regs):
    """
        dnsapi.DnsQuery_UTF8

        DnsQuery_UTF8-->privateNarrowToWideQuery==>>||

            DNS_STATUS WINAPI DnsQuery(
              _In_        PCTSTR      lpstrName,
              _In_        WORD        wType,
              _In_        DWORD       Options,
              _Inout_opt_ PVOID       pExtra,
              _Out_opt_   PDNS_RECORD *ppQueryResultsSet,
              _Out_opt_   PVOID       *pReserved
            );
    """
    esp = regs["ESP"]
    name = xrkutil.dbg_read_pstring(esp + 4)

    xrk_api_call("DnsQuery_UTF8", regs, {"name": name})


# -------------------------------------------------------------------------
# WS2_32.DLL
# -------------------------------------------------------------------------


def run_WSAStartup(regs):
    """
        ws2_32.WSAStartup

          WORD wVersionRequested,
          LPWSADATA lpWSAData
    """
    xrk_api_call("WSAStartup", regs)


def run_WSACleanup(regs):
    """
        ws2_32.WSACleanup

          void
    """
    xrk_api_call("WSACleanup", regs)

"""
af:
    AF_UNSPEC       0
    AF_INET         2
    AF_IPX          6
    AF_APPLETALK    16
    AF_NETBIOS      17
    AF_INET6        23
    AF_IRDA         26
    AF_BTH          32
"""
v_dict_sock_af = {0: "AF_UNSPEC", 2: "AF_INET", 6: "AF_IPX", 16: "AF_APPLETALK", 17: "AF_NETBIOS", 23: "AF_INET6", 26: "AF_IRDA", 32: "AF_BTH"}
"""
type:
    SOCK_STREAM     1
    SOCK_DGRAM      2
    SOCK_RAW        3
    SOCK_RDM        4
    SOCK_SEQPACKET  5
"""
v_dict_sock_type = {1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW", 4: "SOCK_RDM", 5: "SOCK_SEQPACKET"}
"""
protocol:
    IPPROTO_RAW     0
    IPPROTO_ICMP    1
    IPPROTO_IGMP    2
    BTHPROTO_RFCOMM 3
    IPPROTO_TCP     6
    IPPROTO_UDP     17
    IPPROTO_ICMPV6  58
    IPPROTO_RM      113
"""
v_dict_sock_protocol = {0: "IPPROTO_RAW", 1: "IPPROTO_ICMP", 2: "IPPROTO_IGMP", 3: "BTHPROTO_RFCOMM", 6: "IPPROTO_TCP", 17: "IPPROTO_UDP", 58: "IPPROTO_ICMPV6", 113: "IPPROTO_RM"}


def run_socket(regs):
    """
        ws2_32.socket

          _In_ int af,
          _In_ int type,
          _In_ int protocol
    """
    esp = regs["ESP"]
    af = xrkdbg.readLong(esp + 4)
    type_ = xrkdbg.readLong(esp + 8)
    protocol = xrkdbg.readLong(esp + 0xC)

    af_str = af not in v_dict_sock_af and ("%X" % af) or v_dict_sock_af[af]
    type_str = type_ not in v_dict_sock_type and ("%X" % type_) or v_dict_sock_type[type_]
    protocol_str = protocol not in v_dict_sock_protocol and ("%X" % protocol) or v_dict_sock_protocol[protocol]

    xrk_api_call("socket", regs, {"af": af_str, "type": type_str, "protocol": protocol_str})

    k_connect = __get_api_config("socket")
    if k_connect["cmn"].is_always_success:
        socket_end_addr_list = xrkdbg.getFunctionEnd(regs["EIP"])
        # xp sp3
        assert len(socket_end_addr_list) == 1
        end_addr = socket_end_addr_list[0]
        xrkhook.install_hook_to_modify_reg_only(end_addr, "EAX", 0, "force socket to success", is_one_shot=True)
        xrklog.high("install ret hook to force api socket success", verbose=True)


def run_WSASocketW(regs):
    """
        ws2_32.WSASocketW

        socket-->WSASocketW
        WSASocketA-->WSASocketW

          _In_ int                af,
          _In_ int                type,
          _In_ int                protocol,
          _In_ LPWSAPROTOCOL_INFO lpProtocolInfo,
          _In_ GROUP              g,
          _In_ DWORD              dwFlags
    """
    #
    # socket(xp sp3):
    # 71A24211 mov  edi, edi
    # ...
    # 71A2425C call _WSASocketW@24 ;
    # ...
    #
    is_from_socket = __filter_caller_fast("socket", 0x4B)

    if not is_from_socket:
        esp = regs["ESP"]
        af = xrkdbg.readLong(esp + 4)
        type_ = xrkdbg.readLong(esp + 8)
        protocol = xrkdbg.readLong(esp + 0xC)

        af_str = af in v_dict_sock_af and ("%X" % af) or v_dict_sock_af[af]
        type_str = type_ in v_dict_sock_type and ("%X" % type_) or v_dict_sock_type[type_]
        protocol_str = protocol in v_dict_sock_protocol and ("%X" % protocol) or v_dict_sock_protocol[protocol]

        xrk_api_call("WSASocketW", regs, {"af": af_str, "type": type_str, "protocol": protocol_str})

        k_WSASocketW = __get_api_config("WSASocketW")
        if k_WSASocketW["cmn"].is_always_success:
            socket_end_addr_list = xrkdbg.getFunctionEnd(regs["EIP"])
            # xp sp3
            assert len(socket_end_addr_list) == 1
            end_addr = socket_end_addr_list[0]
            xrkhook.install_hook_to_modify_reg_only(end_addr, "EAX", 0, "force WSASocketW to success", is_one_shot=True)
            xrklog.high("install ret hook to force api WSASocketW success", verbose=True)


def run_closesocket(regs):
    """
        ws2_32.closesocket

          _In_ SOCKET s
    """
    xrk_api_call("closesocket", regs)


def run_getnameinfo(regs):
    """
        ws2_32.getnameinfo

          _In_  const struct sockaddr FAR *sa,
          _In_  socklen_t                 salen,
          _Out_ char FAR                  *host,
          _In_  DWORD                     hostlen,
          _Out_ char FAR                  *serv,
          _In_  DWORD                     servlen,
          _In_  int                       flags
    """
    xrk_api_call("getnameinfo", regs)


def run_GetNameInfoW(regs):
    """
        ws2_32.GetNameInfoW

          _In_  const SOCKADDR  *pSockaddr,
          _In_        socklen_t SockaddrLength,
          _Out_       PWCHAR    pNodeBuffer,
          _In_        DWORD     NodeBufferSize,
          _Out_       PWCHAR    pServiceBuffer,
          _In_        DWORD     ServiceBufferSize,
          _In_        INT       Flags
    """
    xrk_api_call("GetNameInfoW", regs)


def run_getsockname(regs):
    """
        ws2_32.getsockname

          SOCKET s,
          struct sockaddr FAR* name,
          int FAR* namelen
    """
    esp = regs["ESP"]
    p_addr = xrkdbg.readLong(esp + 0x8)
    ip_str, ip_value, port = xrkutil.parse_sockaddr(p_addr)

    xrk_api_call("getsockname", regs, {"sock_name": ("%s:%d" % (ip_str, port))})


def run_getpeername(regs):
    """
        ws2_32.getpeername

          _In_    SOCKET          s,
          _Out_   struct sockaddr *name,
          _Inout_ int             *namelen
    """
    xrk_api_call("getpeername", regs)


def run_gethostname(regs):
    """
        ws2_32.gethostname

          _Out_ char *name,
          _In_  int  namelen
    """
    xrk_api_call("gethostname", regs)


def run_gethostbyaddr(regs):
    """
        ws2_32.gethostbyaddr

          _In_ const char *addr,
          _In_       int  len,
          _In_       int  type
    """
    esp = regs["ESP"]
    addr = xrkutil.dbg_read_pstring(esp + 4)

    xrk_api_call("gethostbyaddr", regs, {"addr": addr})


def run_gethostbyname(regs):
    """
        ws2_32.gethostbyname

          _In_ const char *name
    """
    esp = regs["ESP"]
    ws2_32_host_name = xrkutil.dbg_read_pstring(esp + 4)

    xrk_api_call("gethostbyname", regs, {"ws2_32_host_name": ws2_32_host_name})


def run_getaddrinfo(regs):
    """
        ws2_32.getaddrinfo

          _In_opt_       PCSTR      pNodeName,
          _In_opt_       PCSTR      pServiceName,
          _In_opt_ const ADDRINFOA  *pHints,
          _Out_          PADDRINFOA *ppResult
    """
    esp = regs["ESP"]
    ws2_32_node_name = xrkutil.dbg_read_pstring(esp + 4)
    ws2_32_svc_name = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("getaddrinfo", regs, {"ws2_32_node_name": ws2_32_node_name, "ws2_32_svc_name": ws2_32_svc_name})


def run_GetAddrInfoW(regs):
    """
        ws2_32.GetAddrInfoW

          _In_opt_  PCWSTR pNodeName,
          _In_opt_  PCWSTR pServiceName,
          _In_opt_  const ADDRINFOW *pHints,
          _Out_     PADDRINFOW *ppResult
    """
    esp = regs["ESP"]
    ws2_32_node_name = xrkutil.dbg_read_pwstring(esp + 4)
    ws2_32_svc_name = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("GetAddrInfoW", regs, {"ws2_32_node_name": ws2_32_node_name, "ws2_32_svc_name": ws2_32_svc_name})


def run_freeaddrinfo(regs):
    """
        ws2_32.freeaddrinfo

          _In_ struct addrinfo *ai
    """
    xrk_api_call("freeaddrinfo", regs)


def run_bind(regs):
    """
        ws2_32.bind

          _In_ SOCKET                s,
          _In_ const struct sockaddr *name,
          _In_ int                   namelen
    """
    esp = regs["ESP"]
    p_addr = xrkdbg.readLong(esp + 0x8)
    ip_str, ip_value, port = xrkutil.parse_sockaddr(p_addr)

    xrk_api_call("bind", regs, {"sock_addr": ("%s:%d" % (ip_str, port))})


def run_listen(regs):
    """
        ws2_32.listen

          _In_ SOCKET s,
          _In_ int    backlog
    """
    xrk_api_call("listen", regs)


def run_WSAAccept(regs):
    """
        ws2_32.WSAAccept

        accept-->WSAAccept

          _In_    SOCKET          s,
          _Out_   struct sockaddr *addr,
          _Inout_ LPINT           addrlen,
          _In_    LPCONDITIONPROC lpfnCondition,
          _In_    DWORD_PTR       dwCallbackData
    """
    xrk_api_call("WSAAccept", regs)


def run_connect(regs):
    """
        ws2_32.connect

          SOCKET s,
          const struct sockaddr FAR* name,
          int namelen
    """
    esp = regs["ESP"]
    p_addr = xrkdbg.readLong(esp + 8)
    ip_str, ip_value, port = xrkutil.parse_sockaddr(p_addr)

    ws2_32_tar_addr = "%s:%d" % (ip_str, port)
    xrk_api_call("connect", regs, {"ws2_32_tar_addr": ws2_32_tar_addr})

    k_connect = __get_api_config("connect")

    if k_connect["is_redirect"] or (k_connect["cdl_redirect"] is not None and k_connect["cdl_redirect"](regs)):
        xrkutil.replace_sockaddr(p_addr, k_connect["redirect_ip"], port)

    if k_connect["cmn"].is_always_success:
        connect_end_addr = xrkdbg.getFunctionEnd(regs["EIP"])
        # xp sp3
        assert len(connect_end_addr) == 1
        xrkhook.install_hook_to_modify_reg_only(connect_end_addr[0], "EAX", 0, "force connect ret success", is_one_shot=True)


def run_WSAConnect(regs):
    """
        ws2_32.WSAConnect

          _In_  SOCKET                s,
          _In_  const struct sockaddr *name,
          _In_  int                   namelen,
          _In_  LPWSABUF              lpCallerData,
          _Out_ LPWSABUF              lpCalleeData,
          _In_  LPQOS                 lpSQOS,
          _In_  LPQOS                 lpGQOS
    """
    esp = regs["ESP"]
    p_addr = xrkdbg.readLong(esp + 8)
    ip_str, ip_value, port = xrkutil.parse_sockaddr(p_addr)

    ws2_32_tar_addr = "%s:%d" % (ip_str, port)
    xrk_api_call("WSAConnect", regs, {"ws2_32_tar_addr": ws2_32_tar_addr})

    k_WSAConnect = __get_api_config("WSAConnect")
    if k_WSAConnect["is_redirect"] or (k_WSAConnect["cdl_redirect"] is not None and k_WSAConnect["cdl_redirect"](regs)):
        xrkutil.replace_sockaddr(p_addr, k_WSAConnect["redirect_ip"], port)


def run_send(regs):
    """
        ws2_32.send

          _In_       SOCKET s,
          _In_ const char   *buf,
          _In_       int    len,
          _In_       int    flags
    """
    esp = regs["ESP"]
    addr = xrkdbg.readLong(esp + 8)
    send_len = xrkdbg.readLong(esp + 12)

    xrk_api_call("send", regs, {"addr": addr, "send_len": send_len})

    k_send = __get_api_config("send")
    if k_send["is_pt_send"]:
        xrkutil.pt_addr_to_str_with_0x_with_decode_rows(addr, send_len, comment="send data:")
    if k_send["cmn"].is_always_success:
        send_end_addr_list = xrkdbg.getFunctionEnd(regs["EIP"])
        # xp sp3
        assert len(send_end_addr_list) == 1
        end_addr = send_end_addr_list[0]
        # fake all bytes sent success
        xrkhook.install_hook_to_modify_reg_only(end_addr, "EAX", send_len, "force send to success", is_one_shot=True)
        xrklog.high("install ret hook to force api send success", verbose=True)


def run_sendto(regs):
    """
        ws2_32.sendto

          _In_       SOCKET                s,
          _In_ const char                  *buf,
          _In_       int                   len,
          _In_       int                   flags,
          _In_       const struct sockaddr *to,
          _In_       int                   tolen
    """
    esp = regs["ESP"]
    addr = xrkdbg.readLong(esp + 8)
    send_len = xrkdbg.readLong(esp + 12)

    xrk_api_call("sendto", regs, {"addr": addr, "send_len": send_len})

    k_sendto = __get_api_config("sendto")
    if k_sendto["is_pt_send"]:
        xrkutil.pt_addr_to_str_with_0x_with_decode_rows(addr, send_len, comment="sendto data:")
    if k_sendto["cmn"].is_always_success:
        send_end_addr_list = xrkdbg.getFunctionEnd(regs["EIP"])
        # xp sp3
        assert len(send_end_addr_list) == 1
        end_addr = send_end_addr_list[0]
        # fake all bytes sent success
        xrkhook.install_hook_to_modify_reg_only(end_addr, "EAX", send_len, "force sendto to success", is_one_shot=True)
        xrklog.high("install ret hook to force api sendto success", verbose=True)


def run_WSASend(regs):
    """
        ws2_32.WSASend

          _In_  SOCKET                             s,
          _In_  LPWSABUF                           lpBuffers,
          _In_  DWORD                              dwBufferCount,
          _Out_ LPDWORD                            lpNumberOfBytesSent,
          _In_  DWORD                              dwFlags,
          _In_  LPWSAOVERLAPPED                    lpOverlapped,
          _In_  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    """
    """
    esp = regs["ESP"]
    addr = xrkdbg.readLong(esp + 8)
    buf_cnt = xrkdbg.readLong(esp + 12)
    for i in range(buf_cnt):
        pass
    """
    xrk_api_call("WSASend", regs)


def run_WSASendTo(regs):
    """
        ws2_32.WSASendTo

          _In_  SOCKET                             s,
          _In_  LPWSABUF                           lpBuffers,
          _In_  DWORD                              dwBufferCount,
          _Out_ LPDWORD                            lpNumberOfBytesSent,
          _In_  DWORD                              dwFlags,
          _In_  const struct sockaddr              *lpTo,
          _In_  int                                iToLen,
          _In_  LPWSAOVERLAPPED                    lpOverlapped,
          _In_  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    """
    """
    esp = regs["ESP"]
    buf = xrkdbg.readLong(esp + 8)
    len_ = xrkdbg.readLong(esp + 12)
    """
    xrk_api_call("WSASendTo", regs)


def run_WSASendDisconnect(regs):
    """
        ws2_32.WSASendDisconnect

          _In_  SOCKET s,
          _In_  LPWSABUF lpOutboundDisconnectData
    """
    xrk_api_call("WSASendDisconnect", regs)


def run_recv_retn(regs, api_name, old_regs, buf, flags):
    """
        recv retn
    """
    recv_len = regs["EAX"]
    if recv_len != 0xFFFFFFFF and recv_len > 0:

        recv_buf = xrkdbg.readMemory(buf, recv_len)
        # we use old_regs from recv/recvfrom
        xrk_api_call(api_name, old_regs, {"recv_buf": xrkutil.buf_to_str(recv_buf), "recv_len": recv_len})

    else:
        xrk_api_call(api_name, old_regs, {"recv_len": 0})

    if "recv_RETN" in xrkdbg.listHooks():
        xrkdbg.remove_hook("recv_RETN")


def run_recv(regs):
    """
        ws2_32.recv

          _In_   SOCKET s,
          _Out_  char *buf,
          _In_   int len,
          _In_   int flags
    """
    esp = regs["ESP"]
    buf = xrkdbg.readLong(esp + 8)
    # len_ = xrkdbg.readLong(esp + 0xC)
    flags = xrkdbg.readLong(esp + 0x10)

    # TODO: we shall be able to fill this buffer by our own, and even jmp to retn.

    if "recv_RETN" not in xrkdbg.listHooks():

        retn_addrs = xrkdbg.getFunctionEnd(regs["EIP"])
        # xp sp3
        assert len(retn_addrs) == 1

        xrkmonctrl.install_addr_hook_ex(retn_addrs[0], "recv_RETN", run_recv_retn, shall_pause=False, param1="recv", param2=regs, param3=buf, param4=flags)


def run_recvfrom(regs):
    """
        ws2_32.recvfrom

          _In_        SOCKET          s,
          _Out_       char            *buf,
          _In_        int             len,
          _In_        int             flags,
          _Out_       struct sockaddr *from,
          _Inout_opt_ int             *fromlen
    """
    esp = regs["ESP"]
    buf = xrkdbg.readLong(esp + 8)
    # len_ = xrkdbg.readLong(esp + 0xC)
    flags = xrkdbg.readLong(esp + 0x10)

    if "recvfrom_RETN" not in xrkdbg.listHooks():

        retn_addrs = xrkdbg.getFunctionEnd(regs["EIP"])
        # xp sp3
        assert len(retn_addrs) == 1

        xrkmonctrl.install_addr_hook_ex(retn_addrs[0], "recvfrom_RETN", run_recv_retn, shall_pause=False, param1="recvfrom", param2=regs, param3=buf, param4=flags)


def run_WSARecv(regs):
    """
        ws2_32.WSARecv

          _In_    SOCKET                             s,
          _Inout_ LPWSABUF                           lpBuffers,
          _In_    DWORD                              dwBufferCount,
          _Out_   LPDWORD                            lpNumberOfBytesRecvd,
          _Inout_ LPDWORD                            lpFlags,
          _In_    LPWSAOVERLAPPED                    lpOverlapped,
          _In_    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    """
    xrk_api_call("WSARecv", regs)


def run_WSARecvFrom(regs):
    """
        ws2_32.WSARecvFrom

          _In_    SOCKET                             s,
          _Inout_ LPWSABUF                           lpBuffers,
          _In_    DWORD                              dwBufferCount,
          _Out_   LPDWORD                            lpNumberOfBytesRecvd,
          _Inout_ LPDWORD                            lpFlags,
          _Out_   struct sockaddr                    *lpFrom,
          _Inout_ LPINT                              lpFromlen,
          _In_    LPWSAOVERLAPPED                    lpOverlapped,
          _In_    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    """
    xrk_api_call("WSARecvFrom", regs)


def run_WSARecvDisconnect(regs):
    """
        ws2_32.WSARecvDisconnect

          _In_  SOCKET   s,
          _Out_ LPWSABUF lpInboundDisconnectData
    """
    xrk_api_call("WSARecvDisconnect", regs)


def run_select(regs):
    """
        ws2_32.select

        select-->DSOCKET::GetCountedDSocketFromSocket/...

          _In_    int                  nfds,
          _Inout_ fd_set               *readfds,
          _Inout_ fd_set               *writefds,
          _Inout_ fd_set               *exceptfds,
          _In_    const struct timeval *timeout
    """
    xrk_api_call("select", regs)

    k_select = __get_api_config("select")
    if k_select["cmn"].is_always_success:
        select_end_addr_list = xrkdbg.getFunctionEnd(regs["EIP"])
        # xp sp3
        assert len(select_end_addr_list) == 1
        end_addr = select_end_addr_list[0]
        # return "True" value
        xrkhook.install_hook_to_modify_reg_only(end_addr, "EAX", 1, "force select to success", is_one_shot=True)
        xrklog.high("install ret hook to force api select success", verbose=True)


def run_setsockopt(regs):
    """
        ws2_32.setsockopt

        setsockopt-->DSOCKET::GetCountedDSocketFromSocket/...

          _In_       SOCKET s,
          _In_       int    level,
          _In_       int    optname,
          _In_ const char   *optval,
          _In_       int    optlen
    """
    xrk_api_call("setsockopt", regs)

    k_setsockopt = __get_api_config("setsockopt")
    if k_setsockopt["cmn"].is_always_success:
        setsockopt_end_addr_list = xrkdbg.getFunctionEnd(regs["EIP"])
        # xp sp3
        assert len(setsockopt_end_addr_list) == 1
        end_addr = setsockopt_end_addr_list[0]
        xrkhook.install_hook_to_modify_reg_only(end_addr, "EAX", 0, "force setsockopt to success", is_one_shot=True)
        xrklog.high("install ret hook to force api setsockopt success", verbose=True)


# -------------------------------------------------------------------------
# WININET.DLL
# -------------------------------------------------------------------------


def run_InternetOpenA(regs):
    """
        wininet.InternetOpenA

        InternetOpenW-->InternetOpenA

          _In_ LPCTSTR lpszAgent,
          _In_ DWORD   dwAccessType,
          _In_ LPCTSTR lpszProxyName,
          _In_ LPCTSTR lpszProxyBypass,
          _In_ DWORD   dwFlags
    """
    esp = regs["ESP"]
    internet_agent = xrkutil.dbg_read_pstring(esp + 4)
    internet_proxy_name = xrkutil.dbg_read_pstring(esp + 0xC)
    internet_proxy_pwd = xrkutil.dbg_read_pstring(esp + 0x10)

    xrk_api_call("InternetOpenA", regs, {"internet_agent": internet_agent, "internet_proxy_name": internet_proxy_name, "internet_proxy_pwd": internet_proxy_pwd})


def run_InternetFindNextFileA(regs):
    """
        wininet.InternetFindNextFileA

        InternetFindNextFileW-->InternetFindNextFileA-->InternalInternetFindNextFileA

          _In_  HINTERNET hFind,
          _Out_ LPVOID    lpvFindData
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("InternetFindNextFileA", regs, {"handle": handle})


def run_InternetConnectA(regs):
    """
        wininet.InternetConnectA

        InternetConnectW-->InternetConnectA-->FtpConnect/HttpConnect

          _In_ HINTERNET     hInternet,
          _In_ LPCTSTR       lpszServerName,
          _In_ INTERNET_PORT nServerPort,
          _In_ LPCTSTR       lpszUsername,
          _In_ LPCTSTR       lpszPassword,
          _In_ DWORD         dwService,
          _In_ DWORD         dwFlags,
          _In_ DWORD_PTR     dwContext
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    internet_svr = xrkutil.dbg_read_pstring(esp + 8)
    internet_user_name = xrkutil.dbg_read_pstring(esp + 0x10)
    internet_user_pwd = xrkutil.dbg_read_pstring(esp + 0x14)

    xrk_api_call("InternetConnectA", regs, {"handle": handle, "internet_svr": internet_svr, "internet_user_name": internet_user_name, "internet_user_pwd": internet_user_pwd})


def run_InternetCrackUrlA(regs):
    """
        wininet.InternetCrackUrlA

        InternetCrackUrlW-->InternetCrackUrlA-->CrackUrl

          _In_    LPCTSTR          lpszUrl,
          _In_    DWORD            dwUrlLength,
          _In_    DWORD            dwFlags,
          _Inout_ LPURL_COMPONENTS lpUrlComponents
    """
    esp = regs["ESP"]
    internet_url = xrkutil.dbg_read_pstring(esp + 4)

    xrk_api_call("InternetCrackUrlA", regs, {"internet_url": internet_url})


def run_InternetOpenUrlA(regs):
    """
        wininet.InternetOpenUrlA

        InternetOpenUrlW-->InternetOpenUrlA

          _In_ HINTERNET hInternet,
          _In_ LPCTSTR   lpszUrl,
          _In_ LPCTSTR   lpszHeaders,
          _In_ DWORD     dwHeadersLength,
          _In_ DWORD     dwFlags,
          _In_ DWORD_PTR dwContext
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    internet_url = xrkutil.dbg_read_pstring(esp + 8)
    internet_headers = xrkutil.dbg_read_pstring(esp + 0xC)

    xrk_api_call("InternetOpenUrlA", regs, {"handle": handle, "internet_url": internet_url, "internet_headers": internet_headers})


def run_InternetGetCookieExW(regs):
    """
        wininet.InternetGetCookieExW

        InternetGetCookieA-->InternetGetCookieExA-->InternetGetCookieExW->InternetGetCookieEx2
        InternetGetCookieW-->InternetGetCookieExW==>>||

          _In_        LPCTSTR lpszURL,
          _In_        LPCTSTR lpszCookieName,
          _Inout_opt_ LPTSTR  lpszCookieData,
          _Inout_     LPDWORD lpdwSize,
          _In_        DWORD   dwFlags,
          _In_        LPVOID  lpReserved
    """
    esp = regs["ESP"]
    internet_url = xrkutil.dbg_read_pwstring(esp + 4)
    internet_cookie = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("InternetGetCookieExW", regs, {"internet_url": internet_url, "internet_cookie": internet_cookie})


def run_InternetSetCookieA(regs):
    """
        wininet.InternetSetCookieA

        InternetSetCookieW-->InternetSetCookieA-->InternalInternetSetCookie

          _In_ LPCTSTR lpszUrl,
          _In_ LPCTSTR lpszCookieName,
          _In_ LPCTSTR lpszCookieData
    """
    esp = regs["ESP"]
    internet_url = xrkutil.dbg_read_pstring(esp + 4)
    internet_c_name = xrkutil.dbg_read_pstring(esp + 8)
    internet_c_data = xrkutil.dbg_read_pstring(esp + 12)

    xrk_api_call("InternetSetCookieA", regs, {"internet_url": internet_url, "internet_cookie_name": internet_c_name, "internet_cookie_data": internet_c_data})


def run_InternetSetCookieExA(regs):
    """
        wininet.InternetSetCookieExA

        InternetSetCookieExA-->InternalInternetSetCookie

          _In_ LPCTSTR   lpszURL,
          _In_ LPCTSTR   lpszCookieName,
          _In_ LPCTSTR   lpszCookieData,
          _In_ DWORD     dwFlags,
          _In_ DWORD_PTR dwReserved
    """
    esp = regs["ESP"]
    internet_url = xrkutil.dbg_read_pstring(esp + 4)
    internet_c_name = xrkutil.dbg_read_pstring(esp + 8)
    internet_c_data = xrkutil.dbg_read_pstring(esp + 12)

    xrk_api_call("InternetSetCookieExA", regs, {"internet_url": internet_url, "internet_cookie_name": internet_c_name, "internet_cookie_data": internet_c_data})


def run_InternetSetCookieExW(regs):
    """
        wininet.InternetSetCookieExW

        InternetSetCookieExW-->InternalInternetSetCookie

          _In_ LPCTSTR   lpszURL,
          _In_ LPCTSTR   lpszCookieName,
          _In_ LPCTSTR   lpszCookieData,
          _In_ DWORD     dwFlags,
          _In_ DWORD_PTR dwReserved
    """
    esp = regs["ESP"]
    internet_url = xrkutil.dbg_read_pwstring(esp + 4)
    internet_c_name = xrkutil.dbg_read_pwstring(esp + 8)
    internet_c_data = xrkutil.dbg_read_pwstring(esp + 12)

    xrk_api_call("InternetSetCookieExW", regs, {"internet_url": internet_url, "internet_cookie_name": internet_c_name, "internet_cookie_data": internet_c_data})


def run_InternetSetCookieEx2(regs):
    """
        wininet.InternetSetCookieEx2

        InternetSetCookieEx2-->InternalInternetSetCookieEx2
    """
    xrk_api_call("InternetSetCookieEx2", regs)


def run_InternetReadFile(regs):
    """
        wininet.InternetReadFile

        InternetReadFile-->InternalInternetReadFile

          _In_  HINTERNET hFile,
          _Out_ LPVOID    lpBuffer,
          _In_  DWORD     dwNumberOfBytesToRead,
          _Out_ LPDWORD   lpdwNumberOfBytesRead
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    size = xrkdbg.readLong(esp + 0xC)

    xrk_api_call("InternetReadFile", regs, {"handle": handle, "size": size})


def run_InternetReadFileExA(regs):
    """
        wininet.InternetReadFileExA

        InternetReadFileExW-->InternetReadFileExA

          _In_  HINTERNET          hFile,
          _Out_ LPINTERNET_BUFFERS lpBuffersOut,
          _In_  DWORD              dwFlags,
          _In_  DWORD_PTR          dwContext
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    size = xrkdbg.readLong(esp + 0xC)

    xrk_api_call("InternetReadFileExA", regs, {"handle": handle, "size": size})


def run_InternetWriteFile(regs):
    """
        wininet.InternetWriteFile

        InternetWriteFile-->InternalInternetWriteFile

          _In_  HINTERNET hFile,
          _In_  LPCVOID   lpBuffer,
          _In_  DWORD     dwNumberOfBytesToWrite,
          _Out_ LPDWORD   lpdwNumberOfBytesWritten
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    buf = xrkdbg.readLong(esp + 8)
    size = xrkdbg.readLong(esp + 0xC)

    xrk_api_call("InternetWriteFile", regs, {"handle": handle, "buf": buf, "size": size})


def run_InternetAttemptConnect(regs):
    """
        wininet.InternetAttemptConnect

          _In_ DWORD dwReserved
    """
    xrk_api_call("InternetAttemptConnect", regs)


def run_InternetCanonicalizeUrlA(regs):
    """
        wininet.InternetCanonicalizeUrlA

        InternetCanonicalizeUrlA-->UrlCanonicalizeA

          _In_    LPCTSTR lpszUrl,
          _Out_   LPTSTR  lpszBuffer,
          _Inout_ LPDWORD lpdwBufferLength,
          _In_    DWORD   dwFlags
    """
    esp = regs["ESP"]
    url = xrkutil.dbg_read_pstring(esp + 4)

    xrk_api_call("InternetCanonicalizeUrlA", regs, {"url": url})


def run_InternetCanonicalizeUrlW(regs):
    """
        wininet.InternetCanonicalizeUrlW

        InternetCanonicalizeUrlW-->UrlCanonicalizeW

          _In_    LPCTSTR lpszUrl,
          _Out_   LPTSTR  lpszBuffer,
          _Inout_ LPDWORD lpdwBufferLength,
          _In_    DWORD   dwFlags
    """
    esp = regs["ESP"]
    url = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("InternetCanonicalizeUrlW", regs, {"url": url})


def run_HttpOpenRequestA(regs):
    """
        wininet.HttpOpenRequestA

        HttpOpenRequestA-->InternalHttpOpenRequestA

          _In_ HINTERNET hConnect,
          _In_ LPCTSTR   lpszVerb,
          _In_ LPCTSTR   lpszObjectName,
          _In_ LPCTSTR   lpszVersion,
          _In_ LPCTSTR   lpszReferer,
          _In_ LPCTSTR   *lplpszAcceptTypes,
          _In_ DWORD     dwFlags,
          _In_ DWORD_PTR dwContext
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    internet_verb = xrkutil.dbg_read_pstring(esp + 8, default="GET")
    internet_obj_name = xrkutil.dbg_read_pstring(esp + 0xC)
    internet_ver = xrkutil.dbg_read_pstring(esp + 0x10)
    internet_refer = xrkutil.dbg_read_pstring(esp + 0x14)

    xrk_api_call("HttpOpenRequestA", regs, {"handle": handle, "internet_verb": internet_verb, "internet_obj_name": internet_obj_name, "internet_ver": internet_ver, "internet_refer": internet_refer})


def run_HttpOpenRequestW(regs):
    """
        wininet.HttpOpenRequestW

        HttpOpenRequestW-->InternalHttpOpenRequestA

          _In_ HINTERNET hConnect,
          _In_ LPCTSTR   lpszVerb,
          _In_ LPCTSTR   lpszObjectName,
          _In_ LPCTSTR   lpszVersion,
          _In_ LPCTSTR   lpszReferer,
          _In_ LPCTSTR   *lplpszAcceptTypes,
          _In_ DWORD     dwFlags,
          _In_ DWORD_PTR dwContext
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    internet_verb = xrkutil.dbg_read_pwstring(esp + 8, default="GET")
    internet_obj_name = xrkutil.dbg_read_pwstring(esp + 0xC)
    internet_ver = xrkutil.dbg_read_pwstring(esp + 0x10)
    internet_refer = xrkutil.dbg_read_pwstring(esp + 0x14)

    xrk_api_call("HttpOpenRequestW", regs, {"handle": handle, "internet_verb": internet_verb, "internet_obj_name": internet_obj_name, "internet_ver": internet_ver, "internet_refer": internet_refer})


def run_HttpSendRequestA(regs):
    """
        wininet.HttpSendRequestA

        HttpSendRequestA-->InternalHttpSendRequestA-->HttpWrapSendRequest

          _In_ HINTERNET hRequest,
          _In_ LPCTSTR   lpszHeaders,
          _In_ DWORD     dwHeadersLength,
          _In_ LPVOID    lpOptional,
          _In_ DWORD     dwOptionalLength
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    headers = xrkutil.dbg_read_pstring(esp + 8)
    opt = xrkutil.dbg_read_pstring(esp + 0x10)

    xrk_api_call("HttpSendRequestA", regs, {"handle": handle, "headers": headers, "opt": opt})


def run_HttpSendRequestW(regs):
    """
        wininet.HttpSendRequestW

        HttpSendRequestW-->HttpWrapSendRequest

          _In_ HINTERNET hRequest,
          _In_ LPCTSTR   lpszHeaders,
          _In_ DWORD     dwHeadersLength,
          _In_ LPVOID    lpOptional,
          _In_ DWORD     dwOptionalLength
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    internet_headers = xrkutil.dbg_read_pwstring(esp + 8)
    internet_opt = xrkutil.dbg_read_pwstring(esp + 0x10)

    xrk_api_call("HttpSendRequestW", regs, {"handle": handle, "internet_headers": internet_headers, "internet_opt": internet_opt})


def run_HttpSendRequestExA(regs):
    """
        wininet.HttpSendRequestExA

        HttpSendRequestExA-->HttpWrapSendRequest

          _In_  HINTERNET          hRequest,
          _In_  LPINTERNET_BUFFERS lpBuffersIn,
          _Out_ LPINTERNET_BUFFERS lpBuffersOut,
          _In_  DWORD              dwFlags,
          _In_  DWORD_PTR          dwContext
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("HttpSendRequestExA", regs, {"handle": handle})


def run_HttpSendRequestExW(regs):
    """
        wininet.HttpSendRequestExW

        HttpSendRequestExW-->HttpWrapSendRequest

          _In_  HINTERNET          hRequest,
          _In_  LPINTERNET_BUFFERS lpBuffersIn,
          _Out_ LPINTERNET_BUFFERS lpBuffersOut,
          _In_  DWORD              dwFlags,
          _In_  DWORD_PTR          dwContext
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("HttpSendRequestExW", regs, {"handle": handle})


def run_HttpAddRequestHeadersA(regs):
    """
        wininet.HttpAddRequestHeadersA

        HttpAddRequestHeadersW-->HttpAddRequestHeadersA-->wHttpAddRequestHeaders

          _In_ HINTERNET hRequest,
          _In_ LPCTSTR   lpszHeaders,
          _In_ DWORD     dwHeadersLength,
          _In_ DWORD     dwModifiers
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    internet_headers = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("HttpAddRequestHeadersA", regs, {"handle": handle, "internet_headers": internet_headers})


def run_HttpWebSocketReceive(regs):
    """
        wininet.HttpWebSocketReceive

        HttpWebSocketReceive-->InternalWebSocketReceive
    """
    xrk_api_call("HttpWebSocketReceive", regs)


def run_HttpWebSocketSend(regs):
    """
        wininet.HttpWebSocketSend

        HttpWebSocketSend-->InternalWebSocketSend
    """
    xrk_api_call("HttpWebSocketSend", regs)


# -------------------------------------------------------------------------
# WINHTTP.DLL
# -------------------------------------------------------------------------


def run_WinHttpOpen(regs):
    """
        winhttp.WinHttpOpen

        WinHttpOpen-->winhttp.InternetOpenA

          _In_opt_ LPCWSTR pwszUserAgent,
          _In_     DWORD   dwAccessType,
          _In_     LPCWSTR pwszProxyName,
          _In_     LPCWSTR pwszProxyBypass,
          _In_     DWORD   dwFlags
    """
    esp = regs["ESP"]
    user_agent = xrkutil.dbg_read_pwstring(esp + 4)
    proxy_name = xrkutil.dbg_read_pwstring(esp + 0xC)
    proxy_pwd = xrkutil.dbg_read_pwstring(esp + 0x10)

    xrk_api_call("WinHttpOpen", regs, {"user_agent": user_agent, "proxy_name": proxy_name, "proxy_pwd": proxy_pwd})


def run_WinHttpCloseHandle(regs):
    """
        winhttp.WinHttpCloseHandle

        WinHttpCloseHandle-->DereferenceObject

          _In_ HINTERNET hInternet
    """
    xrk_api_call("WinHttpCloseHandle", regs)


def run_WinHttpConnect(regs):
    """
        winhttp.WinHttpConnect

        WinHttpConnect-->winhttp.InternetConnectA

          _In_       HINTERNET     hSession,
          _In_       LPCWSTR       pswzServerName,
          _In_       INTERNET_PORT nServerPort,
          _Reserved_ DWORD         dwReserved
    """
    esp = regs["ESP"]
    svr_name = xrkutil.dbg_read_pwstring(esp + 8)
    svr_port = xrkdbg.readLong(esp + 0xC)

    xrk_api_call("WinHttpConnect", regs, {"svr_name": svr_name, "svr_port": svr_port})


def run_WinHttpOpenRequest(regs):
    """
        winhttp.WinHttpOpenRequest

        WinHttpOpenRequest-->winhttp.HttpOpenRequestA

          _In_ HINTERNET hConnect,
          _In_ LPCWSTR   pwszVerb,
          _In_ LPCWSTR   pwszObjectName,
          _In_ LPCWSTR   pwszVersion,
          _In_ LPCWSTR   pwszReferrer,
          _In_ LPCWSTR   *ppwszAcceptTypes,
          _In_ DWORD     dwFlags
    """
    esp = regs["ESP"]
    verb = xrkutil.dbg_read_pwstring(esp + 8)
    obj_name = xrkutil.dbg_read_pwstring(esp + 0xC)
    ver = xrkutil.dbg_read_pwstring(esp + 0x10)
    refer = xrkutil.dbg_read_pwstring(esp + 0x14)
    p_accept_type = xrkdbg.readLong(esp + 0x18)
    accept_type = xrkutil.dbg_read_pwstring(p_accept_type)

    xrk_api_call("WinHttpOpenRequest", regs, {"verb": verb, "obj_name": obj_name, "ver": ver, "refer": refer, "accept_type": accept_type})


def run_WinHttpSendRequest(regs):
    """
        winhttp.WinHttpSendRequest

        WinHttpSendRequest-->winhttp.HttpWrapSendRequest

          _In_     HINTERNET hRequest,
          _In_opt_ LPCWSTR   pwszHeaders,
          _In_     DWORD     dwHeadersLength,
          _In_opt_ LPVOID    lpOptional,
          _In_     DWORD     dwOptionalLength,
          _In_     DWORD     dwTotalLength,
          _In_     DWORD_PTR dwContext
    """
    esp = regs["ESP"]
    headers = xrkutil.dbg_read_pwstring(esp + 0x8)

    xrk_api_call("WinHttpSendRequest", regs, {"headers": headers})


def run_WinHttpReceiveResponse(regs):
    """
        winhttp.WinHttpReceiveResponse

        WinHttpReceiveResponse-->winhttp.HttpWrapSendRequest

          _In_       HINTERNET hRequest,
          _Reserved_ LPVOID    lpReserved
    """
    xrk_api_call("WinHttpReceiveResponse", regs)


def run_WinHttpQueryHeaders(regs):
    """
        winhttp.WinHttpQueryHeaders

        WinHttpQueryHeaders-->winhttp.HttpQueryInfoA

          _In_     HINTERNET hRequest,
          _In_     DWORD     dwInfoLevel,
          _In_opt_ LPCWSTR   pwszName,
          _Out_    LPVOID    lpBuffer,
          _Inout_  LPDWORD   lpdwBufferLength,
          _Inout_  LPDWORD   lpdwIndex
    """
    esp = regs["ESP"]
    name = xrkutil.dbg_read_pwstring(esp + 0xC)

    xrk_api_call("WinHttpQueryHeaders", regs, {"name": name})


def run_WinHttpQueryDataAvailable(regs):
    """
        winhttp.WinHttpQueryDataAvailable

        WinHttpQueryDataAvailable-->winhttp.InternetGetThreadInfo/winhttp.InternetIndicateStatus

          _In_  HINTERNET hRequest,
          _Out_ LPDWORD   lpdwNumberOfBytesAvailable
    """
    xrk_api_call("WinHttpQueryDataAvailable", regs)


def run_WinHttpReadData(regs):
    """
        winhttp.WinHttpReadData

        WinHttpReadData-->winhttp.InternetGetThreadInfo/winhttp.CFsm_ReadFile::CFsm_ReadFile/winhttp.InternetIndicateStatus

          _In_  HINTERNET hRequest,
          _Out_ LPVOID    lpBuffer,
          _In_  DWORD     dwNumberOfBytesToRead,
          _Out_ LPDWORD   lpdwNumberOfBytesRead
    """
    xrk_api_call("WinHttpReadData", regs)


def run_WinHttpAddRequestHeaders(regs):
    """
        winhttp.WinHttpAddRequestHeaders

        WinHttpAddRequestHeaders-->winhttp.HttpAddRequestHeadersA

          _In_ HINTERNET hRequest,
          _In_ LPCWSTR   pwszHeaders,
          _In_ DWORD     dwHeadersLength,
          _In_ DWORD     dwModifiers
    """
    esp = regs["ESP"]
    headers = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("WinHttpAddRequestHeaders", regs, {"headers": headers})


def run_WinHttpCrackUrl(regs):
    """
        winhttp.WinHttpCrackUrl

        WinHttpCrackUrl-->winhttp.WinHttpCrackUrlA

          _In_    LPCWSTR          pwszUrl,
          _In_    DWORD            dwUrlLength,
          _In_    DWORD            dwFlags,
          _Inout_ LPURL_COMPONENTS lpUrlComponents
    """
    esp = regs["ESP"]
    url = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("WinHttpCrackUrl", regs, {"url": url})


def retnWinHttpCreateUrlHook(LogBpHook):
    def __init__(self, old_regs, p_ret_url):
        LogBpHook.__init__(self)
        self.old_regs = old_regs
        self.p_ret_url = p_ret_url

    def run(self, regs):
        """
            log
        """
        url = xrkutil.dbg_read_pwstring(self.p_ret_url)

        xrk_api_call("WinHttpCreateUrl", self.old_regs, {"url": url})

        self.UnHook()


def run_WinHttpCreateUrl(regs):
    """
        winhttp.WinHttpCreateUrl

        WinHttpCreateUrl-->winhttp.WinHttpCreateUrlA

          _In_    LPURL_COMPONENTS lpUrlComponents,
          _In_    DWORD            dwFlags,
          _Out_   LPWSTR           pwszUrl,
          _Inout_ LPDWORD          lpdwUrlLength
    """
    esp = regs["ESP"]
    p_ret_url = xrkdbg.readLong(esp + 0xC)

    assert "WinHttpCreateUrl_RETN" not in xrkdbg.listHooks()
    retn_addrs = xrkdbg.getFunctionEnd(regs["EIP"])
    # xp sp3
    assert len(retn_addrs) == 1
    h = retnWinHttpCreateUrlHook(regs, p_ret_url)
    h.add("WinHttpCreateUrl_RETN", retn_addrs[0])
    xrklog.high("install Retn hook to WinHttpCreateUrl at: %.8X" % (retn_addrs[0]), verbose=True)


def run_WinHttpWriteData(regs):
    """
        winhttp.WinHttpWriteData

        WinHttpWriteData-->CFsm_HttpWriteData::CFsm_HttpWriteData

          _In_  HINTERNET hRequest,
          _In_  LPCVOID   lpBuffer,
          _In_  DWORD     dwNumberOfBytesToWrite,
          _Out_ LPDWORD   lpdwNumberOfBytesWritten
    """
    esp = regs["ESP"]
    buf = xrkdbg.readLong(esp + 0x8)
    size = xrkdbg.readLong(esp + 0xC)

    xrk_api_call("WinHttpWriteData", regs, {"buf": buf, "size": size})


# -------------------------------------------------------------------------
# KERNEL32.DLL --> PROC
# -------------------------------------------------------------------------


def run_IsWow64Process(regs):
    """
        kernel32.IsWow64Process

        IsWow64Process-->NtQueryInformationProcess(ntdll)

          _In_  HANDLE hProcess,
          _Out_ PBOOL  Wow64Process
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("IsWow64Process", regs, {"handle": handle})


def run_CreateProcessW(regs):
    """
        kernel32.CreateProcessW

        CreateProcessW-->CreateProcessInternalW

          _In_opt_    LPCTSTR               lpApplicationName,
          _Inout_opt_ LPTSTR                lpCommandLine,
          _In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
          _In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
          _In_        BOOL                  bInheritHandles,
          _In_        DWORD                 dwCreationFlags,
          _In_opt_    LPVOID                lpEnvironment,
          _In_opt_    LPCTSTR               lpCurrentDirectory,
          _In_        LPSTARTUPINFO         lpStartupInfo,
          _Out_       LPPROCESS_INFORMATION lpProcessInformation
    """
    esp = regs["ESP"]
    app_name = xrkutil.dbg_read_pwstring(esp + 4)
    cmd_line = xrkutil.dbg_read_pwstring(esp + 8)
    cur_dir_ = xrkutil.dbg_read_pwstring(esp + 0x20)

    xrk_api_call("CreateProcessW", regs, {"app_name": app_name, "cmd_line": cmd_line, "cur_dir_": cur_dir_})

    flag = xrkdbg.readLong(esp + 0x18)
    if flag & 4:
        xrkutil.xrklog.highlight("create process with suspend flag, u should pay attention to this")


def run_CreateProcessInternalA(regs):
    """
        kernel32.CreateProcessInternalA

        CreateProcessA-->CreateProcessInternalA-->CreateProcessInternalW
        WinExec-->CreateProcessInternalA==>>||

          HANDLE hToken,
          LPCWSTR lpApplicationName,
          LPWSTR lpCommandLine,
          LPSECURITY_ATTRIBUTES lpProcessAttributes,
          LPSECURITY_ATTRIBUTES lpThreadAttributes,
          BOOL bInheritHandles,
          DWORD dwCreationFlags,
          LPVOID lpEnvironment,
          LPCWSTR lpCurrentDirectory,
          LPSTARTUPINFOW lpStartupInfo,
          LPPROCESS_INFORMATION lpProcessInformation,
          PHANDLE hNewToken
    """
    #
    # CreateProcessA(xp sp3)
    # 7C80236B mov  edi, edi
    # ...
    # 7C802392 call _CreateProcessInternalA@48 # 0x27
    # ...
    #
    is_from_CreateProcessA = __filter_caller_fast("CreateProcessA", 0x27)

    #
    # WinExec(xp sp3)
    # 7C8623AD mov  edi, edi
    # ...
    # 7C8623EE call _CreateProcessInternalA@48 # 0x41
    # ...
    #
    is_from_WinExec_1 = __filter_caller_fast("WinExec", 0x41)

    #
    # WinExec(xp sp3)
    # 7C8623AD mov  edi, edi
    # ...
    # 7C862440 call _CreateProcessInternalA@48 # 0x93
    # ...
    #
    is_from_WinExec_2 = __filter_caller_fast("WinExec", 0x93)

    if not is_from_CreateProcessA and not is_from_WinExec_1 and not is_from_WinExec_2:

        esp = regs["ESP"]
        handle = xrkdbg.readLong(esp + 4)
        app_name = xrkutil.dbg_read_pwstring(esp + 8)
        cmd_line = xrkutil.dbg_read_pwstring(esp + 0xC)
        cur_dir_ = xrkutil.dbg_read_pwstring(esp + 0x24)

        xrk_api_call("CreateProcessInternalA", regs, {"handle": handle, "app_name": app_name, "cmd_line": cmd_line, "cur_dir_": cur_dir_})

        flag = xrkdbg.readLong(esp + 0x1C)
        if flag & 4:
            xrkutil.xrklog.highlight("create process with suspend flag, u should pay attention to this")


def run_CreateProcessInternalW(regs):
    """
        kernel32.CreateProcessInternalW

        CreateProcessA-->CreateProcessInternalA-->CreateProcessInternalW
        CreateProcessW-->CreateProcessInternalW
        WinExec-->CreateProcessInternalA==>>||

          HANDLE hToken,
          LPCWSTR lpApplicationName,
          LPWSTR lpCommandLine,
          LPSECURITY_ATTRIBUTES lpProcessAttributes,
          LPSECURITY_ATTRIBUTES lpThreadAttributes,
          BOOL bInheritHandles,
          DWORD dwCreationFlags,
          LPVOID lpEnvironment,
          LPCWSTR lpCurrentDirectory,
          LPSTARTUPINFOW lpStartupInfo,
          LPPROCESS_INFORMATION lpProcessInformation,
          PHANDLE hNewToken
    """
    #
    # CreateProcessInternalA(xp sp3)
    # 7C81D536 push 98h
    # ...
    # 7C81D622 call _CreateProcessInternalW@48 # 0xEC
    # ...
    #
    is_from_CreateProcessInternalA = __filter_caller_fast("CreateProcessInternalA", 0xEC)

    #
    # CreateProcessW(xp sp3)
    # 7C802336 mov  edi, edi
    # ...
    # 7C80235D call _CreateProcessInternalW@48 # 0x27
    # ...
    #
    is_from_CreateProcessW = __filter_caller_fast("CreateProcessW", 0x27)

    if not is_from_CreateProcessInternalA and not is_from_CreateProcessW:

        esp = regs["ESP"]
        handle = xrkdbg.readLong(esp + 4)
        app_name = xrkutil.dbg_read_pwstring(esp + 8)
        cmd_line = xrkutil.dbg_read_pwstring(esp + 0xC)
        cur_dir_ = xrkutil.dbg_read_pwstring(esp + 0x24)

        xrk_api_call("CreateProcessInternalW", regs, {"handle": handle, "app_name": app_name, "cmd_line": cmd_line, "cur_dir_": cur_dir_})

        flag = xrkdbg.readLong(esp + 0x1C)
        if flag & 4:
            xrkutil.xrklog.highlight("create process with suspend flag, u should pay attention to this")


def run_CreateThread(regs):
    """
        kernel32.CreateThread

        CreateThread-->CreateRemoteThread==>>||

          _In_opt_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
          _In_      SIZE_T                 dwStackSize,
          _In_      LPTHREAD_START_ROUTINE lpStartAddress,
          _In_opt_  LPVOID                 lpParameter,
          _In_      DWORD                  dwCreationFlags,
          _Out_opt_ LPDWORD                lpThreadId
    """
    esp = regs["ESP"]
    cbk_proc = xrkdbg.readLong(esp + 0xC)

    xrk_api_call("CreateThread", regs, {"cbk_proc": cbk_proc})

    flag = xrkdbg.readLong(esp + 0x18)
    if flag & 4:
        xrkutil.xrklog.highlight("create thread with suspend flag, u should pay attention to this")
    cbk_thread = xrkdbg.readLong(esp + 0x10)
    xrkutil.may_update_comment(cbk_thread, "thread")

    k_CreateThread = __get_api_config("CreateThread")
    if k_CreateThread["is_log_new_thread_start"]:
        # TODO: x
        pass
    if k_CreateThread["is_bp_new_thread_start"]:
        xrkutil.may_bp(cbk_thread)


def run_CreateRemoteThread(regs):
    """
        kernel32.CreateRemoteThread

        CreateRemoteThread-->NtCreateThread(ntdll)
        CreateThread-->CreateRemoteThread==>>||

          _In_  HANDLE                 hProcess,
          _In_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
          _In_  SIZE_T                 dwStackSize,
          _In_  LPTHREAD_START_ROUTINE lpStartAddress,
          _In_  LPVOID                 lpParameter,
          _In_  DWORD                  dwCreationFlags,
          _Out_ LPDWORD                lpThreadId
    """
    #
    # CreateThread(xp sp3)
    # 7C8106C7 mov  edi, edi
    # ...
    # 7C8106E0 call _CreateRemoteThread@28 # 0x19
    # ...
    #
    is_from_CreateThread = __filter_caller_fast("CreateThread", 0x19)

    if not is_from_CreateThread:

        esp = regs["ESP"]
        handle = xrkdbg.readLong(esp + 4)
        cbk_proc = xrkdbg.readLong(esp + 0x10)

        xrk_api_call("CreateRemoteThread", regs, {"handle": handle, "cbk_proc": cbk_proc})

        flag = xrkdbg.readLong(esp + 0x18)
        if flag & 4:
            xrkutil.xrklog.highlight("create remote thread with suspend flag, u should pay attention to this")
        cbk_thread = xrkdbg.readLong(esp + 0x10)
        xrkutil.may_update_comment(cbk_thread, "thread")

        k_CreateRemoteThread = __get_api_config("CreateRemoteThread")
        if k_CreateRemoteThread["is_log_new_thread_start"]:
            # TODO: x
            pass
        if k_CreateRemoteThread["is_bp_new_thread_start"]:
            xrkutil.may_bp(cbk_thread)


def run_CreateRemoteThreadEx(regs):
    """
        kernel32.CreateRemoteThreadEx

          _In_      HANDLE                       hProcess,
          _In_opt_  LPSECURITY_ATTRIBUTES        lpThreadAttributes,
          _In_      SIZE_T                       dwStackSize,
          _In_      LPTHREAD_START_ROUTINE       lpStartAddress,
          _In_opt_  LPVOID                       lpParameter,
          _In_      DWORD                        dwCreationFlags,
          _In_opt_  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
          _Out_opt_ LPDWORD                      lpThreadId

        !+ require from Win7
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    thread_routine = xrkdbg.readLong(esp + 0x10)

    xrk_api_call("CreateRemoteThreadEx", regs, {"handle": handle, "thread_routine": thread_routine})

    flag = xrkdbg.readLong(esp + 0x18)
    if flag & 4:
        xrkutil.xrklog.highlight("create thread with suspend flag, u should pay attention to this")


def run_OpenProcess(regs):
    """
        kernel32.OpenProcess

        OpenProcess-->NtOpenProcess(ntdll)

          _In_ DWORD dwDesiredAccess,
          _In_ BOOL  bInheritHandle,
          _In_ DWORD dwProcessId
    """
    esp = regs["ESP"]
    pid = xrkdbg.readLong(esp + 0xC)

    xrk_api_call("OpenProcess", regs, {"pid": pid})


def run_TerminateProcess(regs):
    """
        kernel32.TerminateProcess

        TerminateProcess-->NtTerminateProcess(ntdll)

          _In_ HANDLE hProcess,
          _In_ UINT   uExitCode
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    code = xrkdbg.readLong(esp + 8)

    xrk_api_call("TerminateProcess", regs, {"handle": handle, "code": code})


def run_ExitProcess(regs):
    """
        kernel32.ExitProcess

        ExitProcess-->LdrShutdownProcess

          _In_ UINT uExitCode

        !+defaulted to BpHook here
    """
    esp = regs["ESP"]
    code = xrkdbg.readLong(esp + 4)

    xrk_api_call("ExitProcess", regs, {"code": code})


def run_GetExitCodeProcess(regs):
    """
        kernel32.GetExitCodeProcess

        GetExitCodeProcess-->NtQueryInformationProcess(ntdll)

          _In_   HANDLE hProcess,
          _Out_  LPDWORD lpExitCode
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("GetExitCodeProcess", regs, {"handle": handle})


def run_OpenThread(regs):
    """
        kernel32.OpenThread

        OpenThread-->NtOpenThread(ntdll)

          _In_ DWORD dwDesiredAccess,
          _In_ BOOL  bInheritHandle,
          _In_ DWORD dwThreadId
    """
    esp = regs["ESP"]
    tid = xrkdbg.readLong(esp + 0xC)

    xrk_api_call("OpenThread", regs, {"tid": tid})


def run_TerminateThread(regs):
    """
        kernel32.TerminateThread

        TerminateThread-->NtTerminateThread(ntdll)

          _Inout_ HANDLE hThread,
          _In_    DWORD  dwExitCode
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    code = xrkdbg.readLong(esp + 8)

    xrk_api_call("TerminateThread", regs, {"handle": handle, "code": code})


def run_SuspendThread(regs):
    """
        kernel32.SuspendThread

        SuspendThread-->NtSuspendThread(ntdll)

          _In_ HANDLE hThread
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("SuspendThread", regs, {"handle": handle})


def run_ResumeThread(regs):
    """
        kernel32.ResumeThread

        ResumeThread-->NtResumeThread(ntdll)

          _In_ HANDLE hThread
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("ResumeThread", regs, {"handle": handle})


def run_ExitThread(regs):
    """
        kernel32.ExitThread

        ExitThread-->LdrShutdownThread

          _In_ DWORD dwExitCode
    """
    esp = regs["ESP"]
    code = xrkdbg.readLong(esp + 4)

    xrk_api_call("ExitThread", regs, {"code": code})


def run_CreateToolhelp32Snapshot(regs):
    """
        kernel32.CreateToolhelp32Snapshot

          _In_ DWORD dwFlags,
          _In_ DWORD th32ProcessID
    """
    esp = regs["ESP"]
    pid = xrkdbg.readLong(esp + 8)

    xrk_api_call("CreateToolhelp32Snapshot", regs, {"pid": pid})


def run_Process32FirstW(regs):
    """
        kernel32.Process32FirstW

        Process32First-->Process32FirstW-->NtMapViewOfSection/NtUnmapViewOfSection(ntdll)

          _In_    HANDLE           hSnapshot,
          _Inout_ LPPROCESSENTRY32 lppe
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("Process32FirstW", regs, {"handle": handle})


def run_Process32NextW(regs):
    """
        kernel32.Process32NextW

        Process32Next-->Process32NextW-->NtMapViewOfSection/NtUnmapViewOfSection(ntdll)

          _In_  HANDLE           hSnapshot,
          _Out_ LPPROCESSENTRY32 lppe
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("Process32NextW", regs, {"handle": handle})


def run_Module32FirstW(regs):
    """
        kernel32.Module32FirstW

        Module32First-->Module32FirstW-->NtMapViewOfSection/NtUnmapViewOfSection(ntdll)

          _In_    HANDLE          hSnapshot,
          _Inout_ LPMODULEENTRY32 lpme
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("Module32FirstW", regs, {"handle": handle})


def run_Module32NextW(regs):
    """
        kernel32.Module32NextW

        Module32Next-->Module32NextW-->NtMapViewOfSection/NtUnmapViewOfSection(ntdll)

          _In_  HANDLE          hSnapshot,
          _Out_ LPMODULEENTRY32 lpme
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("Module32NextW", regs, {"handle": handle})


def run_Thread32First(regs):
    """
        kernel32.Thread32First

        Thread32First-->NtMapViewOfSection/NtUnmapViewOfSection(ntdll)

          _In_    HANDLE          hSnapshot,
          _Inout_ LPTHREADENTRY32 lpte
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("Thread32First", regs, {"handle": handle})


def run_Thread32Next(regs):
    """
        kernel32.Thread32Next

        Thread32Next-->NtMapViewOfSection/NtUnmapViewOfSection(ntdll)

          _In_  HANDLE          hSnapshot,
          _Out_ LPTHREADENTRY32 lpte
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("Thread32Next", regs, {"handle": handle})


def run_ReadProcessMemory(regs):
    """
        kernel32.ReadProcessMemory

        ReadProcessMemory-->NtReadVirtualMemory(ntdll)
        Toolhelp32ReadProcessMemory-->OpenProcess/ReadProcessMemory

          _In_  HANDLE  hProcess,
          _In_  LPCVOID lpBaseAddress,
          _Out_ LPVOID  lpBuffer,
          _In_  SIZE_T  nSize,
          _Out_ SIZE_T  *lpNumberOfBytesRead
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    base = xrkdbg.readLong(esp + 8)
    size = xrkdbg.readLong(esp + 0x10)

    xrk_api_call("ReadProcessMemory", regs, {"handle": handle, "base": base, "size": size})


def run_WriteProcessMemory(regs):
    """
        kernel32.WriteProcessMemory

        WriteProcessMemory-->NtProtectVirtualMemory/NtWriteVirtualMemory(ntdll)

          _In_  HANDLE  hProcess,
          _In_  LPVOID  lpBaseAddress,
          _In_  LPCVOID lpBuffer,
          _In_  SIZE_T  nSize,
          _Out_ SIZE_T  *lpNumberOfBytesWritten
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    base = xrkdbg.readLong(esp + 8)
    size = xrkdbg.readLong(esp + 0x10)

    xrk_api_call("WriteProcessMemory", regs, {"handle": handle, "base": base, "size": size})


# -------------------------------------------------------------------------
# FILE MAP && UNMAP
# -------------------------------------------------------------------------


def run_CreateFileMappingW(regs):
    """
        kernel32.CreateFileMappingW

        CreateFileMappingA-->CreateFileMappingW-->NtCreateSection(ntdll)

          _In_     HANDLE                hFile,
          _In_opt_ LPSECURITY_ATTRIBUTES lpAttributes,
          _In_     DWORD                 flProtect,
          _In_     DWORD                 dwMaximumSizeHigh,
          _In_     DWORD                 dwMaximumSizeLow,
          _In_opt_ LPCTSTR               lpName
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    file = xrkutil.dbg_read_pwstring(esp + 0x18)

    xrk_api_call("CreateFileMappingW", regs, {"handle": handle, "file": file})


def run_OpenFileMappingW(regs):
    """
        kernel32.OpenFileMappingW

        OpenFileMappingA-->OpenFileMappingW-->NtOpenSection(ntdll)

          _In_ DWORD   dwDesiredAccess,
          _In_ BOOL    bInheritHandle,
          _In_ LPCTSTR lpName
    """
    esp = regs["ESP"]
    file = xrkutil.dbg_read_pwstring(esp + 0xC)

    xrk_api_call("OpenFileMappingW", regs, {"file": file})


def run_MapViewOfFileEx(regs):
    """
        kernel32.MapViewOfFileEx

          _In_     HANDLE hFileMappingObject,
          _In_     DWORD  dwDesiredAccess,
          _In_     DWORD  dwFileOffsetHigh,
          _In_     DWORD  dwFileOffsetLow,
          _In_     SIZE_T dwNumberOfBytesToMap,
          _In_opt_ LPVOID lpBaseAddress
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("MapViewOfFileEx", regs, {"handle": handle})


def run_UnmapViewOfFile(regs):
    """
        kernel32.UnmapViewOfFile

        UnmapViewOfFile-->NtUnmapViewOfSection

          LPCVOID lpBaseAddress
    """
    esp = regs["ESP"]
    addr = xrkdbg.readLong(esp + 4)

    xrk_api_call("UnmapViewOfFile", regs, {"addr": addr})


# -------------------------------------------------------------------------
# FILE --> THIS SUCKS
# -------------------------------------------------------------------------

def run_CreateFileW(regs):
    """
        kernel32.CreateFileW

        CreateFileA-->CreateFileW-->NtCreateFile(ntdll)
        OpenFile-->CreateFileA==>||
        _lopen-->CreateFileA==>>||
        _lcreat-->CreateFileA==>>||

          _In_     LPCTSTR               lpFileName,
          _In_     DWORD                 dwDesiredAccess,
          _In_     DWORD                 dwShareMode,
          _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
          _In_     DWORD                 dwCreationDisposition,
          _In_     DWORD                 dwFlagsAndAttributes,
          _In_opt_ HANDLE                hTemplateFile
    """
    esp = regs["ESP"]
    file = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("CreateFileW", regs, {"file": file})


def run_ReadFile(regs):
    """
        kernel32.ReadFile

        ReadFile-->NtReadFile(ntdll)
        _lread-->ReadFile==>>||

          HANDLE hFile,
          LPVOID lpBuffer,
          DWORD nNumberOfBytesToRead,
          LPDWORD lpNumberOfBytesRead,
          LPOVERLAPPED lpOverlapped
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("ReadFile", regs, {"handle": handle})


def run_ReadFileEx(regs):
    """
        kernel32.ReadFileEx

        ReadFileEx-->NtReadFile(ntdll)

          _In_      HANDLE                          hFile,
          _Out_opt_ LPVOID                          lpBuffer,
          _In_      DWORD                           nNumberOfBytesToRead,
          _Inout_   LPOVERLAPPED                    lpOverlapped,
          _In_      LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("ReadFileEx", regs, {"handle": handle})


# -------------------------------------------------------------------------
# FILES
# -------------------------------------------------------------------------


def run_PathFileExistsA(regs):
    """
        shlwapi.PathFileExistsA

        PathFileExistsA-->GetFileAttributesA

          _In_ LPCTSTR pszPath
    """
    esp = regs["ESP"]
    path = xrkutil.dbg_read_pstring(esp + 4)

    xrk_api_call("PathFileExistsA", regs, {"path": path})


def run_PathFileExistsW(regs):
    """
        shlwapi.PathFileExistsW

        PathFileExistsW-->GetFileAttributesW

          _In_ LPCTSTR pszPath
    """
    esp = regs["ESP"]
    path = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("PathFileExistsW", regs, {"path": path})


def run_WriteFile(regs):
    """
        kernel32.WriteFile

        WriteFile-->NtWriteFile(ntdll)
        _lwrite-->WriteFile==>>||

          HANDLE hFile,
          LPCVOID lpBuffer,
          DWORD nNumberOfBytesToWrite,
          LPDWORD lpNumberOfBytesWritten,
          LPOVERLAPPED lpOverlapped
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    buf = xrkdbg.readLong(esp + 8)
    size = xrkdbg.readLong(esp + 0xC)

    xrk_api_call("WriteFile", regs, {"handle": handle, "buf": buf, "size": size})


def run_WriteFileEx(regs):
    """
        kernel32.WriteFileEx

        WriteFileEx-->NtWriteFile(ntdll)

          _In_     HANDLE                          hFile,
          _In_opt_ LPCVOID                         lpBuffer,
          _In_     DWORD                           nNumberOfBytesToWrite,
          _Inout_  LPOVERLAPPED                    lpOverlapped,
          _In_     LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    buf = xrkdbg.readLong(esp + 8)
    size = xrkdbg.readLong(esp + 0xC)

    xrk_api_call("WriteFileEx", regs, {"handle": handle, "buf": buf, "size": size})


def run_CopyFileExW(regs):
    """
        kernel32.CopyFileExW

        CopyFileA-->CopyFileExW-->BasepCopyFileExW-->BaseCopyStream
        CopyFileW-->CopyFileExW==>>||
        CopyFileExA-->CopyFileExW==>>||

          _In_      LPCTSTR lpExistingFileName,
          _In_      LPCTSTR lpNewFileName,
          _In_opt_  LPPROGRESS_ROUTINE lpProgressRoutine,
          _In_opt_  LPVOID lpData,
          _In_opt_  LPBOOL pbCancel,
          _In_      DWORD dwCopyFlags
    """
    esp = regs["ESP"]
    file_old = xrkutil.dbg_read_pwstring(esp + 4)
    file_new = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("CopyFileExW", regs, {"file_old": file_old, "file_new": file_new})


def run_MoveFileWithProgressW(regs):
    """
        kernel32.MoveFileWithProgressW

        MoveFileA-->MoveFileWithProgressA-->MoveFileWithProgressW-->BasepCopyFileExW-->BaseCopyStream
        MoveFileW-->MoveFileWithProgressW==>||
        MoveFileExA-->MoveFileWithProgressA==>>||
        MoveFileExW-->MoveFileWithProgressW==>>||

          _In_     LPCTSTR            lpExistingFileName,
          _In_opt_ LPCTSTR            lpNewFileName,
          _In_opt_ LPPROGRESS_ROUTINE lpProgressRoutine,
          _In_opt_ LPVOID             lpData,
          _In_     DWORD              dwFlags
    """
    esp = regs["ESP"]
    file_old = xrkutil.dbg_read_pwstring(esp + 4)
    file_new = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("MoveFileWithProgressW", regs, {"file_old": file_old, "file_new": file_new})


def run_CreateDirectoryW(regs):
    """
        kernel32.CreateDirectoryW

        CreateDirectoryA-->CreateDirectoryW-->NtCreateFile(ntdll)

          LPCTSTR lpPathName,
          LPSECURITY_ATTRIBUTES lpSecurityAttributes
    """
    esp = regs["ESP"]
    dir_ = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("CreateDirectoryW", regs, {"dir": dir_})


def run_CreateDirectoryExW(regs):
    """
        kernel32.CreateDirectoryExW

        CreateDirectoryExA-->CreateDirectoryExW-->NtOpenFile/NtCreateFile(ntdll)

          _In_     LPCTSTR               lpTemplateDirectory,
          _In_     LPCTSTR               lpNewDirectory,
          _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
    """
    esp = regs["ESP"]
    dir_template = xrkutil.dbg_read_pwstring(esp + 4)
    dir_new = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("CreateDirectoryExW", regs, {"dir_template": dir_template, "dir_new": dir_new})


def run_RemoveDirectoryW(regs):
    """
        kernel32.RemoveDirectoryW

        RemoveDirectoryA-->RemoveDirectoryW-->NtOpenFile/NtSetInformationFile(ntdll)

          LPCTSTR lpPathName
    """
    esp = regs["ESP"]
    dir_ = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("RemoveDirectoryW", regs, {"dir": dir_})


def run_ReplaceFileW(regs):
    """
        kernel32.ReplaceFileW

        ReplaceFileA-->ReplaceFileW-->NtOpenFile/NtSetInformationFile(ntdll)

          _In_       LPCTSTR lpReplacedFileName,
          _In_       LPCTSTR lpReplacementFileName,
          _In_opt_   LPCTSTR lpBackupFileName,
          _In_       DWORD   dwReplaceFlags,
          _Reserved_ LPVOID  lpExclude,
          _Reserved_ LPVOID  lpReserved
    """
    esp = regs["ESP"]
    file_placed = xrkutil.dbg_read_pwstring(esp + 4)
    file_placement = xrkutil.dbg_read_pwstring(esp + 8)
    file_backup = xrkutil.dbg_read_pwstring(esp + 0xC)

    xrk_api_call("ReplaceFileWHook", regs, {"file_placed": file_placed, "file_placement": file_placement, "file_backup": file_backup})


def run_DeleteFileW(regs):
    """
        kernel32.DeleteFileW

        DeleteFileA-->DeleteFileW-->NtOpenFile(ntdll)

          LPCTSTR lpFileName
    """
    esp = regs["ESP"]
    file = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("RemoveDirectoryW", regs, {"file": file})


def run_DeviceIoControl(regs):
    """
        kernel32.DeviceIoControl

        DeviceIoControl-->NtDeviceIoControlFile/NtFsControlFile(ntdll)

          _In_        HANDLE       hDevice,
          _In_        DWORD        dwIoControlCode,
          _In_opt_    LPVOID       lpInBuffer,
          _In_        DWORD        nInBufferSize,
          _Out_opt_   LPVOID       lpOutBuffer,
          _In_        DWORD        nOutBufferSize,
          _Out_opt_   LPDWORD      lpBytesReturned,
          _Inout_opt_ LPOVERLAPPED lpOverlapped
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    io_ctrl_code = xrkdbg.readLong(esp + 8)

    xrk_api_call("DeviceIoControl", regs, {"handle": handle, "io_ctrl_code": io_ctrl_code})


def run_FindFirstFileExW(regs):
    """
        kernel32.FindFirstFileExW

        FindFirstFileA-->FindFirstFileExW-->NtOpenFile/NtQueryDirectoryFile(ntdll)
        FindFirstFileW-->FindFirstFileExW==>||
        FindFirstFileExA-->FindFirstFileExW==>||

          LPCTSTR lpFileName,
          FINDEX_INFO_LEVELS fInfoLevelId,
          LPVOID lpFindFileData,
          FINDEX_SEARCH_OPS fSearchOp,
          LPVOID lpSearchFilter,
          DWORD dwAdditionalFlags
    """
    esp = regs["ESP"]
    file = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("FindFirstFileExW", regs, {"file": file})


def run_FindNextFileW(regs):
    """
        kernel32.FindNextFileW

        FindNextFileA-->FindNextFileW-->NtQueryDirectoryFile(ntdll)

          HANDLE hFindFile,
          LPWIN32_FIND_DATA lpFindFileData
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("FindNextFileW", regs, {"handle": handle})


def run_SetFileAttributesW(regs):
    """
        kernel32.SetFileAttributesW

        SetFileAttributesA-->SetFileAttributesW-->NtOpenFile/NtSetInformationFile(ntdll)

          LPCTSTR lpFileName,
          DWORD dwAttributes

        file attrs:
            FILE_ATTRIBUTE_ARCHIVE (32 (0x20))
            FILE_ATTRIBUTE_HIDDEN (2 (0x2))
            FILE_ATTRIBUTE_NORMAL (128 (0x80))
            FILE_ATTRIBUTE_NOT_CONTENT_INDEXED (8192 (0x2000))
            FILE_ATTRIBUTE_OFFLINE (4096 (0x1000))
            FILE_ATTRIBUTE_READONLY (1 (0x1))
            FILE_ATTRIBUTE_SYSTEM (4 (0x4))
            FILE_ATTRIBUTE_TEMPORARY (256 (0x100))
    """
    esp = regs["ESP"]
    file = xrkutil.dbg_read_pwstring(esp + 4)
    attr = xrkdbg.readLong(esp + 8)

    attrs = ""
    if attr & 0x20:
        attrs = attrs + "|" + "FILE_ATTRIBUTE_ARCHIVE"
    if attr & 0x2:
        attrs = attrs + "|" + "FILE_ATTRIBUTE_HIDDEN"
    if attr & 0x80:
        attrs = attrs + "|" + "FILE_ATTRIBUTE_NORMAL"
    if attr & 0x2000:
        attrs = attrs + "|" + "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED"
    if attr & 0x1000:
        attrs = attrs + "|" + "FILE_ATTRIBUTE_OFFLINE"
    if attr & 0x1:
        attrs = attrs + "|" + "FILE_ATTRIBUTE_READONLY"
    if attr & 0x4:
        attrs = attrs + "|" + "FILE_ATTRIBUTE_SYSTEM"
    if attr & 0x100:
        attrs = attrs + "|" + "FILE_ATTRIBUTE_TEMPORARY"

    xrk_api_call("SetFileAttributesW", regs, {"file": file, "attrs": attrs})


def run_SetFileTime(regs):
    """
        kernel32.SetFileTime

        SetFileTime-->NtSetInformationFile

          _In_           HANDLE   hFile,
          _In_opt_ const FILETIME *lpCreationTime,
          _In_opt_ const FILETIME *lpLastAccessTime,
          _In_opt_ const FILETIME *lpLastWriteTime
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    ptime_create = xrkdbg.readLong(esp + 8)
    ptime_last_access = xrkdbg.readLong(esp + 0xC)
    ptime_last_write = xrkdbg.readLong(esp + 0x10)

    time_create = xrkutil.parse_p_file_time(ptime_create)
    time_last_access = xrkutil.parse_p_file_time(ptime_last_access)
    time_last_write = xrkutil.parse_p_file_time(ptime_last_write)

    xrk_api_call("SetFileTime", regs, {"handle": handle, "create": str(time_create), "last_access": str(time_last_access), "last_write": str(time_last_write)})


def run_GetFileTime(regs):
    """
        kernel32.GetFileTime

        GetFileTime-->NtQueryInformationFile

          _In_      HANDLE     hFile,
          _Out_opt_ LPFILETIME lpCreationTime,
          _Out_opt_ LPFILETIME lpLastAccessTime,
          _Out_opt_ LPFILETIME lpLastWriteTime
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("GetFileTime", regs, {"handle": handle})


def run_GetFileSizeEx(regs):
    """
        kernel32.GetFileSizeEx

        GetFileSize-->GetFileSizeEx-->NtQueryInformationFile

          _In_  HANDLE         hFile,
          _Out_ PLARGE_INTEGER lpFileSize
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("GetFileSizeEx", regs, {"handle": handle})


# -------------------------------------------------------------------------
# PROFILE
# -------------------------------------------------------------------------


def run_GetPrivateProfileStringA(regs):
    """
        kernel32.GetPrivateProfileStringA

        GetPrivateProfileIntA-->GetPrivateProfileStringA-->BaseDllReadWriteIniFile
        GetPrivateProfileSectionNamesA-->GetPrivateProfileStringA==>>||
        GetPrivateProfileStructA-->GetPrivateProfileStringA==>>||
        GetProfileStringA-->GetPrivateProfileStringA==>>||
        GetProfileIntA-->GetPrivateProfileIntA==>>||

          _In_  LPCTSTR lpAppName,
          _In_  LPCTSTR lpKeyName,
          _In_  LPCTSTR lpDefault,
          _Out_ LPTSTR  lpReturnedString,
          _In_  DWORD   nSize,
          _In_  LPCTSTR lpFileName
    """
    esp = regs["ESP"]
    app_name = xrkutil.dbg_read_pstring(esp + 4)
    key_name = xrkutil.dbg_read_pstring(esp + 8)
    default = xrkutil.dbg_read_pstring(esp + 0xC)
    file_name = xrkutil.dbg_read_pstring(esp + 0x18)

    xrk_api_call("GetPrivateProfileStringA", regs, {"app_name": app_name, "key_name": key_name, "default": default, "file_name": file_name})


def run_GetPrivateProfileStringW(regs):
    """
        kernel32.GetPrivateProfileStringW

        GetPrivateProfileIntW-->GetPrivateProfileStringW-->BaseDllReadWriteIniFile
        GetPrivateProfileSectionNamesW-->GetPrivateProfileStringW==>>||
        GetPrivateProfileStructW-->GetPrivateProfileStringW==>>||
        GetProfileStringW-->GetPrivateProfileStringW==>>||
        GetProfileIntW-->GetPrivateProfileIntW==>>||

          _In_  LPCTSTR lpAppName,
          _In_  LPCTSTR lpKeyName,
          _In_  LPCTSTR lpDefault,
          _Out_ LPTSTR  lpReturnedString,
          _In_  DWORD   nSize,
          _In_  LPCTSTR lpFileName
    """
    esp = regs["ESP"]
    app_name = xrkutil.dbg_read_pwstring(esp + 4)
    key_name = xrkutil.dbg_read_pwstring(esp + 8)
    default = xrkutil.dbg_read_pwstring(esp + 0xC)
    file_name = xrkutil.dbg_read_pwstring(esp + 0x18)

    xrk_api_call("GetPrivateProfileStringW", regs, {"app_name": app_name, "key_name": key_name, "default": default, "file_name": file_name})


def run_GetPrivateProfileSectionA(regs):
    """
        kernel32.GetPrivateProfileSectionA

        GetPrivateProfileSectionA-->BaseDllReadWriteIniFile
        GetProfileSectionA-->GetPrivateProfileSectionA==>>||

          _In_  LPCTSTR lpAppName,
          _Out_ LPTSTR  lpReturnedString,
          _In_  DWORD   nSize,
          _In_  LPCTSTR lpFileName
    """
    esp = regs["ESP"]
    app_name = xrkutil.dbg_read_pstring(esp + 4)
    file_name = xrkutil.dbg_read_pstring(esp + 0x10)

    xrk_api_call("GetPrivateProfileSectionA", regs, {"app_name": app_name, "file_name": file_name})


def run_GetPrivateProfileSectionW(regs):
    """
        kernel32.GetPrivateProfileSectionW

        GetPrivateProfileSectionW-->BaseDllReadWriteIniFile
        GetProfileSectionW-->GetPrivateProfileSectionW==>>||

          _In_  LPCTSTR lpAppName,
          _Out_ LPTSTR  lpReturnedString,
          _In_  DWORD   nSize,
          _In_  LPCTSTR lpFileName
    """
    esp = regs["ESP"]
    app_name = xrkutil.dbg_read_pwstring(esp + 4)
    file_name = xrkutil.dbg_read_pwstring(esp + 0x10)

    xrk_api_call("GetPrivateProfileSectionW", regs, {"app_name": app_name, "file_name": file_name})


def run_WritePrivateProfileSectionA(regs):
    """
        kernel32.WritePrivateProfileSectionA

        WritePrivateProfileSectionA-->BaseDllReadWriteIniFile
        WriteProfileSectionA-->WritePrivateProfileSectionA==>>||

          _In_ LPCTSTR lpAppName,
          _In_ LPCTSTR lpString,
          _In_ LPCTSTR lpFileName
    """
    esp = regs["ESP"]
    app_name = xrkutil.dbg_read_pstring(esp + 4)
    str_ = xrkutil.dbg_read_pstring(esp + 8)
    file_name = xrkutil.dbg_read_pstring(esp + 0xC)

    xrk_api_call("WritePrivateProfileSectionA", regs, {"app_name": app_name, "str": str_, "file_name": file_name})


def run_WritePrivateProfileSectionW(regs):
    """
        kernel32.WritePrivateProfileSectionW

        WritePrivateProfileSectionW-->BaseDllReadWriteIniFile
        WriteProfileSectionW-->WritePrivateProfileSectionW==>>||

          _In_ LPCTSTR lpAppName,
          _In_ LPCTSTR lpString,
          _In_ LPCTSTR lpFileName
    """
    esp = regs["ESP"]
    app_name = xrkutil.dbg_read_pwstring(esp + 4)
    str_ = xrkutil.dbg_read_pwstring(esp + 8)
    file_name = xrkutil.dbg_read_pwstring(esp + 0xC)

    xrk_api_call("WritePrivateProfileSectionW", regs, {"app_name": app_name, "str": str_, "file_name": file_name})


def run_WritePrivateProfileStringA(regs):
    """
        kernel32.WritePrivateProfileStringA

        WritePrivateProfileStringA-->BaseDllReadWriteIniFile
        WritePrivateProfileStructA-->WritePrivateProfileStringA
        WriteProfileStringA-->WritePrivateProfileStringA==>>||

          _In_ LPCTSTR lpAppName,
          _In_ LPCTSTR lpKeyName,
          _In_ LPCTSTR lpString,
          _In_ LPCTSTR lpFileName
    """
    esp = regs["ESP"]
    app_name = xrkutil.dbg_read_pstring(esp + 4)
    key_name = xrkutil.dbg_read_pstring(esp + 8)
    str_ = xrkutil.dbg_read_pstring(esp + 0xC)
    file_name = xrkutil.dbg_read_pstring(esp + 0x10)

    xrk_api_call("WritePrivateProfileStringA", regs, {"app_name": app_name, "key_name": key_name, "str": str_, "file_name": file_name})


def run_WritePrivateProfileStringW(regs):
    """
        kernel32.WritePrivateProfileStringW

        WritePrivateProfileStringW-->BaseDllReadWriteIniFile
        WritePrivateProfileStructW-->WritePrivateProfileStringW
        WriteProfileStringW-->WritePrivateProfileStringW==>>||

          _In_ LPCTSTR lpAppName,
          _In_ LPCTSTR lpKeyName,
          _In_ LPCTSTR lpString,
          _In_ LPCTSTR lpFileName
    """
    esp = regs["ESP"]
    app_name = xrkutil.dbg_read_pwstring(esp + 4)
    key_name = xrkutil.dbg_read_pwstring(esp + 8)
    str_ = xrkutil.dbg_read_pwstring(esp + 0xC)
    file_name = xrkutil.dbg_read_pwstring(esp + 0x10)

    xrk_api_call("WritePrivateProfileStringW", regs, {"app_name": app_name, "key_name": key_name, "str": str_, "file_name": file_name})


# -------------------------------------------------------------------------
# HOOKS
# -------------------------------------------------------------------------


def run_CallNextHookEx(regs):
    """
        user32.CallNextHookEx

        CallNextHookEx-->NtUserCallNextHookEx(??)

          _In_opt_ HHOOK  hhk,
          _In_     int    nCode,
          _In_     WPARAM wParam,
          _In_     LPARAM lParam
    """
    esp = regs["ESP"]
    code = xrkdbg.readLong(esp + 8)

    xrk_api_call("CallNextHookEx", regs, {"code": code})


def run_SetWindowsHookA(regs):
    """
        user32.SetWindowsHookA

        SetWindowsHookA-->NtUserSetWindowsHookAW(??)

          _In_ int       idHook,
          _In_ HOOKPROC  lpfn,
          _In_ HINSTANCE hMod,
          _In_ DWORD     dwThreadId
    """
    esp = regs["ESP"]
    id_ = xrkdbg.readLong(esp + 4)
    pfn = xrkdbg.readLong(esp + 8)

    xrk_api_call("SetWindowsHookA", regs, {"id": xrkutil.hook_id_to_str(id_), "pfn": pfn})


def run_SetWindowsHookW(regs):
    """
        user32.SetWindowsHookW

        SetWindowsHookW-->NtUserSetWindowsHookAW(??)

          _In_ int       idHook,
          _In_ HOOKPROC  lpfn,
          _In_ HINSTANCE hMod,
          _In_ DWORD     dwThreadId
    """
    esp = regs["ESP"]
    id_ = xrkdbg.readLong(esp + 4)
    pfn = xrkdbg.readLong(esp + 8)

    xrk_api_call("SetWindowsHookW", regs, {"id": xrkutil.hook_id_to_str(id_), "pfn": pfn})


def run_SetWindowsHookExAW(regs):
    """
        user32.SetWindowsHookExAW

        SetWindowsHookExA-->SetWindowsHookExAW
        SetWindowsHookExW-->SetWindowsHookExAW

          _In_ int       idHook,
          _In_ HOOKPROC  lpfn,
          _In_ HINSTANCE hMod,
          _In_ DWORD     dwThreadId
    """
    esp = regs["ESP"]
    id_ = xrkdbg.readLong(esp + 4)
    pfn = xrkdbg.readLong(esp + 8)
    tid = xrkdbg.readLong(esp + 0x10)

    xrk_api_call("SetWindowsHookExAW", regs, {"id": xrkutil.hook_id_to_str(id_), "pfn": pfn, "tid": tid})


def run_SetWindowsHookExA(regs):
    """
        user32.SetWindowsHookExA

        SetWindowsHookExA-->SetWindowsHookExAW

          _In_ int       idHook,
          _In_ HOOKPROC  lpfn,
          _In_ HINSTANCE hMod,
          _In_ DWORD     dwThreadId
    """
    esp = regs["ESP"]
    id_ = xrkdbg.readLong(esp + 4)
    pfn = xrkdbg.readLong(esp + 8)
    tid = xrkdbg.readLong(esp + 0x10)

    xrk_api_call("SetWindowsHookExA", regs, {"id": xrkutil.hook_id_to_str(id_), "pfn": pfn, "tid": tid})


def run_SetWindowsHookExW(regs):
    """
        user32.SetWindowsHookExW

        SetWindowsHookExW-->SetWindowsHookExAW

          _In_ int       idHook,
          _In_ HOOKPROC  lpfn,
          _In_ HINSTANCE hMod,
          _In_ DWORD     dwThreadId
    """
    esp = regs["ESP"]
    id_ = xrkdbg.readLong(esp + 4)
    pfn = xrkdbg.readLong(esp + 8)
    tid = xrkdbg.readLong(esp + 0x10)

    xrk_api_call("SetWindowsHookExW", regs, {"id": xrkutil.hook_id_to_str(id_), "pfn": pfn, "tid": tid})


def run_UnhookWindowsHook(regs):
    """
        user32.UnhookWindowsHook

        UnhookWindowsHook-->NtUserCallTwoParam

          int nCode,
          HOOKPROC pfnFilterProc
    """
    esp = regs["ESP"]
    code = xrkdbg.readLong(esp + 4)

    xrk_api_call("UnhookWindowsHook", regs, {"code": code})


def run_NtUserUnhookWindowsHookEx(regs):
    """
        ntdll.NtUserUnhookWindowsHookEx

        NtUserUnhookWindowsHookEx-->??

          HHOOK hhk
    """
    xrk_api_call("NtUserUnhookWindowsHookEx", regs)


# -------------------------------------------------------------------------
# URL DOWNLOAD
# -------------------------------------------------------------------------


def run_URLDownloadW(regs):
    """
        urlmon.URLDownloadW

        URLDownloadA-->URLDownloadW
    """
    esp = regs["ESP"]
    internet_url = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("URLDownloadW", regs, {"internet_url": internet_url})


def run_URLDownloadToFileW(regs):
    """
        urlmon.URLDownloadToFileW

        URLDownloadToFileA-->URLDownloadToFileW-->CFileDownload::CFileDownload

          LPUNKNOWN            pCaller,
          LPCTSTR              szURL,
          LPCTSTR              szFileName,
          _Reserved_ DWORD     dwReserved,
          LPBINDSTATUSCALLBACK lpfnCB
    """
    esp = regs["ESP"]
    internet_url = xrkutil.dbg_read_pwstring(esp + 8)
    file = xrkutil.dbg_read_pwstring(esp + 12)

    xrk_api_call("URLDownloadToFileW", regs, {"internet_url": internet_url, "file": file})


def run_URLDownloadToCacheFileW(regs):
    """
        urlmon.URLDownloadToCacheFileW

        URLDownloadToCacheFileA-->URLDownloadToCacheFileW-->CCacheFileDownload::CCacheFileDownload

          _In_       LPUNKNOWN           lpUnkcaller,
          _In_       LPCSTR              szURL,
          _Out_      LPTSTR              szFileName,
          _In_       DWORD               cchFileName,
          _Reserved_ DWORD               dwReserved,
          _In_opt_   IBindStatusCallback *pBSC
    """
    esp = regs["ESP"]
    internet_url = xrkutil.dbg_read_pwstring(esp + 8)
    file = xrkutil.dbg_read_pwstring(esp + 12)

    xrk_api_call("URLDownloadToCacheFileW", regs, {"internet_url": internet_url, "file": file})


# -------------------------------------------------------------------------
# SERVICE
# -------------------------------------------------------------------------


def run_OpenSCManagerA(regs):
    """
        advapi32.OpenSCManagerA

        OpenSCManagerA-->ROpenSCManagerA

          _In_opt_ LPCTSTR lpMachineName,
          _In_opt_ LPCTSTR lpDatabaseName,
          _In_     DWORD   dwDesiredAccess
    """
    esp = regs["ESP"]
    svc_mc_name = xrkutil.dbg_read_pstring(esp + 4)
    svc_db_name = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("OpenSCManagerA", regs, {"svc_mc_name": svc_mc_name, "svc_db_name": svc_db_name})


def run_OpenSCManagerW(regs):
    """
        advapi32.OpenSCManagerW

        OpenSCManagerW-->ROpenSCManagerW

          _In_opt_ LPCTSTR lpMachineName,
          _In_opt_ LPCTSTR lpDatabaseName,
          _In_     DWORD   dwDesiredAccess
    """
    esp = regs["ESP"]
    svc_mc_name = xrkutil.dbg_read_pwstring(esp + 4)
    svc_db_name = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("OpenSCManagerW", regs, {"svc_mc_name": svc_mc_name, "svc_db_name": svc_db_name})


def run_CreateServiceA(regs):
    """
        advapi32.CreateServiceA

        CreateServiceA-->RCreateServiceA

          _In_      SC_HANDLE hSCManager,
          _In_      LPCTSTR   lpServiceName,
          _In_opt_  LPCTSTR   lpDisplayName,
          _In_      DWORD     dwDesiredAccess,
          _In_      DWORD     dwServiceType,
          _In_      DWORD     dwStartType,
          _In_      DWORD     dwErrorControl,
          _In_opt_  LPCTSTR   lpBinaryPathName,
          _In_opt_  LPCTSTR   lpLoadOrderGroup,
          _Out_opt_ LPDWORD   lpdwTagId,
          _In_opt_  LPCTSTR   lpDependencies,
          _In_opt_  LPCTSTR   lpServiceStartName,
          _In_opt_  LPCTSTR   lpPassword
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    svc_name = xrkutil.dbg_read_pstring(esp + 8)
    svc_display_name = xrkutil.dbg_read_pstring(esp + 0xC)
    svc_file = xrkutil.dbg_read_pstring(esp + 0x20)

    xrk_api_call("CreateServiceA", regs, {"handle": handle, "svc_name": svc_name, "svc_display_name": svc_display_name, "svc_file": svc_file})


def run_CreateServiceW(regs):
    """
        advapi32.CreateServiceW

        CreateServiceW-->RCreateServiceW

          _In_      SC_HANDLE hSCManager,
          _In_      LPCTSTR   lpServiceName,
          _In_opt_  LPCTSTR   lpDisplayName,
          _In_      DWORD     dwDesiredAccess,
          _In_      DWORD     dwServiceType,
          _In_      DWORD     dwStartType,
          _In_      DWORD     dwErrorControl,
          _In_opt_  LPCTSTR   lpBinaryPathName,
          _In_opt_  LPCTSTR   lpLoadOrderGroup,
          _Out_opt_ LPDWORD   lpdwTagId,
          _In_opt_  LPCTSTR   lpDependencies,
          _In_opt_  LPCTSTR   lpServiceStartName,
          _In_opt_  LPCTSTR   lpPassword
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    svc_name = xrkutil.dbg_read_pwstring(esp + 8)
    svc_display_name = xrkutil.dbg_read_pwstring(esp + 0xC)
    svc_file = xrkutil.dbg_read_pwstring(esp + 0x20)

    xrk_api_call("CreateServiceW", regs, {"handle": handle, "svc_name": svc_name, "svc_display_name": svc_display_name, "svc_file": svc_file})


def run_ControlService(regs):
    """
        advapi32.ControlService

        ControlService-->RControlService

          _In_  SC_HANDLE        hService,
          _In_  DWORD            dwControl,
          _Out_ LPSERVICE_STATUS lpServiceStatus
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    code = xrkdbg.readLong(esp + 8)

    xrk_api_call("ControlService", regs, {"handle": handle, "code": code})


def run_DeleteService(regs):
    """
        advapi32.DeleteService

        DeleteService-->RDeleteService

          _In_ SC_HANDLE hService
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("DeleteService", regs, {"handle": handle})


def run_GetServiceDisplayNameA(regs):
    """
        advapi32.GetServiceDisplayNameA

        GetServiceDisplayNameA-->RGetServiceDisplayNameA

          _In_      SC_HANDLE hSCManager,
          _In_      LPCTSTR   lpServiceName,
          _Out_opt_ LPTSTR    lpDisplayName,
          _Inout_   LPDWORD   lpcchBuffer
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    svc_name = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("GetServiceDisplayNameA", regs, {"handle": handle, "svc_name": svc_name})


def run_GetServiceDisplayNameW(regs):
    """
        advapi32.GetServiceDisplayNameW

        GetServiceDisplayNameW-->RGetServiceDisplayNameW

          _In_      SC_HANDLE hSCManager,
          _In_      LPCTSTR   lpServiceName,
          _Out_opt_ LPTSTR    lpDisplayName,
          _Inout_   LPDWORD   lpcchBuffer
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    svc_name = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("GetServiceDisplayNameW", regs, {"handle": handle, "svc_name": svc_name})


def run_GetServiceKeyNameA(regs):
    """
        advapi32.GetServiceKeyNameA

        GetServiceKeyNameA-->RGetServiceKeyNameA

          _In_      SC_HANDLE hSCManager,
          _In_      LPCTSTR   lpDisplayName,
          _Out_opt_ LPTSTR    lpServiceName,
          _Inout_   LPDWORD   lpcchBuffer
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    svc_display_name = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("GetServiceKeyNameA", regs, {"handle": handle, "svc_display_name": svc_display_name})


def run_GetServiceKeyNameW(regs):
    """
        advapi32.GetServiceKeyNameW

        GetServiceKeyNameW-->RGetServiceKeyNameW

          _In_      SC_HANDLE hSCManager,
          _In_      LPCTSTR   lpDisplayName,
          _Out_opt_ LPTSTR    lpServiceName,
          _Inout_   LPDWORD   lpcchBuffer
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    svc_display_name = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("GetServiceKeyNameW", regs, {"handle": handle, "svc_display_name": svc_display_name})


def run_OpenServiceA(regs):
    """
        advapi32.OpenServiceA

        OpenServiceA-->ROpenServiceA

          _In_  SC_HANDLE hSCManager,
          _In_  LPCTSTR lpServiceName,
          _In_  DWORD dwDesiredAccess
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    svc_name = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("OpenServiceA", regs, {"handle": handle, "svc_name": svc_name})


def run_OpenServiceW(regs):
    """
        advapi32.OpenServiceW

        OpenServiceW-->ROpenServiceW

          _In_  SC_HANDLE hSCManager,
          _In_  LPCTSTR lpServiceName,
          _In_  DWORD dwDesiredAccess
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    svc_name = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("OpenServiceW", regs, {"handle": handle, "svc_name": svc_name})


def run_RegisterServiceCtrlHandlerW(regs):
    """
        advapi32.RegisterServiceCtrlHandlerW

        RegisterServiceCtrlHandlerA-->RegisterServiceCtrlHandlerW-->RegisterServiceCtrlHandlerHelp

          _In_ LPCTSTR            lpServiceName,
          _In_ LPHANDLER_FUNCTION lpHandlerProc
    """
    esp = regs["ESP"]
    svc_name = xrkutil.dbg_read_pwstring(esp + 4)
    cbk_proc = xrkdbg.readLong(esp + 8)

    xrk_api_call("RegisterServiceCtrlHandlerW", regs, {"svc_name": svc_name, "cbk_proc": cbk_proc})


def run_RegisterServiceCtrlHandlerExW(regs):
    """
        advapi32.RegisterServiceCtrlHandlerExW

        RegisterServiceCtrlHandlerExA-->RegisterServiceCtrlHandlerExW-->RegisterServiceCtrlHandlerHelp

          _In_     LPCTSTR               lpServiceName,
          _In_     LPHANDLER_FUNCTION_EX lpHandlerProc,
          _In_opt_ LPVOID                lpContext
    """
    esp = regs["ESP"]
    svc_name = xrkutil.dbg_read_pwstring(esp + 4)
    cbk_proc = xrkdbg.readLong(esp + 8)

    xrk_api_call("RegisterServiceCtrlHandlerExW", regs, {"svc_name": svc_name, "cbk_proc": cbk_proc})


def run_StartServiceA(regs):
    """
        advapi32.StartServiceA

        StartServiceA-->RStartServiceA

          _In_     SC_HANDLE hService,
          _In_     DWORD     dwNumServiceArgs,
          _In_opt_ LPCTSTR   *lpServiceArgVectors
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("StartServiceA", regs, {"handle": handle})


def run_StartServiceW(regs):
    """
        advapi32.StartServiceW

        StartServiceW-->RStartServiceW

          _In_     SC_HANDLE hService,
          _In_     DWORD     dwNumServiceArgs,
          _In_opt_ LPCTSTR   *lpServiceArgVectors
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("StartServiceW", regs, {"handle": handle})


def run_StartServiceCtrlDispatcherA(regs):
    """
        advapi32.StartServiceCtrlDispatcherA

          _In_  const SERVICE_TABLE_ENTRY *lpServiceTable
    """
    esp = regs["ESP"]
    ptable = xrkdbg.readLong(esp + 4)
    svc_name = xrkutil.dbg_read_pstring(ptable)
    cbk_proc = xrkdbg.readLong(ptable + 4)

    xrk_api_call("StartServiceCtrlDispatcherA", regs, {"svc_name": svc_name, "cbk_proc": cbk_proc})


def run_StartServiceCtrlDispatcherW(regs):
    """
        advapi32.StartServiceCtrlDispatcherW

          _In_  const SERVICE_TABLE_ENTRY *lpServiceTable
    """
    esp = regs["ESP"]
    ptable = xrkdbg.readLong(esp + 4)
    svc_name = xrkutil.dbg_read_pwstring(ptable)
    cbk_proc = xrkdbg.readLong(ptable + 4)

    xrk_api_call("StartServiceCtrlDispatcherW", regs, {"svc_name": svc_name, "cbk_proc": cbk_proc})


# -------------------------------------------------------------------------
# MUTEX
# -------------------------------------------------------------------------


def run_CreateMutexW(regs):
    """
        kernel32.CreateMutexW

        CreateMutexA-->CreateMutexW-->NtCreateMutant(ntdll)

          _In_opt_ LPSECURITY_ATTRIBUTES lpMutexAttributes,
          _In_     BOOL                  bInitialOwner,
          _In_opt_ LPCTSTR               lpName
    """
    esp = regs["ESP"]
    mutex = xrkutil.dbg_read_pwstring(esp + 0xC)

    xrk_api_call("CreateMutexW", regs, {"mutex": mutex})


def run_OpenMutexW(regs):
    """
        kernel32.OpenMutexW

        OpenMutexA-->OpenMutexW-->NtOpenMutant(ntdll)

          _In_ DWORD   dwDesiredAccess,
          _In_ BOOL    bInheritHandle,
          _In_ LPCTSTR lpName
    """
    esp = regs["ESP"]
    mutex = xrkutil.dbg_read_pwstring(esp + 0xC)

    xrk_api_call("OpenMutexW", regs, {"mutex": mutex})


def run_ReleaseMutex(regs):
    """
        kernel32.ReleaseMutex

        ReleaseMutex-->NtReleaseMutant

          HANDLE hMutex
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("ReleaseMutex", regs, {"handle": handle})


# -------------------------------------------------------------------------
# EVENT LOG
# -------------------------------------------------------------------------


def run_OpenEventLogA(regs):
    """
        advapi32.OpenEventLogA

        OpenEventLogA-->ElfOpenEventLogA

          _In_ LPCTSTR lpUNCServerName,
          _In_ LPCTSTR lpSourceName
    """
    esp = regs["ESP"]
    svr_name = xrkutil.dbg_read_pstring(esp + 4)
    src_name = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("OpenEventLogA", regs, {"svr_name": svr_name, "src_name": src_name})


def run_OpenEventLogW(regs):
    """
        advapi32.OpenEventLogW

        OpenEventLogW-->ElfOpenEventLogW

          _In_ LPCTSTR lpUNCServerName,
          _In_ LPCTSTR lpSourceName
    """
    esp = regs["ESP"]
    svr_name = xrkutil.dbg_read_pwstring(esp + 4)
    src_name = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("OpenEventLogW", regs, {"svr_name": svr_name, "src_name": src_name})


def run_ClearEventLogW(regs):
    """
        advapi32.ClearEventLogW

        ClearEventLogA-->ClearEventLogW-->ElfClearEventLogFileW

          _In_ HANDLE  hEventLog,
          _In_ LPCTSTR lpBackupFileName
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    file_bk_name = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("ClearEventLogW", regs, {"handle": handle, "file_bk_name": file_bk_name})


# -------------------------------------------------------------------------
# PRIVILEDGES
# -------------------------------------------------------------------------


def run_AdjustTokenPrivileges(regs):
    """
        advapi32.AdjustTokenPrivileges

        AdjustTokenPrivileges-->NtAdjustPrivilegesToken(ntdll)

          _In_      HANDLE            TokenHandle,
          _In_      BOOL              DisableAllPrivileges,
          _In_opt_  PTOKEN_PRIVILEGES NewState,
          _In_      DWORD             BufferLength,
          _Out_opt_ PTOKEN_PRIVILEGES PreviousState,
          _Out_opt_ PDWORD            ReturnLength
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("AdjustTokenPrivileges", regs, {"handle": handle})


def run_LookupPrivilegeDisplayNameW(regs):
    """
        advapi32.LookupPrivilegeDisplayNameW

        LookupPrivilegeDisplayNameA-->LookupPrivilegeDisplayNameW-->LsaLookupPrivilegeDisplayName

          _In_opt_  LPCTSTR lpSystemName,
          _In_      LPCTSTR lpName,
          _Out_opt_ LPTSTR  lpDisplayName,
          _Inout_   LPDWORD cchDisplayName,
          _Out_     LPDWORD lpLanguageId
    """
    esp = regs["ESP"]
    sys_name = xrkutil.dbg_read_pwstring(esp + 4)
    name = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("LookupPrivilegeDisplayNameWHook", regs, {"sys_name": sys_name, "name": name})


def run_LookupPrivilegeNameW(regs):
    """
        advapi32.LookupPrivilegeNameW

        LookupPrivilegeNameA-->LookupPrivilegeNameW-->LsaLookupPrivilegeName

          _In_opt_  LPCTSTR lpSystemName,
          _In_      PLUID   lpLuid,
          _Out_opt_ LPTSTR  lpName,
          _Inout_   LPDWORD cchName
    """
    esp = regs["ESP"]
    sys_name = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("LookupPrivilegeNameW", regs, {"sys_name": sys_name})


def run_LookupPrivilegeValueW(regs):
    """
        advapi32.LookupPrivilegeValueW

        LookupPrivilegeValueA-->LookupPrivilegeValueW-->LsaLookupPrivilegeValue

          _In_opt_ LPCTSTR lpSystemName,
          _In_     LPCTSTR lpName,
          _Out_    PLUID   lpLuid
    """
    esp = regs["ESP"]
    sys_name = xrkutil.dbg_read_pwstring(esp + 4)
    name = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("LookupPrivilegeValueW", regs, {"sys_name": sys_name, "name": name})


# -------------------------------------------------------------------------
# RESOURCE
# -------------------------------------------------------------------------


def run_FindResourceA(regs):
    """
        kernel32.FindResourceA

        FindResourceA-->LdrFindResource_U(ntdll)

          _In_opt_ HMODULE hModule,
          _In_     LPCTSTR lpName,
          _In_     LPCTSTR lpType
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    res = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("FindResourceA", regs, {"handle": handle, "res": res})


def run_FindResourceW(regs):
    """
        kernel32.FindResourceW

        FindResourceW-->LdrFindResource_U(ntdll)

          _In_opt_ HMODULE hModule,
          _In_     LPCTSTR lpName,
          _In_     LPCTSTR lpType
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    res = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("FindResourceW", regs, {"handle": handle, "res": res})


def run_FindResourceExA(regs):
    """
        kernel32.FindResourceExA

        FindResourceExA-->LdrFindResource_U(ntdll)

          _In_opt_ HMODULE hModule,
          _In_     LPCTSTR lpType,
          _In_     LPCTSTR lpName,
          _In_     WORD    wLanguage
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    res = xrkutil.dbg_read_pstring(esp + 0xC)

    xrk_api_call("FindResourceExA", regs, {"handle": handle, "res": res})


def run_FindResourceExW(regs):
    """
        kernel32.FindResourceExW

        FindResourceExW-->LdrFindResource_U(ntdll)

          _In_opt_ HMODULE hModule,
          _In_     LPCTSTR lpType,
          _In_     LPCTSTR lpName,
          _In_     WORD    wLanguage
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    res = xrkutil.dbg_read_pwstring(esp + 0xC)

    xrk_api_call("FindResourceExW", regs, {"handle": handle, "res": res})


def run_LoadResource(regs):
    """
        kernel32.LoadResource

        LoadResource-->LdrAccessResource(ntdll)

          _In_opt_ HMODULE hModule,
          _In_     HRSRC   hResInfo
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("LoadResource", regs, {"handle": handle})


def run_AddResource(regs):
    """
        kernel32.AddResource

        UpdateResourceA-->UpdateResourceW-->AddResource

          [in]  IWorkspaceClientExt *pUnk,
          [out] DWORD               *pdwCookie
    """
    xrk_api_call("AddResource", regs)


def run_UpdateResourceW(regs):
    """
        kernel32.UpdateResourceW

        UpdateResourceA-->UpdateResourceW-->AddResource

          _In_     HANDLE  hUpdate,
          _In_     LPCTSTR lpType,
          _In_     LPCTSTR lpName,
          _In_     WORD    wLanguage,
          _In_opt_ LPVOID  lpData,
          _In_     DWORD   cbData
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    res_type = xrkutil.dbg_read_pwstring(esp + 8)
    res_name = xrkutil.dbg_read_pwstring(esp + 0xC)

    xrk_api_call("UpdateResourceW", regs, {"handle": handle, "res_type": res_type, "res_name": res_name})


# -------------------------------------------------------------------------
# DISK VOLUME
# -------------------------------------------------------------------------


def run_GetDiskFreeSpaceW(regs):
    """
        kernel32.GetDiskFreeSpaceW

        GetDiskFreeSpaceA-->GetDiskFreeSpaceW-->NtOpenFile/NtQueryVolumeInformationFile(ntdll)

          _In_  LPCTSTR lpRootPathName,
          _Out_ LPDWORD lpSectorsPerCluster,
          _Out_ LPDWORD lpBytesPerSector,
          _Out_ LPDWORD lpNumberOfFreeClusters,
          _Out_ LPDWORD lpTotalNumberOfClusters
    """
    esp = regs["ESP"]
    path = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("GetDiskFreeSpaceW", regs, {"path": path})


def run_GetDiskFreeSpaceExW(regs):
    """
        kernel32.GetDiskFreeSpaceExW

        GetDiskFreeSpaceExA-->GetDiskFreeSpaceExW-->NtOpenFile/NtQueryVolumeInformationFile(ntdll)

          LPCWSTR lpDirectoryName,
          PULARGE_INTEGER lpFreeBytesAvailableToCaller,
          PULARGE_INTEGER lpTotalNumberOfBytes,
          PULARGE_INTEGER lpTotalNumberOfFreeBytes
    """
    esp = regs["ESP"]
    dir_ = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("GetDiskFreeSpaceExW", regs, {"dir": dir_})


def run_GetDriveTypeW(regs):
    """
        kernel32.GetDriveTypeW

        GetDriveTypeA-->GetDriveTypeW-->NtOpenFile/NtQueryVolumeInformationFile(ntdll)

          _In_opt_ LPCTSTR lpRootPathName
    """
    esp = regs["ESP"]
    path = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("GetDriveTypeW", regs, {"path": path})


def run_GetVolumeInformationW(regs):
    """
        kernel32.GetVolumeInformationW

        GetVolumeInformationA-->GetVolumeInformationW-->NtOpenFile/NtQueryVolumeInformationFile(ntdll)

          _In_opt_  LPCTSTR lpRootPathName,
          _Out_opt_ LPTSTR  lpVolumeNameBuffer,
          _In_      DWORD   nVolumeNameSize,
          _Out_opt_ LPDWORD lpVolumeSerialNumber,
          _Out_opt_ LPDWORD lpMaximumComponentLength,
          _Out_opt_ LPDWORD lpFileSystemFlags,
          _Out_opt_ LPTSTR  lpFileSystemNameBuffer,
          _In_      DWORD   nFileSystemNameSize
    """
    esp = regs["ESP"]
    path = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("GetVolumeInformationW", regs, {"path": path})


def run_GetVolumeNameForVolumeMountPointW(regs):
    """
        kernel32.GetVolumeNameForVolumeMountPointW

        GetVolumeNameForVolumeMountPointA-->GetVolumeNameForVolumeMountPointW-->BasepGetVolumeNameForVolumeMountPoint

          _In_  LPCTSTR lpszVolumeMountPoint,
          _Out_ LPTSTR  lpszVolumeName,
          _In_  DWORD   cchBufferLength
    """
    esp = regs["ESP"]
    path = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("GetVolumeNameForVolumeMountPointW", regs, {"path": path})


def run_FindFirstVolumeW(regs):
    """
        kernel32.FindFirstVolumeW

        FindFirstVolumeA-->FindFirstVolumeW-->CreateFileW/DeviceIoControl/FindNextVolumeW

          _Out_ LPTSTR lpszVolumeName,
          _In_  DWORD  cchBufferLength
    """
    xrk_api_call("FindFirstVolumeW", regs)


def run_FindNextVolumeW(regs):
    """
        kernel32.FindNextVolumeW

        FindNextVolumeA-->FindNextVolumeW

          _In_  HANDLE hFindVolume,
          _Out_ LPTSTR lpszVolumeName,
          _In_  DWORD  cchBufferLength
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("FindNextVolumeW", regs, {"handle": handle})


def run_GetFullPathNameW(regs):
    """
        kernel32.GetFullPathNameW

        GetVolumePathNameA-->GetVolumePathNameW-->GetFullPathNameW

          _In_  LPCTSTR lpFileName,
          _In_  DWORD   nBufferLength,
          _Out_ LPTSTR  lpBuffer,
          _Out_ LPTSTR  *lpFilePart
    """
    xrk_api_call("GetFullPathNameW", regs)


def run_GetVolumePathNamesForVolumeNameW(regs):
    """
        kernel32.GetVolumePathNamesForVolumeNameW

        GetVolumePathNamesForVolumeNameA-->GetVolumePathNamesForVolumeNameW-->CreateFileW/DeviceIoControl

          _In_  LPCTSTR lpszVolumeName,
          _Out_ LPTSTR  lpszVolumePathNames,
          _In_  DWORD   cchBufferLength,
          _Out_ PDWORD  lpcchReturnLength
    """
    esp = regs["ESP"]
    path_vol_name = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("GetVolumePathNamesForVolumeNameW", regs, {"path_vol_name": path_vol_name})


def run_GetLogicalDriveStringsA(regs):
    """
        kernel32.GetLogicalDriveStringsA

          _In_   DWORD nBufferLength,
          _Out_  LPTSTR lpBuffer
    """
    xrk_api_call("GetLogicalDriveStringsA", regs)


def run_GetLogicalDriveStringsW(regs):
    """
        kernel32.GetLogicalDriveStringsW

          _In_   DWORD nBufferLength,
          _Out_  LPTSTR lpBuffer
    """
    xrk_api_call("GetLogicalDriveStringsW", regs)


def run_GetLogicalDrives(regs):
    """
        kernel32.GetLogicalDrives

        GetLogicalDrives-->NtQueryInformationProcess

          void
    """
    xrk_api_call("GetLogicalDrives", regs)


# -------------------------------------------------------------------------
# WINDOW
# -------------------------------------------------------------------------


def run_EnumWindows(regs):
    """
        user32.EnumWindows

        EnumWindows-->InternalEnumWindows

          _In_ WNDENUMPROC lpEnumFunc,
          _In_ LPARAM      lParam
    """
    esp = regs["ESP"]
    cbk_proc = xrkdbg.readLong(esp + 4)

    xrk_api_call("EnumWindows", regs, {"cbk_proc": cbk_proc})


def run_EnumChildWindows(regs):
    """
        user32.EnumChildWindows

        EnumChildWindows-->InternalEnumWindows

          _In_opt_ HWND        hWndParent,
          _In_     WNDENUMPROC lpEnumFunc,
          _In_     LPARAM      lParam
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    cbk_proc = xrkdbg.readLong(esp + 8)

    xrk_api_call("EnumChildWindows", regs, {"handle": handle, "cbk_proc": cbk_proc})


def run_EnumDesktopWindows(regs):
    """
        user32.EnumDesktopWindows

        EnumDesktopWindows-->InternalEnumWindows

          _In_opt_ HDESK       hDesktop,
          _In_     WNDENUMPROC lpfn,
          _In_     LPARAM      lParam
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    cbk_proc = xrkdbg.readLong(esp + 8)

    xrk_api_call("EnumDesktopWindows", regs, {"handle": handle, "cbk_proc": cbk_proc})


def run_EnumDesktopsA(regs):
    """
        user32.EnumDesktopsA

        EnumDesktopsA-->InternalEnumObjects

          _In_opt_ HWINSTA         hwinsta,
          _In_     DESKTOPENUMPROC lpEnumFunc,
          _In_     LPARAM          lParam
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    cbk_proc = xrkdbg.readLong(esp + 8)

    xrk_api_call("EnumDesktopsA", regs, {"handle": handle, "cbk_proc": cbk_proc})


def run_EnumDesktopsW(regs):
    """
        user32.EnumDesktopsW

        EnumDesktopsW-->InternalEnumObjects

          _In_opt_ HWINSTA         hwinsta,
          _In_     DESKTOPENUMPROC lpEnumFunc,
          _In_     LPARAM          lParam
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    cbk_proc = xrkdbg.readLong(esp + 8)

    xrk_api_call("EnumDesktopsW", regs, {"handle": handle, "cbk_proc": cbk_proc})


def run_EnumDisplayDevicesA(regs):
    """
        user32.EnumDisplayDevicesA

        EnumDisplayDevicesA-->NtUserEnumDisplayDevices(??)

          LPCTSTR lpDevice,
          DWORD iDevNum,
          PDISPLAY_DEVICE lpDisplayDevice,
          DWORD dwFlags
    """
    esp = regs["ESP"]
    file_dev = xrkutil.dbg_read_pstring(esp + 4)

    xrk_api_call("EnumDisplayDevicesA", regs, {"file_dev": file_dev})


def run_EnumDisplayDevicesW(regs):
    """
        user32.EnumDisplayDevicesW

        EnumDisplayDevicesW-->NtUserEnumDisplayDevices(??)

          LPCTSTR lpDevice,
          DWORD iDevNum,
          PDISPLAY_DEVICE lpDisplayDevice,
          DWORD dwFlags
    """
    esp = regs["ESP"]
    file_dev = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("EnumDisplayDevicesW", regs, {"file_dev": file_dev})


def run_FindWindowA(regs):
    """
        user32.FindWindowA

        FindWindowA-->InternalFindWindowExA

          _In_opt_ LPCTSTR lpClassName,
          _In_opt_ LPCTSTR lpWindowName
    """
    esp = regs["ESP"]
    window_class_name = xrkutil.dbg_read_pstring(esp + 4)
    window_name = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("FindWindowA", regs, {"window_class_name": window_class_name, "window_name": window_name})


def run_FindWindowW(regs):
    """
        user32.FindWindowW

        FindWindowW-->InternalFindWindowExW

          _In_opt_ LPCTSTR lpClassName,
          _In_opt_ LPCTSTR lpWindowName
    """
    esp = regs["ESP"]
    window_class_name = xrkutil.dbg_read_pwstring(esp + 4)
    window_name = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("FindWindowW", regs, {"window_class_name": window_class_name, "window_name": window_name})


def run_FindWindowExA(regs):
    """
        user32.FindWindowExA

        FindWindowExA-->InternalFindWindowExA

          _In_opt_ HWND    hwndParent,
          _In_opt_ HWND    hwndChildAfter,
          _In_opt_ LPCTSTR lpszClass,
          _In_opt_ LPCTSTR lpszWindow
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    handle_child = xrkdbg.readLong(esp + 8)
    window_class_name = xrkutil.dbg_read_pstring(esp + 0xC)
    window_name = xrkutil.dbg_read_pstring(esp + 0x10)

    xrk_api_call("FindWindowExA", regs, {"handle": handle, "handle_child": handle_child, "window_class_name": window_class_name, "window_name": window_name})


def run_FindWindowExW(regs):
    """
        user32.FindWindowExW

        FindWindowExW-->InternalFindWindowExW

          _In_opt_ HWND    hwndParent,
          _In_opt_ HWND    hwndChildAfter,
          _In_opt_ LPCTSTR lpszClass,
          _In_opt_ LPCTSTR lpszWindow
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    handle_child = xrkdbg.readLong(esp + 8)
    window_class_name = xrkutil.dbg_read_pwstring(esp + 0xC)
    window_name = xrkutil.dbg_read_pwstring(esp + 0x10)

    xrk_api_call("FindWindowExW", regs, {"handle": handle, "handle_child": handle_child, "window_class_name": window_class_name, "window_name": window_name})


def run_GetDesktopWindow(regs):
    """
        user32.GetDesktopWindow

          void
    """
    xrk_api_call("GetDesktopWindow", regs)


# -------------------------------------------------------------------------
# PIPE
# -------------------------------------------------------------------------


def run_CallNamedPipeW(regs):
    """
        kernel32.CallNamedPipeW

        CallNamedPipeA-->CallNamedPipeW

          _In_  LPCTSTR lpNamedPipeName,
          _In_  LPVOID  lpInBuffer,
          _In_  DWORD   nInBufferSize,
          _Out_ LPVOID  lpOutBuffer,
          _In_  DWORD   nOutBufferSize,
          _Out_ LPDWORD lpBytesRead,
          _In_  DWORD   nTimeOut
    """
    esp = regs["ESP"]
    file_pipe_name = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("CallNamedPipeW", regs, {"file_pipe_name": file_pipe_name})


def run_CreateNamedPipeW(regs):
    """
        kernel32.CreateNamedPipeW

        CreateNamedPipeA-->CreateNamedPipeW-->NtCreateNamedPipeFile(ntdll)

          _In_     LPCTSTR               lpName,
          _In_     DWORD                 dwOpenMode,
          _In_     DWORD                 dwPipeMode,
          _In_     DWORD                 nMaxInstances,
          _In_     DWORD                 nOutBufferSize,
          _In_     DWORD                 nInBufferSize,
          _In_     DWORD                 nDefaultTimeOut,
          _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
    """
    esp = regs["ESP"]
    file_pipe_name = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("CreateNamedPipeW", regs, {"file_pipe_name": file_pipe_name})


def run_CreatePipe(regs):
    """
        kernel32.CreatePipe

        CreatePipe-->NtCreateNamedPipeFile/NtOpenFile(ntdll)

          _Out_    PHANDLE               hReadPipe,
          _Out_    PHANDLE               hWritePipe,
          _In_opt_ LPSECURITY_ATTRIBUTES lpPipeAttributes,
          _In_     DWORD                 nSize
    """
    xrk_api_call("CreatePipe", regs)


def run_WaitNamedPipeW(regs):
    """
        kernel32.WaitNamedPipeW

        WaitNamedPipeA-->WaitNamedPipeW-->NtOpenFile/NtFsControlFile(ntdll)

          _In_ LPCTSTR lpNamedPipeName,
          _In_ DWORD   nTimeOut
    """
    esp = regs["ESP"]
    file_pipe_name = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("WaitNamedPipeW", regs, {"file_pipe_name": file_pipe_name})


def run_PeekNamedPipe(regs):
    """
        kernel32.PeekNamedPipe

        PeekNamedPipe-->NtFsControlFile(ntdll)

          _In_       HANDLE hNamedPipe,
          _Out_opt_  LPVOID lpBuffer,
          _In_       DWORD nBufferSize,
          _Out_opt_  LPDWORD lpBytesRead,
          _Out_opt_  LPDWORD lpTotalBytesAvail,
          _Out_opt_  LPDWORD lpBytesLeftThisMessage
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("PeekNamedPipe", regs, {"handle": handle})


def run_ConnectNamedPipe(regs):
    """
        kernel32.ConnectNamedPipe

        ConnectNamedPipe-->NtFsControlFile(ntdll)

          _In_        HANDLE       hNamedPipe,
          _Inout_opt_ LPOVERLAPPED lpOverlapped
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("ConnectNamedPipe", regs, {"handle": handle})


def run_DisconnectNamedPipe(regs):
    """
        kernel32.DisconnectNamedPipe

        DisconnectNamedPipe-->NtFsControlFile(ntdll)

          _In_ HANDLE hNamedPipe
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("DisconnectNamedPipe", regs, {"handle": handle})


# -------------------------------------------------------------------------
# ENVIRONMENT
# -------------------------------------------------------------------------


def run_GetEnvironmentStringsA(regs):
    """
        kernel32.GetEnvironmentStringsA

          void
    """
    xrk_api_call("GetEnvironmentStringsA", regs)


def run_GetEnvironmentStringsW(regs):
    """
        kernel32.GetEnvironmentStringsW

          void
    """
    xrk_api_call("GetEnvironmentStringsW", regs)


def run_GetEnvironmentVariableA(regs):
    """
        kernel32.GetEnvironmentVariableA

        GetEnvironmentVariableA-->RtlQueryEnvironmentVariable_U(ntdll)

          _In_opt_  LPCTSTR lpName,
          _Out_opt_ LPTSTR  lpBuffer,
          _In_      DWORD   nSize
    """
    esp = regs["ESP"]
    name = xrkutil.dbg_read_pstring(esp + 4)

    xrk_api_call("GetEnvironmentVariableA", regs, {"name": name})


def run_GetEnvironmentVariableW(regs):
    """
        kernel32.GetEnvironmentVariableW

        GetEnvironmentVariableW-->RtlQueryEnvironmentVariable_U(ntdll)

          _In_opt_  LPCTSTR lpName,
          _Out_opt_ LPTSTR  lpBuffer,
          _In_      DWORD   nSize
    """
    esp = regs["ESP"]
    name = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("GetEnvironmentVariableW", regs, {"name": name})


def run_SetEnvironmentVariableA(regs):
    """
        kernel32.SetEnvironmentVariableA

        SetEnvironmentVariableA-->RtlSetEnvironmentVariable(ntdll)

          _In_     LPCTSTR lpName,
          _In_opt_ LPCTSTR lpValue
    """
    esp = regs["ESP"]
    name = xrkutil.dbg_read_pstring(esp + 4)
    value = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("SetEnvironmentVariableA", regs, {"name": name, "value": value})


def run_SetEnvironmentVariableW(regs):
    """
        kernel32.SetEnvironmentVariableW

        SetEnvironmentVariableW-->RtlSetEnvironmentVariable(ntdll)

          _In_     LPCTSTR lpName,
          _In_opt_ LPCTSTR lpValue
    """
    esp = regs["ESP"]
    name = xrkutil.dbg_read_pwstring(esp + 4)
    value = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("SetEnvironmentVariableW", regs, {"name": name, "value": value})


def run_ExpandEnvironmentStringsA(regs):
    """
        kernel32.ExpandEnvironmentStringsA

        ExpandEnvironmentStringsA-->RtlExpandEnvironmentStrings_U(ntdll)

          _In_      LPCTSTR lpSrc,
          _Out_opt_ LPTSTR  lpDst,
          _In_      DWORD   nSize
    """
    esp = regs["ESP"]
    src = xrkutil.dbg_read_pstring(esp + 4)

    xrk_api_call("ExpandEnvironmentStringsA", regs, {"src": src})


def run_ExpandEnvironmentStringsW(regs):
    """
        kernel32.ExpandEnvironmentStringsW

        ExpandEnvironmentStringsW-->RtlExpandEnvironmentStrings_U(ntdll)

          _In_      LPCTSTR lpSrc,
          _Out_opt_ LPTSTR  lpDst,
          _In_      DWORD   nSize
    """
    esp = regs["ESP"]
    src = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("ExpandEnvironmentStringsW", regs, {"src": src})


# -------------------------------------------------------------------------
# MISC ESSENTIONAL
# -------------------------------------------------------------------------


def run_SleepEx(regs):
    """
        kernel32.SleepEx

        Sleep-->SleepEx-->NtDelayExecution(ntdll)

          _In_  DWORD dwMilliseconds,
          _In_  BOOL bAlertable
    """
    addr = regs["ESP"] + 0x4
    msecs = xrkdbg.readLong(addr)

    xrk_api_call("SleepEx", regs, {"msecs": msecs})

    k_SleepEx = __get_api_config("SleepEx")
    if k_SleepEx["shorten_edge"] != 0:
        if msecs >= k_SleepEx["shorten_edge"]:
            xrkdbg.writeLong(addr, 1)


def run_VirtualProtectEx(regs):
    """
        kernel32.VirtualProtectEx

        VirtualProtect-->VirtualProtectEx-->NtProtectVirtualMemory(ntdll)

          _In_  HANDLE hProcess,
          _In_  LPVOID lpAddress,
          _In_  SIZE_T dwSize,
          _In_  DWORD  flNewProtect,
          _Out_ PDWORD lpflOldProtect
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    addr = xrkdbg.readLong(esp + 8)
    size = xrkdbg.readLong(esp + 12)

    xrk_api_call("VirtualProtectEx", regs, {"handle": handle, "addr": addr, "size": size})


def run_LoadLibraryW(regs):
    """
        kernel32.LoadLibraryW

        LoadLibraryA-->LoadLibraryExA-->LoadLibraryExW-->LdrLoadDll(ntdll)
        LoadLibraryW-->LoadLibraryExW==>>||

          _In_        LPCTSTR lpFileName
    """
    esp = regs["ESP"]
    file_name = xrkutil.dbg_read_pstring(esp + 4)

    xrk_api_call("LoadLibraryW", regs, {"file_name": file_name})

    # itd_lib_name_check(get_cloud_monCtrl(), "LoadLibraryW", file_name)


def run_LoadLibraryExA(regs):
    """
        kernel32.LoadLibraryExA

        LoadLibraryA-->LoadLibraryExA-->LoadLibraryExW-->LdrLoadDll(ntdll)
        LoadLibraryW-->LoadLibraryExW==>>||

          _In_        LPCTSTR lpFileName,
          _Reserved_  HANDLE hFile,
          _In_        DWORD dwFlags
    """
    # we don't make filter for LoadLibraryA, and actually we don't hook LoadLibraryA, because imm parses stack well
    esp = regs["ESP"]
    file_name = xrkutil.dbg_read_pstring(esp + 4)

    xrk_api_call("LoadLibraryExA", regs, {"file_name": file_name})

    # itd_lib_name_check(get_cloud_monCtrl(), "LoadLibraryExA", file_name)


def run_LoadLibraryExW(regs):
    """
        kernel32.LoadLibraryExW

        LoadLibraryA-->LoadLibraryExA-->LoadLibraryExW-->LdrLoadDll(ntdll)
        LoadLibraryW-->LoadLibraryExW==>>||

          _In_        LPCTSTR lpFileName,
          _Reserved_  HANDLE hFile,
          _In_        DWORD dwFlags
    """
    #
    # LoadLibraryExA(xp sp3):
    # 7C801D53 mov  edi, edi
    # ...
    # 7C801D6D call _LoadLibraryExW@12 # 0x1A
    # ...
    #
    is_from_LoadLibraryExA = __filter_caller_fast("LoadLibraryExA", 0x1A)

    #
    # LoadLibraryW(xp sp3):
    # 7C80AEDB mov  edi, edi
    # ...
    # 7C80AEE7 call _LoadLibraryExW@12 # 0xC
    # ...
    #
    is_from_LoadLibraryW = __filter_caller_fast("LoadLibraryW", 0xC)

    if not is_from_LoadLibraryExA and not is_from_LoadLibraryW:

        esp = regs["ESP"]
        file_name = xrkutil.dbg_read_pwstring(esp + 4)

        xrk_api_call("LoadLibraryExW", regs, {"file_name": file_name})

        # itd_lib_name_check(get_cloud_monCtrl(), "LoadLibraryExW", file_name)


def run_GetProcAddress(regs):
    """
        kernel32.GetProcAddress

        GetProcAddress-->LdrGetProcedureAddress

          HMODULE hModule,
          LPCWSTR lpProcName
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    if xrkutil.validate_addr(xrkdbg.readLong(esp + 8)):
        name = xrkutil.dbg_read_pstring(esp + 8)
    else:
        name = xrkdbg.readLong(esp + 8)

    xrk_api_call("GetProcAddress", regs, {"handle": handle, "name": name})


def run_IsDebuggerPresent(regs):
    """
        kernel32.IsDebuggerPresent

          void
    """
    xrk_api_call("IsDebuggerPresent", regs)


# -------------------------------------------------------------------------
# MISC OPTIONAL
# -------------------------------------------------------------------------


def run_SetErrorMode(regs):
    """
        kernel32.SetErrorMode

        SetErrorMode-->NtSetInformationProcess

            _In_ UINT uMode
    """
    esp = regs["ESP"]
    mode = xrkdbg.readLong(esp + 4)
    modes = ""
    if mode & 1:
        modes = modes + "|" + "SEM_FAILCRITICALERRORS"
    if mode & 2:
        modes = modes + "|" + "SEM_NOGPFAULTERRORBOX"
    if mode & 4:
        modes = modes + "|" + "SEM_NOALIGNMENTFAULTEXCEPT"
    if mode & 0x8000:
        modes = modes + "|" + "SEM_NOOPENFILEERRORBOX"

    xrk_api_call("SetErrorMode", regs, {"mode": modes})


def run_SetUnhandledExceptionFilter(regs):
    """
        kernel32.SetUnhandledExceptionFilter

          _In_ LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
    """
    xrk_api_call("SetUnhandledExceptionFilter", regs)


def run_ShellExecuteExW(regs):
    """
        shell32.ShellExecuteExW

        ShellExecuteA-->ShellExecuteExA-->ShellExecuteExW-->ShellExecuteNormal
        ShellExecuteW-->ShellExecuteExW==>>||
        RealShellExecuteA-->RealShellExecuteExA-->ShellExecuteExA==>>||
        RealShellExecuteW-->RealShellExecuteExW-->ShellExecuteExW==>>||
        WOWShellExecute-->RealShellExecuteExA==>>||
        ShellExec_RunDLLA-->_ShellExec_RunDLL-->ShellExecuteExW
        ShellExec_RunDLLW-->_ShellExec_RunDLL==>>||

        ?+ since this will callinto: kernel32.CreateProcessInternalW, so this might be not necessary?

          LPSHELLEXECUTEINFO lpExecInfo
    """
    esp = regs["ESP"]
    info = xrkdbg.readLong(esp + 4)
    verb = xrkutil.dbg_read_pwstring(info + 0xC)
    file = xrkutil.dbg_read_pwstring(info + 0x10)
    parm = xrkutil.dbg_read_pwstring(info + 0x14)
    dir_ = xrkutil.dbg_read_pwstring(info + 0x18)

    xrk_api_call("ShellExecuteExWHook", regs, {"verb": verb, "file": file, "parm": parm, "dir": dir_})


def run_QueueUserAPC(regs):
    """
        kernel32.QueueUserAPC

        QueueUserAPC-->NtQueueApcThread(ntdll)

          _In_  PAPCFUNC pfnAPC,
          _In_  HANDLE hThread,
          _In_  ULONG_PTR dwData
    """
    esp = regs["ESP"]
    cbk_proc = xrkdbg.readLong(esp + 4)

    xrk_api_call("QueueUserAPC", regs, {"cbk_proc": cbk_proc})


def run_RaiseException(regs):
    """
        kernel32.RaiseException

        RaiseException-->RtlRaiseException(ntdll)

          DWORD dwExceptionCode,
          DWORD dwExceptionFlags,
          DWORD nNumberOfArguments,
          const DWORD* lpArguments
    """
    xrk_api_call("RaiseException", regs)


def run_GetComputerNameW(regs):
    """
        kernel32.GetComputerNameW

        GetComputerNameA-->GetComputerNameW-->NtOpenKey/NtCreateKey(ntdll)

          _Out_   LPTSTR  lpBuffer,
          _Inout_ LPDWORD lpnSize
    """
    xrk_api_call("GetComputerNameW", regs)


def run_GetComputerNameExW(regs):
    """
        kernel32.GetComputerNameExW

        GetComputerNameExA-->GetComputerNameExW-->BasepGetNameFromReg

          _In_    COMPUTER_NAME_FORMAT NameType,
          _Out_   LPTSTR               lpBuffer,
          _Inout_ LPDWORD              lpnSize
    """
    xrk_api_call("GetComputerNameExW", regs)


def run_SetComputerNameW(regs):
    """
        kernel32.SetComputerNameW

        SetComputerNameA-->SetComputerNameW-->NtOpenKey/NtSetValueKey(ntdll)

          _In_ LPCTSTR lpComputerName
    """
    esp = regs["ESP"]
    name = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("SetComputerNameW", regs, {"name": name})


def run_SetComputerNameExW(regs):
    """
        kernel32.SetComputerNameExW

        SetComputerNameExA-->SetComputerNameExW-->BaseSetNetbiosName/BaseSetNetbiosName/BaseSetDnsName

          _In_ COMPUTER_NAME_FORMAT NameType,
          _In_ LPCTSTR              lpBuffer
    """
    esp = regs["ESP"]
    name = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("SetComputerNameExW", regs, {"name": name})


def run_GetModuleFileNameW_retn(regs, addr, size, fake_md_name):
    """
        retn of GetModuleFileNameW, modify it's retn
    """
    xrkutil.write_wstr(addr, fake_md_name)
    xrklog.high("faking md file name at %.8X to: %s" % (addr, fake_md_name))

    if "GetModuleFileNameW_RETN" in xrkdbg.listHooks():
        xrkdbg.remove_hook("GetModuleFileNameW_RETN")


def run_GetModuleFileNameW(regs):
    """
        kernel32.GetModuleFileNameW

        GetModuleFileNameA-->GetModuleFileNameW

          _In_opt_ HMODULE hModule,
          _Out_    LPTSTR  lpFilename,
          _In_     DWORD   nSize

        1. check if getting main pe path(don't check cstk)
        2. check fake_md_name
        3. install retn hook

        !+ for xp sp3, retn of GetModuleFileNameW only has 1 address
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    addr = xrkdbg.readLong(esp + 0x8)
    size = xrkdbg.readLong(esp + 0xC)

    xrk_api_call("GetModuleFileNameW", regs, {"handle": handle})

    if handle == 0:

        # we ignore multi thread situations here.
        assert "GetModuleFileNameW_RETN" not in xrkdbg.listHooks()
        k_GetModuleFileNameW = __get_api_config("GetModuleFileNameW")
        fake_md_name = k_GetModuleFileNameW["fake_md_name"]
        if fake_md_name is not None and len(fake_md_name) > 0 and len(fake_md_name) <= size - 2:

            retn_addrs = xrkdbg.getFunctionEnd(regs["EIP"])
            # xp sp3
            assert len(retn_addrs) == 1

            xrkmonctrl.install_addr_hook_ex(retn_addrs[0], "GetModuleFileNameW_RETN", run_GetModuleFileNameW_retn, shall_pause=False, param1=addr, param2=size, param3=fake_md_name)


def run_GetVersion(regs):
    """
        kernel32.GetVersion

          void
    """
    xrk_api_call("GetVersion", regs)


def run_GetVersionExA(regs):
    """
        kernel32.GetVersionExA

        GetVersionExA-->GetVersionExW

          _Inout_ LPOSVERSIONINFO lpVersionInfo
    """
    xrk_api_call("GetVersionExA", regs)


def run_GetVersionExW(regs):
    """
        kernel32.GetVersionExW

        GetVersionExA-->GetVersionExW

          _Inout_ LPOSVERSIONINFO lpVersionInfo
    """
    #
    # GetVersionExA(xp sp3)
    # 7C812B6E mov  edi, edi
    # ...
    # 7C812BAD call _GetVersionExW@4 # 0x3F
    # ...
    #
    is_from_GetVersionExA = __filter_caller_fast("GetVersionExA", 0x3F)

    if not is_from_GetVersionExA:
        xrk_api_call("GetVersionExW", regs)


def run_CreateMailslotW(regs):
    """
        kernel32.CreateMailslotW

        CreateMailslotA-->CreateMailslotW-->NtCreateMailslotFile(ntdll)

          _In_     LPCTSTR               lpName,
          _In_     DWORD                 nMaxMessageSize,
          _In_     DWORD                 lReadTimeout,
          _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
    """
    esp = regs["ESP"]
    name = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("CreateMailslotW", regs, {"name": name})


def run_GetCommandLineA(regs):
    """
        kernel32.GetCommandLineA

          void
    """
    xrk_api_call("GetCommandLineA", regs)


def run_GetCommandLineW(regs):
    """
        kernel32.GetCommandLineW

          void
    """
    xrk_api_call("GetCommandLineW", regs)


def run_GetStartupInfoA(regs):
    """
        kernel32.GetStartupInfoA

          _Out_ LPSTARTUPINFO lpStartupInfo
    """
    xrk_api_call("GetStartupInfoA", regs)


def run_GetStartupInfoW(regs):
    """
        kernel32.GetStartupInfoW

          _Out_ LPSTARTUPINFO lpStartupInfo
    """
    xrk_api_call("GetStartupInfoW", regs)


def run_OutputDebugStringA(regs):
    """
        kernel32.OutputDebugStringA

        OutputDebugStringW-->OutputDebugStringA-->RaiseException

          LPCTSTR lpOutputString
    """
    esp = regs["ESP"]
    str_ = xrkutil.dbg_read_pstring(esp + 4)

    xrk_api_call("OutputDebugStringA", regs, {"str": str_})


def run_SetSystemPowerState(regs):
    """
        kernel32.SetSystemPowerState

        SetSystemPowerState-->NtInitiatePowerAction(ntdll)

          _In_ BOOL fSuspend,
          _In_ BOOL fForce
    """
    esp = regs["ESP"]
    is_suspend = xrkdbg.readLong(esp + 4)
    is_force = xrkdbg.readLong(esp + 8)

    xrk_api_call("SetSystemPowerState", regs, {"is_suspend": is_suspend, "is_force": is_force})


def run_SetSystemTime(regs):
    """
        kernel32.SetSystemTime

        SetSystemTime-->NtSetSystemTime(ntdll)

          _In_ const SYSTEMTIME *lpSystemTime
    """
    xrk_api_call("SetSystemTime", regs)


def run_SetSystemTimeAdjustment(regs):
    """
        kernel32.SetSystemTimeAdjustment

        SetSystemTimeAdjustment-->NtSetSystemInformation(ntdll)

          _In_  DWORD dwTimeAdjustment,
          _In_  BOOL bTimeAdjustmentDisabled
    """
    xrk_api_call("SetSystemTimeAdjustment", regs)


# -------------------------------------------------------------------------
# OTHER
# -------------------------------------------------------------------------


def run_GetSystemTime(regs):
    """
        kernel32.GetSystemTime

        GetSystemTime-->??/RtlTimeToTimeFields

          LPSYSTEMTIME lpSystemTime
    """
    xrk_api_call("GetSystemTime", regs)


def run_GetTempPathW(regs):
    """
        kernel32.GetTempPathW

        GetTempPathA-->GetTempPathW-->BasepGetTempPathW-->RtlQueryEnvironmentVariable_U

          _In_  DWORD  nBufferLength,
          _Out_ LPTSTR lpBuffer
    """
    xrk_api_call("GetTempPathW", regs)


def run_GetSystemDirectoryA(regs):
    """
        kernel32.GetSystemDirectoryA

        GetSystemDirectoryA-->BaseWindowsSystemDirectory/RtlUnicodeToMultiByteSize/xx

          _Out_ LPTSTR lpBuffer,
          _In_  UINT   uSize
    """
    xrk_api_call("GetSystemDirectoryA", regs)


def run_GetSystemDirectoryW(regs):
    """
        kernel32.GetSystemDirectoryW

        GetSystemDirectoryW-->BaseWindowsSystemDirectory

          _Out_ LPTSTR lpBuffer,
          _In_  UINT   uSize
    """
    xrk_api_call("GetSystemDirectoryW", regs)


def run_SetProcessWindowStation(regs):
    """
        user32.SetProcessWindowStation

          _In_ HWINSTA hWinSta
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("SetProcessWindowStation", regs, {"handle": handle})


def run_OpenDesktopA(regs):
    """
        user32.OpenDesktopA

        OpenDesktopA-->CommonOpenDesktop

          _In_ LPTSTR      lpszDesktop,
          _In_ DWORD       dwFlags,
          _In_ BOOL        fInherit,
          _In_ ACCESS_MASK dwDesiredAccess
    """
    esp = regs["ESP"]
    desktop = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("OpenDesktopA", regs, {"desktop": desktop})


def run_OpenDesktopW(regs):
    """
        user32.OpenDesktopW

        OpenDesktopW-->CommonOpenDesktop

          _In_ LPTSTR      lpszDesktop,
          _In_ DWORD       dwFlags,
          _In_ BOOL        fInherit,
          _In_ ACCESS_MASK dwDesiredAccess
    """
    esp = regs["ESP"]
    desktop = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("OpenDesktopW", regs, {"desktop": desktop})


def run_SetThreadDesktop(regs):
    """
        user32.SetThreadDesktop

        SetThreadDesktop??

          _In_ HDESK hDesktop
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("SetThreadDesktop", regs, {"handle": handle})


def run_OpenWindowStationA(regs):
    """
        user32.OpenWindowStationA

        OpenWindowStationA-->CommonOpenWindowStation

          _In_ LPTSTR      lpszWinSta,
          _In_ BOOL        fInherit,
          _In_ ACCESS_MASK dwDesiredAccess
    """
    esp = regs["ESP"]
    station = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("OpenWindowStationA", regs, {"station": station})


def run_OpenWindowStationW(regs):
    """
        user32.OpenWindowStationW

        OpenWindowStationW-->CommonOpenWindowStation

          _In_ LPTSTR      lpszWinSta,
          _In_ BOOL        fInherit,
          _In_ ACCESS_MASK dwDesiredAccess
    """
    esp = regs["ESP"]
    station = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("OpenWindowStationW", regs, {"station": station})


def run_OpenProcessToken(regs):
    """
        advapi32.OpenProcessToken

        OpenProcessToken-->NtOpenProcessToken

          _In_  HANDLE  ProcessHandle,
          _In_  DWORD   DesiredAccess,
          _Out_ PHANDLE TokenHandle
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("OpenProcessToken", regs, {"handle": handle})


def run_WNetUseConnectionW(regs):
    """
        mpr.WNetUseConnectionW

        WNetAddConnectionA-->WNetAddConnectionW-->WNetUseConnectionW-->CUseConnection::CUseConnection/
        WNetAddConnection2A-->WNetUseConnectionA-->WNetUseConnectionW==>>||
        WNetAddConnection2W-->WNetUseConnectionW==>>||
        WNetAddConnection3A-->WNetUseConnectionA==>>||
        WNetAddConnection3W-->WNetUseConnectionW==>>||

          _In_    HWND          hwndOwner,
          _In_    LPNETRESOURCE lpNetResource,
          _In_    LPCTSTR       lpPassword,
          _In_    LPCTSTR       lpUserID,
          _In_    DWORD         dwFlags,
          _Out_   LPTSTR        lpAccessName,
          _Inout_ LPDWORD       lpBufferSize,
          _Out_   LPDWORD       lpResult
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    pwd = xrkutil.dbg_read_pwstring(esp + 0xC)
    userid = xrkutil.dbg_read_pwstring(esp + 0x10)

    xrk_api_call("WNetUseConnectionW", regs, {"handle": handle, "pwd": pwd, "userid": userid})


def run_GetModuleHandleW(regs):
    """
        kernel32.GetModuleHandleW

        GetModuleHandleA-->GetModuleHandleW-->BasepGetModuleHandleExW

          _In_opt_ LPCTSTR lpModuleName

        !+ If this parameter is NULL, GetModuleHandle returns a handle to the file used to create the calling process
    """
    esp = regs["ESP"]
    file_name = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("GetModuleHandleW", regs, {"file_name": file_name})


def run_GetModuleHandleExW(regs):
    """
        kernel32.GetModuleHandleExW

        GetModuleHandleExA-->GetModuleHandleExW-->BasepGetModuleHandleExW

          _In_     DWORD   dwFlags,
          _In_opt_ LPCTSTR lpModuleName,
          _Out_    HMODULE *phModule

        !+ If this parameter is NULL, GetModuleHandle returns a handle to the file used to create the calling process
    """
    esp = regs["ESP"]
    file_name = xrkutil.dbg_read_pwstring(esp + 0x8)

    xrk_api_call("GetModuleHandleExW", regs, {"file_name": file_name})


def retnGetTickCountHook(LogBpHook):
    def __init__(self, new_tick):
        LogBpHook.__init__(self)
        self.new_tick = new_tick

    def run(self, regs):
        """
            update to new tick
        """
        xrklog.info("update GetTickCount result from %d to %d" % (regs["EAX"], self.new_tick))
        xrkdbg.setReg("EAX", self.new_tick)
        self.UnHook()


def run_GetTickCount(regs):
    """
        kerner32.GetTickCount

          void

        !+ TODO: time related
    """
    xrk_api_call("GetTickCount", regs)

    k_GetTickCount = __get_api_config("GetTickCount")
    if k_GetTickCount["new_tick"] != 0:
        if "GetTickCount_RETN" not in xrkdbg.listHooks():
            retn_addrs = xrkdbg.getFunctionEnd(regs["EIP"])
            # xp sp3
            assert len(retn_addrs) == 1
            h = retnGetTickCountHook(k_GetTickCount["new_tick"])
            h.add("GetTickCount_RETN", retn_addrs[0])
            xrklog.info("add retn hook for GetTickCount at %.8X" % retn_addrs[0], verbose=True)


def run_SetTimer(regs):
    """
        user32.SetTimer

          _In_opt_ HWND      hWnd,
          _In_     UINT_PTR  nIDEvent,
          _In_     UINT      uElapse,
          _In_opt_ TIMERPROC lpTimerFunc
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    evt_id = xrkdbg.readLong(esp + 8)
    elaspe = xrkdbg.readLong(esp + 0xC)
    cbk_timer = xrkdbg.readLong(esp + 0x10)

    xrk_api_call("SetTimer", regs, {"handle": handle, "evt_id": evt_id, "elaspe": elaspe, "cbk_timer": cbk_timer})


def run_SetSystemTimer(regs):
    """
        user32.SetSystemTimer

          _In_ const SYSTEMTIME *lpSystemTime
    """
    xrk_api_call("SetSystemTimer", regs)


def run_KillTimer(regs):
    """
        user32.KillTimer

          _In_opt_  HWND hWnd,
          _In_      UINT_PTR uIDEvent
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)
    evt_id = xrkdbg.readLong(esp + 8)

    xrk_api_call("KillTimer", regs, {"handle": handle, "evt_id": evt_id})


def run_KillSystemTimer(regs):
    """
        user32.KillSystemTimer

        !+ not in msdg
    """
    pass


def run_CreateEventW(regs):
    """
        kernel32.CreateEventW

        CreateEventA --> CreateEventW --> NtCreateEvent

          _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
          _In_     BOOL                  bManualReset,
          _In_     BOOL                  bInitialState,
          _In_opt_ LPCTSTR               lpName
    """
    esp = regs["ESP"]
    evt_name = xrkutil.dbg_read_pwstring(esp + 0x10)

    xrk_api_call("CreateEventW", regs, {"evt_name": evt_name})


def run_OpenEventW(regs):
    """
        kernel32.OpenEventW

        OpenEventA --> OpenEventW --> NtOpenEvent

          _In_  DWORD dwDesiredAccess,
          _In_  BOOL bInheritHandle,
          _In_  LPCTSTR lpName
    """
    esp = regs["ESP"]
    evt_name = xrkutil.dbg_read_pwstring(esp + 0xC)

    xrk_api_call("OpenEventW", regs, {"evt_name": evt_name})


def run_SetEvent(regs):
    """
        kernel32.SetEvent

        SetEvent --> NtSetEvent

          HANDLE hEvent
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("SetEvent", regs, {"handle": handle})


def run_ResetEvent(regs):
    """
        kernel32.ResetEvent

        ResetEvent --> NtClearEvent

          HANDLE hEvent
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("ResetEvent", regs, {"handle": handle})


def run_PulseEvent(regs):
    """
        kernel32.PulseEvent

        PulseEvent --> NtPulseEvent

          HANDLE hEvent
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("PulseEvent", regs, {"handle": handle})


def run_DisableThreadLibraryCalls(regs):
    """
        kernel32.DisableThreadLibraryCalls

        DisableThreadLibraryCalls-->LdrDisableThreadCalloutsForDll

          HMODULE hLibModule
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("DisableThreadLibraryCalls", regs, {"handle": handle})


def run_FileTimeToSystemTime(regs):
    """
        kernel32.FileTimeToSystemTime

        FileTimeToSystemTime-->RtlTimeToTimeFields

          const FILETIME* lpFileTime,
          LPSYSTEMTIME lpSystemTime
    """
    xrk_api_call("FileTimeToSystemTime", regs)


def run_SystemTimeToFileTime(regs):
    """
        kernel32.SystemTimeToFileTime

        SystemTimeToFileTime-->RtlTimeFieldsToTime

          const SYSTEMTIME* lpSystemTime,
          LPFILETIME lpFileTime
    """
    xrk_api_call("SystemTimeToFileTime", regs)


def run_RasGetConnectStatusW(regs):
    """
        rasapi32.RasGetConnectStatusW

        RasGetConnectStatusA-->RasGetConnectStatusW

          _In_    HRASCONN        hrasconn,
          _Inout_ LPRASCONNSTATUS lprasconnstatus

        !+ TODO: others
    """
    xrk_api_call("RasGetConnectStatusW", regs)


def run_WaitForSingleObjectEx(regs):
    """
        kernel32.WaitForSingleObjectEx

        WaitForSingleObject-->WaitForSingleObjectEx-->NtWaitForSingleObject

          HANDLE hHandle,
          DWORD dwMilliseconds
          BOOL bAlertable
    """
    esp = regs["ESP"]
    handle = xrkdbg.readLong(esp + 4)

    xrk_api_call("WaitForSingleObjectEx", regs, {"handle": handle})


def run_WaitForMultipleObjectsEx(regs):
    """
        kernel32.WaitForMultipleObjectsEx

        WaitForMultipleObjects-->WaitForMultipleObjectsEx-->NtWaitForMultipleObjects

          _In_       DWORD  nCount,
          _In_ const HANDLE *lpHandles,
          _In_       BOOL   bWaitAll,
          _In_       DWORD  dwMilliseconds
          _In_       BOOL bAlertable
    """
    esp = regs["ESP"]
    cnt = xrkdbg.readLong(esp + 4)

    xrk_api_call("WaitForMultipleObjectsEx", regs, {"cnt": cnt})


def run_SetProcessDEPPolicy(regs):
    """
        kernel32.SetProcessDEPPolicy

        SetProcessDEPPolicy-->NtSetInformationProcess

          _In_ DWORD dwFlags
    """
    xrk_api_call("SetProcessDEPPolicy", regs)


# -------------------------------------------------------------------------
# CRYPT
# -------------------------------------------------------------------------


def run_CryptAcquireContextA(regs):
    """
        advapi32.CryptAcquireContextA

        CryptAcquireContextW-->CryptAcquireContextA-->RegOpenKeyExA/RegQueryValueExA/....

          _Out_ HCRYPTPROV *phProv,
          _In_  LPCTSTR    pszContainer,
          _In_  LPCTSTR    pszProvider,
          _In_  DWORD      dwProvType,
          _In_  DWORD      dwFlags
    """
    esp = regs["ESP"]
    container = xrkutil.dbg_read_pstring(esp + 8)
    provider = xrkutil.dbg_read_pstring(esp + 0xC)

    xrk_api_call("CryptAcquireContextA", regs, {"container": container, "provider": provider})


def run_CryptReleaseContext(regs):
    """
        advapi32.CryptReleaseContext

          _In_ HCRYPTPROV hProv,
          _In_ DWORD      dwFlags
    """
    xrk_api_call("CryptReleaseContext", regs)


def run_CryptSetProvParam(regs):
    """
        advapi32.CryptSetProvParam

          _In_       HCRYPTPROV hProv,
          _In_       DWORD      dwParam,
          _In_ const BYTE       *pbData,
          _In_       DWORD      dwFlags
    """
    xrk_api_call("CryptSetProvParam", regs)


def run_CryptGetProvParam(regs):
    """
        advapi32.CryptGetProvParam

          _In_     HCRYPTPROV hProv,
          _In_     DWORD dwParam,
          _Out_    BYTE *pbData,
          _Inout_  DWORD *pdwDataLen,
          _In_     DWORD dwFlags
    """
    xrk_api_call("CryptGetProvParam", regs)


def run_CryptCreateHash(regs):
    """
        advapi32.CryptCreateHash

          _In_  HCRYPTPROV hProv,
          _In_  ALG_ID     Algid,
          _In_  HCRYPTKEY  hKey,
          _In_  DWORD      dwFlags,
          _Out_ HCRYPTHASH *phHash
    """
    xrk_api_call("CryptCreateHash", regs)


def run_CryptHashData(regs):
    """
        advapi32.CryptHashData

          _In_ HCRYPTHASH hHash,
          _In_ BYTE       *pbData,
          _In_ DWORD      dwDataLen,
          _In_ DWORD      dwFlags
    """
    xrk_api_call("CryptHashData", regs)


def run_CryptGetHashParam(regs):
    """
        advapi32.CryptGetHashParam

          _In_    HCRYPTHASH hHash,
          _In_    DWORD      dwParam,
          _Out_   BYTE       *pbData,
          _Inout_ DWORD      *pdwDataLen,
          _In_    DWORD      dwFlags
    """
    xrk_api_call("CryptGetHashParam", regs)


def run_CryptSetHashParam(regs):
    """
        advapi32.CryptSetHashParam

          _In_  HCRYPTHASH hHash,
          _In_  DWORD dwParam,
          _In_  const BYTE *pbData,
          _In_  DWORD dwFlags
    """
    xrk_api_call("CryptSetHashParam", regs)


def run_CryptHashSessionKey(regs):
    """
        advapi32.CryptHashSessionKey

          _In_ HCRYPTHASH hHash,
          _In_ HCRYPTKEY  hKey,
          _In_ DWORD      dwFlags
    """
    xrk_api_call("CryptHashSessionKey", regs)


def run_CryptDestroyHash(regs):
    """
        advapi32.CryptDestroyHash

          _In_ HCRYPTHASH hHash
    """
    xrk_api_call("CryptDestroyHash", regs)


def run_CryptGenRandom(regs):
    """
        advapi32.CryptGenRandom

          _In_    HCRYPTPROV hProv,
          _In_    DWORD      dwLen,
          _Inout_ BYTE       *pbBuffer
    """
    xrk_api_call("CryptGenRandom", regs)


def run_CryptDeriveKey(regs):
    """
        advapi32.CryptDeriveKey

          _In_    HCRYPTPROV hProv,
          _In_    ALG_ID     Algid,
          _In_    HCRYPTHASH hBaseData,
          _In_    DWORD      dwFlags,
          _Inout_ HCRYPTKEY  *phKey
    """
    xrk_api_call("CryptDeriveKey", regs)


def run_CryptGenKey(regs):
    """
        advapi32.CryptGenKey

          _In_  HCRYPTPROV hProv,
          _In_  ALG_ID     Algid,
          _In_  DWORD      dwFlags,
          _Out_ HCRYPTKEY  *phKey
    """
    xrk_api_call("CryptGenKey", regs)


def run_CryptDestroyKey(regs):
    """
        advapi32.CryptDestroyKey

          _In_ HCRYPTKEY hKey
    """
    xrk_api_call("CryptDestroyKey", regs)


def run_CryptImportKey(regs):
    """
        advapi32.CryptImportKey

          _In_  HCRYPTPROV hProv,
          _In_  BYTE       *pbData,
          _In_  DWORD      dwDataLen,
          _In_  HCRYPTKEY  hPubKey,
          _In_  DWORD      dwFlags,
          _Out_ HCRYPTKEY  *phKey
    """
    xrk_api_call("CryptImportKey", regs)


def run_CryptExportKey(regs):
    """
        advapi32.CryptExportKey

          _In_    HCRYPTKEY hKey,
          _In_    HCRYPTKEY hExpKey,
          _In_    DWORD     dwBlobType,
          _In_    DWORD     dwFlags,
          _Out_   BYTE      *pbData,
          _Inout_ DWORD     *pdwDataLen
    """
    xrk_api_call("CryptExportKey", regs)


def run_CryptGetKeyParam(regs):
    """
        advapi32.CryptGetKeyParam

          _In_    HCRYPTKEY hKey,
          _In_    DWORD     dwParam,
          _Out_   BYTE      *pbData,
          _Inout_ DWORD     *pdwDataLen,
          _In_    DWORD     dwFlags
    """
    xrk_api_call("CryptGetKeyParam", regs)


def run_CryptSetKeyParam(regs):
    """
        advapi32.CryptSetKeyParam

          _In_       HCRYPTKEY hKey,
          _In_       DWORD     dwParam,
          _In_ const BYTE      *pbData,
          _In_       DWORD     dwFlags
    """
    xrk_api_call("CryptSetKeyParam", regs)


def run_CryptGetUserKey(regs):
    """
        advapi32.CryptGetUserKey

          _In_   HCRYPTPROV hProv,
          _In_   DWORD dwKeySpec,
          _Out_  HCRYPTKEY *phUserKey
    """
    xrk_api_call("CryptGetUserKey", regs)


def run_CryptSignHashA(regs):
    """
        advapi32.CryptSignHashA

        CryptSignHashA-->LocalSignHashW

          _In_    HCRYPTHASH hHash,
          _In_    DWORD      dwKeySpec,
          _In_    LPCTSTR    sDescription,
          _In_    DWORD      dwFlags,
          _Out_   BYTE       *pbSignature,
          _Inout_ DWORD      *pdwSigLen
    """
    xrk_api_call("CryptSignHashA", regs)


def run_CryptSignHashW(regs):
    """
        advapi32.CryptSignHashW

        CryptSignHashW-->LocalSignHashW

          _In_    HCRYPTHASH hHash,
          _In_    DWORD      dwKeySpec,
          _In_    LPCTSTR    sDescription,
          _In_    DWORD      dwFlags,
          _Out_   BYTE       *pbSignature,
          _Inout_ DWORD      *pdwSigLen
    """
    xrk_api_call("CryptSignHashW", regs)


def run_CryptVerifySignatureA(regs):
    """
        advapi32.CryptVerifySignatureA

        CryptVerifySignatureA-->LocalVerifySignatureW

          _In_ HCRYPTHASH hHash,
          _In_ BYTE       *pbSignature,
          _In_ DWORD      dwSigLen,
          _In_ HCRYPTKEY  hPubKey,
          _In_ LPCTSTR    sDescription,
          _In_ DWORD      dwFlags
    """
    xrk_api_call("CryptVerifySignatureA", regs)


def run_CryptVerifySignatureW(regs):
    """
        advapi32.CryptVerifySignatureW

        CryptVerifySignatureW-->LocalVerifySignatureW

          _In_ HCRYPTHASH hHash,
          _In_ BYTE       *pbSignature,
          _In_ DWORD      dwSigLen,
          _In_ HCRYPTKEY  hPubKey,
          _In_ LPCTSTR    sDescription,
          _In_ DWORD      dwFlags
    """
    xrk_api_call("CryptVerifySignatureW", regs)


def run_CryptEncrypt(regs):
    """
        advapi32.CryptEncrypt

          _In_     HCRYPTKEY hKey,
          _In_     HCRYPTHASH hHash,
          _In_     BOOL Final,
          _In_     DWORD dwFlags,
          _Inout_  BYTE *pbData,
          _Inout_  DWORD *pdwDataLen,
          _In_     DWORD dwBufLen
    """
    xrk_api_call("CryptEncrypt", regs)


def run_CryptDecrypt(regs):
    """
        advapi32.CryptDecrypt

          _In_     HCRYPTKEY hKey,
          _In_     HCRYPTHASH hHash,
          _In_     BOOL Final,
          _In_     DWORD dwFlags,
          _Inout_  BYTE *pbData,
          _Inout_  DWORD *pdwDataLen
    """
    xrk_api_call("CryptDecrypt", regs)


def run_CryptDuplicateHash(regs):
    """
        advapi32.CryptDuplicateHash

          _In_  HCRYPTHASH hHash,
          _In_  DWORD      *pdwReserved,
          _In_  DWORD      dwFlags,
          _Out_ HCRYPTHASH *phHash
    """
    xrk_api_call("CryptDuplicateHash", regs)


def run_CryptDuplicateKey(regs):
    """
        advapi32.CryptDuplicateKey

          _In_  HCRYPTKEY hKey,
          _In_  DWORD     *pdwReserved,
          _In_  DWORD     dwFlags,
          _Out_ HCRYPTKEY *phKey
    """
    xrk_api_call("CryptDuplicateKey", regs)


def run_CreateIoCompletionPort(regs):
    """
        kernel32.CreateIoCompletionPort

        CreateIoCompletionPort-->NtCreateIoCompletion/NtSetInformationFile

          _In_     HANDLE    FileHandle,
          _In_opt_ HANDLE    ExistingCompletionPort,
          _In_     ULONG_PTR CompletionKey,
          _In_     DWORD     NumberOfConcurrentThreads
    """
    xrk_api_call("", regs)


def run_BindIoCompletionCallback(regs):
    """
        kernel32.BindIoCompletionCallback

        BindIoCompletionCallback-->RtlSetIoCompletionCallback

          _In_ HANDLE                          FileHandle,
          _In_ LPOVERLAPPED_COMPLETION_ROUTINE Function,
          _In_ ULONG                           Flags
    """
    xrk_api_call("", regs)


def run_PostQueuedCompletionStatus(regs):
    """
        kernel32.PostQueuedCompletionStatus

        PostQueuedCompletionStatus-->NtSetIoCompletion

          _In_     HANDLE       CompletionPort,
          _In_     DWORD        dwNumberOfBytesTransferred,
          _In_     ULONG_PTR    dwCompletionKey,
          _In_opt_ LPOVERLAPPED lpOverlapped
    """
    xrk_api_call("", regs)


def run_GetQueuedCompletionStatus(regs):
    """
        kernel32.GetQueuedCompletionStatus

        GetQueuedCompletionStatus-->NtRemoveIoCompletion

          _In_  HANDLE       CompletionPort,
          _Out_ LPDWORD      lpNumberOfBytes,
          _Out_ PULONG_PTR   lpCompletionKey,
          _Out_ LPOVERLAPPED *lpOverlapped,
          _In_  DWORD        dwMilliseconds
    """
    xrk_api_call("", regs)


# -------------------------------------------------------------------------
# STRING
# -------------------------------------------------------------------------


def run_wnsprintf_retn(regs, api_name, old_regs, dest_addr):
    """
        retn of wnsprintf

        @param: regs
        @param: api_name
        @param: old_regs
        @param: dest_addr
    """
    if api_name == "wnsprintfA":
        str_ = xrkutil.dbg_read_pstring(dest_addr)

    elif api_name == "wnsprintfW":
        str_ = xrkutil.dbg_read_pwstring(dest_addr)

    else:
        assert False

    xrk_api_call(api_name, old_regs, {"formated_str": str_})

    if "wnsprintfA_RETN" in xrkdbg.listHooks():
        xrkdbg.remove_hook("wnsprintfA_RETN")

    if "wnsprintfW_RETN" in xrkdbg.listHooks():
        xrkdbg.remove_hook("wnsprintfW_RETN")


def run_wnsprintfA(regs):
    """
        shlwapi.wnsprintfA

        wnsprintfA-->wvnsprintfA

          _Out_ PTSTR  pszDest,
          _In_  int    cchDest,
          _In_  PCTSTR pszFmt,
          _In_         ...
    """
    esp = regs["ESP"]
    dest = xrkdbg.readLong(esp + 4)

    if "wnsprintfA_RETN" not in xrkdbg.listHooks():
        retn_addrs = xrkdbg.getFunctionEnd(regs["EIP"])
        assert len(retn_addrs) == 1

        xrkmonctrl.install_addr_hook_ex(retn_addrs[0], "wnsprintfA_RETN", run_wnsprintf_retn, shall_pause=False, param1="wnsprintfA", param2=regs, param3=dest)


def run_wnsprintfW(regs):
    """
        shlwapi.wnsprintfW

        wnsprintfW-->wvnsprintfW

          _Out_ PTSTR  pszDest,
          _In_  int    cchDest,
          _In_  PCTSTR pszFmt,
          _In_         ...
    """
    esp = regs["ESP"]
    dest = xrkdbg.readLong(esp + 4)

    if "wnsprintfW_RETN" not in xrkdbg.listHooks():
        retn_addrs = xrkdbg.getFunctionEnd(regs["EIP"])
        assert len(retn_addrs) == 1

        xrkmonctrl.install_addr_hook_ex(retn_addrs[0], "wnsprintfW_RETN", run_wnsprintf_retn, shall_pause=False, param1="wnsprintfW", param2=regs, param3=dest)


def run_RtlInitString(regs):
    """
        ntdll.RtlInitString

          _Out_    PSTRING DestinationString,
          _In_opt_ PCSZ    SourceString
    """
    esp = regs["ESP"]
    src_str = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("RtlInitString", regs, {"src_str": src_str})


def run_RtlInitAnsiString(regs):
    """
        ntdll.RtlInitAnsiString

          _Out_     PANSI_STRING DestinationString,
          _In_opt_  PCSZ SourceString
    """
    esp = regs["ESP"]
    src_str = xrkutil.dbg_read_pstring(esp + 8)

    xrk_api_call("RtlInitAnsiString", regs, {"src_str": src_str})


def run_RtlInitUnicodeString(regs):
    """
        ntdll.RtlInitUnicodeString

          _Out_     PUNICODE_STRING DestinationString,
          _In_opt_  PCWSTR SourceString
    """
    esp = regs["ESP"]
    src_str = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("RtlInitUnicodeString", regs, {"src_str": src_str})


def run_RtlInitUnicodeStringEx(regs):
    """
        ntdll.RtlInitUnicodeStringEx

          _Out_     PUNICODE_STRING DestinationString,
          _In_opt_  PCWSTR SourceString

        !+ not exist in MSDN
    """
    esp = regs["ESP"]
    src_str = xrkutil.dbg_read_pwstring(esp + 8)

    xrk_api_call("RtlInitUnicodeStringEx", regs, {"src_str": src_str})


def run_RtlIsDosDeviceName_U(regs):
    """
        ntdll.RtlIsDosDeviceName_U

          wchar_t *Str

        !+ not exist in MSDN
    """
    esp = regs["ESP"]
    src_str = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("RtlIsDosDeviceName_U", regs, {"src_str": src_str})


def run_RtlDosPathNameToNtPathName_U(regs):
    """
        ntdll.RtlDosPathNameToNtPathName_U

          wchar_t *Str, int a2, int a3, int a4

        !+ not exist in MSDN
    """
    esp = regs["ESP"]
    src_str = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("RtlDosPathNameToNtPathName_U", regs, {"src_str": src_str})


def run_RtlDetermineDosPathNameType_U(regs):
    """
        ntdll.RtlDetermineDosPathNameType_U

          int a1

        !+ not exist in MSDN
    """
    pass


def run_lstrcatA(regs):
    """
        kernel32.lstrcatA

        _Inout_ LPTSTR lpString1,
        _In_    LPTSTR lpString2
    """
    esp = regs["ESP"]
    str1 = xrkutil.dbg_read_pstring(esp + 4)
    str2 = xrkutil.dbg_read_pstring(esp + 8)
    xrk_api_call("lstrcatA", regs, {"str1": str1, "str2": str2})


def run_lstrcatW(regs):
    """
        kernel32.lstrcatW

        lstrcatW-->_wcscat

        _Inout_ LPTSTR lpString1,
        _In_    LPTSTR lpString2
    """
    esp = regs["ESP"]
    str1 = xrkutil.dbg_read_pwstring(esp + 4)
    str2 = xrkutil.dbg_read_pwstring(esp + 8)
    xrk_api_call("lstrcatW", regs, {"str1": str1, "str2": str2})


def run_lstrcmpA(regs):
    """
        kernel32.lstrcmpA

        _In_ LPCTSTR lpString1,
        _In_ LPCTSTR lpString2
    """
    esp = regs["ESP"]
    str1 = xrkutil.dbg_read_pstring(esp + 4)
    str2 = xrkutil.dbg_read_pstring(esp + 8)
    xrk_api_call("lstrcmpA", regs, {"str1": str1, "str2": str2})


def run_lstrcmpW(regs):
    """
        kernel32.lstrcmpW

        _In_ LPCTSTR lpString1,
        _In_ LPCTSTR lpString2
    """
    esp = regs["ESP"]
    str1 = xrkutil.dbg_read_pwstring(esp + 4)
    str2 = xrkutil.dbg_read_pwstring(esp + 8)
    xrk_api_call("lstrcmpW", regs, {"str1": str1, "str2": str2})


def run_lstrcmpiA(regs):
    """
        kernel32.lstrcmpiA

        _In_ LPCTSTR lpString1,
        _In_ LPCTSTR lpString2
    """
    esp = regs["ESP"]
    str1 = xrkutil.dbg_read_pstring(esp + 4)
    str2 = xrkutil.dbg_read_pstring(esp + 8)
    xrk_api_call("lstrcmpiA", regs, {"str1": str1, "str2": str2})


def run_lstrcmpiW(regs):
    """
        kernel32.lstrcmpiW

        _In_ LPCTSTR lpString1,
        _In_ LPCTSTR lpString2
    """
    esp = regs["ESP"]
    str1 = xrkutil.dbg_read_pwstring(esp + 4)
    str2 = xrkutil.dbg_read_pwstring(esp + 8)
    xrk_api_call("lstrcmpiW", regs, {"str1": str1, "str2": str2})


def run_lstrcpyA(regs):
    """
        kernel32.lstrcpyA

        _Out_ LPTSTR lpString1,
        _In_  LPTSTR lpString2
    """
    esp = regs["ESP"]
    str1 = xrkutil.dbg_read_pstring(esp + 4)
    str2 = xrkutil.dbg_read_pstring(esp + 8)
    xrk_api_call("lstrcpyA", regs, {"str1": str1, "str2": str2})


def run_lstrcpyW(regs):
    """
        kernel32.lstrcpyW

        lstrcpyW-->_wcscpy

        _Out_ LPTSTR lpString1,
        _In_  LPTSTR lpString2
    """
    esp = regs["ESP"]
    str1 = xrkutil.dbg_read_pwstring(esp + 4)
    str2 = xrkutil.dbg_read_pwstring(esp + 8)
    xrk_api_call("lstrcpyW", regs, {"str1": str1, "str2": str2})


def run_lstrcpynA(regs):
    """
        kernel32.lstrcpynA

        _Out_ LPTSTR  lpString1,
        _In_  LPCTSTR lpString2,
        _In_  int     iMaxLength
    """
    esp = regs["ESP"]
    str1 = xrkutil.dbg_read_pstring(esp + 4)
    str2 = xrkutil.dbg_read_pstring(esp + 8)
    len_ = xrkdbg.readLong(esp + 0xC)
    xrk_api_call("lstrcpynA", regs, {"str1": str1, "str2": str2, "size": len_})


def run_lstrcpynW(regs):
    """
        kernel32.lstrcpynW

        _Out_ LPTSTR  lpString1,
        _In_  LPCTSTR lpString2,
        _In_  int     iMaxLength
    """
    esp = regs["ESP"]
    str1 = xrkutil.dbg_read_pwstring(esp + 4)
    str2 = xrkutil.dbg_read_pwstring(esp + 8)
    len_ = xrkdbg.readLong(esp + 0xC)
    xrk_api_call("lstrcpynW", regs, {"str1": str1, "str2": str2, "size": len_})


def run_lstrlenA(regs):
    """
        kernel32.lstrlenA

          _In_ LPCTSTR lpString
    """
    esp = regs["ESP"]
    str1 = xrkutil.dbg_read_pstring(esp + 4)
    xrk_api_call("lstrlenA", regs, {"str1": str1})


def run_lstrlenW(regs):
    """
        kernel32.lstrlenW

          _In_ LPCTSTR lpString
    """
    esp = regs["ESP"]
    str1 = xrkutil.dbg_read_pwstring(esp + 4)
    xrk_api_call("lstrlenW", regs, {"str1": str1})


# -------------------------------------------------------------------------
# ALLOC
# -------------------------------------------------------------------------

# TODO: add pause/unpause functionality.


def run_any_alloc_retn(regs, api_name):
    """
        any alloc retn

        @param: regs     : DICT   : reg dict
        @param: api_name : STRING : api name

        1. update k
        2. uninstall this if needed.
        3. fill param_pairs
        4. call suck
    """
    k = xrkcloud.cloud_get("alloc_params")
    assert k is not None and api_name in k
    param_pairs = k[api_name]
    k[api_name] = {}
    xrkcloud.cloud_set("alloc_params", k)

    if len(param_pairs) == 0 or api_name not in xrkdbg.listHooks():

        assert len(param_pairs) == 0
        # if self.api_name in xrkdbg.listHooks(), it might because
        # assert self.api_name not in xrkdbg.listHooks()

        xrkdbg.remove_hook(api_name + "_RETN")

        xrklog.high("removing allocRetnHook: %s" % api_name)
        # for now, we neglect update k
        return

    if api_name == "RtlAllocateHeap":
        param_pairs["addr_ret"] = regs["EAX"]

    elif api_name == "RtlReAllocateHeap":
        param_pairs["addr_ret"] = regs["EAX"]

    elif api_name == "LocalAlloc":
        param_pairs["addr_ret"] = regs["EAX"]

    # for VirtualAlloc/VirtualAllocEx, we have: {"addr": addr, "mm_size": mm_size}
    elif api_name == "VirtualAlloc" or api_name == "VirtualAllocEx":
        addr_ret = regs["EAX"]
        param_pairs["addr_ret"] = addr_ret
        page = xrkdbg.getMemoryPageByAddress(addr_ret)
        if page is not None and page.getBaseAddress() == addr_ret:
            param_pairs["mm_size_ret"] = page.getSize()

    else:
        assert False

    xrk_api_call(api_name, regs, param_pairs)


def __run_any_alloc(api_name, regs, param_pairs):
    """
        any alloc

        1. install RETN hook if needed
        2. update k

        !+ for xp sp3, each alloc function hex has only 1 "RETN", so we use api_END as desc
    """
    hks = xrkdbg.listHooks()
    if api_name + "_RETN" not in hks:

        name = api_name + "_RETN"
        retn_addrs = xrkdbg.getFunctionEnd(xrkdbg.getAddress(api_name))
        # xp sp3
        assert len(retn_addrs) == 1
        xrkdbg.setComment(retn_addrs[0], name)

        xrkmonctrl.install_addr_hook_ex(retn_addrs[0], name, run_any_alloc_retn, shall_pause=False, param1=api_name)

    k = xrkcloud.cloud_get("alloc_params", default={})
    k[api_name] = param_pairs
    xrkcloud.cloud_set("alloc_params", k)


#
# for unknown reason, Imm does not recoginize HeapAlloc and HeapReAlloc, so we use RtlAllocateHeap and RtlReAllocateHeap from ntdll instead.
#
# kernel32.HeapAlloc-->RtlAllocateHeap(ntdll)
# kernel32.HeapReAlloc-->RtlReAllocateHeap(ntdll)
#
# and GlobalAlloc/GlobalReAlloc call RtlAllocateHeap/RtlReAllocateHeap internally, so, we ignore these two calls
#
# kernel32.GlobalAlloc-->RtlAllocateHeap(ntdll)
# kernel32.GlobalReAlloc-->RtlAllocateHeap(ntdll)
#


def run_RtlAllocateHeap(regs):
    """
        ntdll.RtlAllocateHeap

          _In_     PVOID  HeapHandle,
          _In_opt_ ULONG  Flags,
          _In_     SIZE_T Size
    """
    esp = regs["ESP"]
    mm_size = xrkdbg.readLong(esp + 0xC)
    __run_any_alloc("RtlAllocateHeap", regs, {"mm_size": mm_size})


def run_RtlReAllocateHeap(regs):
    """
        ntdll.RtlReAllocateHeap

        int Source1,
        int a2,
        void *Src,
        size_t Size
    """
    esp = regs["ESP"]
    mm_size = xrkdbg.readLong(esp + 0x10)
    __run_any_alloc("RtlReAllocateHeap", regs, {"mm_size": mm_size})


def run_LocalAlloc(regs):
    """
        kernel32.LocalAlloc

        LocalAlloc(kernel32)-->RtlAllocateHeapMapViewOfFile-->MapViewOfFileEx-->NtMapViewOfSection(ntdll)

          _In_  UINT uFlags,
          _In_  SIZE_T uBytes

        flags:
            LHND              0x0042
            LMEM_FIXED        0x0000
            LMEM_MOVEABLE     0x0002
            LMEM_ZEROINIT     0x0040
            LPTR              0x0040
            NONZEROLHND                 Same as LMEM_MOVEABLE.
            NONZEROLPTR                 Same as LMEM_FIXED.
    """
    esp = regs["ESP"]
    mm_size = xrkdbg.readLong(esp + 0x8)
    __run_any_alloc("LocalAlloc", regs, {"mm_size": mm_size})


def run_TlsAlloc(regs):
    """
        kernel32.TlsAlloc

        TlsAlloc(kernel32)-->RtlAllocateHeap(ntdll)

          void
    """
    # for now, this one is ignored
    pass
    # xrk_api_call("TlsAlloc", regs)


#
# for unknown reason, when stop at VirtualAllocEx, call stack is corrupt. so we monitor both VirtualAlloc and VirtualAllocEx, but do some filter in VirtualAllocEx
#

def run_VirtualAlloc(regs):
    """
        kernel32.VirtualAlloc

        VirtualAlloc(kernel32)-->VirtualAllocEx(kernel32)-->NtAllocateVirtualMemory(ntdll)

          _In_opt_ LPVOID lpAddress,
          _In_     SIZE_T dwSize,
          _In_     DWORD  flAllocationType,
          _In_     DWORD  flProtect
    """
    esp = regs["ESP"]
    addr = xrkdbg.readLong(esp + 4)
    mm_size = xrkdbg.readLong(esp + 0x8)

    __run_any_alloc("VirtualAlloc", regs, {"addr": addr, "mm_size": mm_size})

    protect = xrkdbg.readLong(esp + 0x10)
    # PAGE_EXECUTE/PAGE_EXECUTE_READ/PAGE_EXECUTE_READWRITE/PAGE_EXECUTE_WRITECOPY
    if protect & 0x10 or protect & 0x20 or protect & 0x40 or protect & 0x80:
        xrklog.highlight("VirtualAlloc: alloc mm with PAGE_EXECUTE/PAGE_EXECUTE_READ/PAGE_EXECUTE_READWRITE/PAGE_EXECUTE_WRITECOPY")


def run_VirtualAllocEx(regs):
    """
        kernel32.VirtualAllocEx

        VirtualAlloc(kernel32)-->VirtualAllocEx(kernel32)-->NtAllocateVirtualMemory(ntdll)

          _In_     HANDLE hProcess,
          _In_opt_ LPVOID lpAddress,
          _In_     SIZE_T dwSize,
          _In_     DWORD  flAllocationType,
          _In_     DWORD  flProtect

        flAllocationType:
            MEM_COMMIT            0x00001000
            MEM_RESERVE           0x00002000
            MEM_RESET             0x00080000
            MEM_RESET_UNDO        0x1000000

            MEM_LARGE_PAGES       0x20000000
            MEM_PHYSICAL          0x00400000
            MEM_TOP_DOWN          0x00100000

        flProtect:
            PAGE_EXECUTE          0x10
            PAGE_EXECUTE_READ     0x20
            PAGE_EXECUTE_READWRITE 0x40
            PAGE_EXECUTE_WRITECOPY 0x80
            PAGE_NOACCESS         0x01
            PAGE_READONLY         0x02
            PAGE_READWRITE        0x04
            PAGE_WRITECOPY        0x08
            PAGE_TARGETS_INVALID  0x40000000
            PAGE_TARGETS_NO_UPDATE 0x40000000

            PAGE_GUARD            0x100
            PAGE_NOCACHE          0x200
            PAGE_WRITECOMBINE     0x400

        1. special filter, check if called from VirtualAlloc
        2. other stuff
    """
    #
    # VirtualAlloc(xp sp3)
    # 7C809AE1 mov  edi, edi
    # ...
    # 7C809AF4 call _VirtualAllocEx@20 # 0x13
    # ...
    #
    is_from_VirtualAlloc = __filter_caller_fast("VirtualAlloc", 13)

    if not is_from_VirtualAlloc:

        esp = regs["ESP"]
        addr = xrkdbg.readLong(esp + 8)
        mm_size = xrkdbg.readLong(esp + 0xC)

        __run_any_alloc("VirtualAllocEx", regs, {"addr": addr, "mm_size": mm_size})

        protect = xrkdbg.readLong(esp + 0x14)
        # PAGE_EXECUTE/PAGE_EXECUTE_READ/PAGE_EXECUTE_READWRITE/PAGE_EXECUTE_WRITECOPY
        if protect & 0x10 or protect & 0x20 or protect & 0x40 or protect & 0x80:
            xrklog.highlight("VirtualAllocEx: alloc mm with PAGE_EXECUTE/PAGE_EXECUTE_READ/PAGE_EXECUTE_READWRITE/PAGE_EXECUTE_WRITECOPY")

    else:
        # we need to remove "VirtualAllocEx_RETN" here. because if "VirtualAllocEx_RETN" has already been installed, when invoke, it has no param_pairs. actually we don't wanna it to invoke. so, we remove it.
        if "VirtualAllocEx_RETN" in xrkdbg.listHooks():
            debugger.remove_hook("VirtualAllocEx_RETN")


# -------------------------------------------------------------------------
# ATOM
# -------------------------------------------------------------------------


def run_InitAtomTable(regs):
    """
        kernel32.InitAtomTable

        InitAtomTable-->RtlCreateAtomTable

          _In_  DWORD nSize
    """
    esp = regs["ESP"]
    size = xrkdbg.readLong(esp + 4)

    xrk_api_call("InitAtomTable", regs, {"size": size})


def run_AddAtomA(regs):
    """
        kernel32.AddAtomA

        AddAtomA-->InternalAddAtom

          _In_ LPCTSTR lpString
    """
    esp = regs["ESP"]
    str_ = xrkutil.dbg_read_pstring(esp + 4)

    xrk_api_call("AddAtomA", regs, {"str": str_})


def run_AddAtomW(regs):
    """
        kernel32.AddAtomW

        AddAtomW-->InternalAddAtom

          _In_ LPCTSTR lpString
    """
    esp = regs["ESP"]
    str_ = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("AddAtomW", regs, {"str": str_})


def run_DeleteAtom(regs):
    """
        kernel32.DeleteAtom

        DeleteAtom-->InternalDeleteAtom

          _In_ ATOM nAtom
    """
    xrk_api_call("DeleteAtom", regs)


def run_FindAtomA(regs):
    """
        kernel32.FindAtomA

        FindAtomA-->InternalFindAtom

          _In_ LPCTSTR lpString
    """
    esp = regs["ESP"]
    str_ = xrkutil.dbg_read_pstring(esp + 4)

    xrk_api_call("FindAtomA", regs, {"str": str_})


def run_FindAtomW(regs):
    """
        kernel32.FindAtomW

        FindAtomW-->InternalFindAtom

          _In_ LPCTSTR lpString
    """
    esp = regs["ESP"]
    str_ = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("FindAtomW", regs, {"str": str_})


def run_GetAtomNameA(regs):
    """
        kernel32.GetAtomNameA

        GetAtomNameA-->InternalGetAtomName

          _In_  ATOM   nAtom,
          _Out_ LPTSTR lpBuffer,
          _In_  int    nSize
    """
    xrk_api_call("GetAtomNameA", regs)


def run_GetAtomNameW(regs):
    """
        kernel32.GetAtomNameW

        GetAtomNameW-->InternalGetAtomName

          _In_  ATOM   nAtom,
          _Out_ LPTSTR lpBuffer,
          _In_  int    nSize
    """
    xrk_api_call("GetAtomNameW", regs)


def run_GlobalAddAtomA(regs):
    """
        kernel32.GlobalAddAtomA

        GlobalAddAtomA-->InternalAddAtom

          _In_ LPCTSTR lpString
    """
    esp = regs["ESP"]
    str_ = xrkutil.dbg_read_pstring(esp + 4)

    xrk_api_call("GlobalAddAtomA", regs, {"str": str_})


def run_GlobalAddAtomW(regs):
    """
        kernel32.GlobalAddAtomW

        GlobalAddAtomW-->InternalAddAtom

          _In_ LPCTSTR lpString
    """
    esp = regs["ESP"]
    str_ = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("GlobalAddAtomW", regs, {"str": str_})


def run_GlobalDeleteAtom(regs):
    """
        kernel32.GlobalDeleteAtom

        GlobalDeleteAtom-->InternalDeleteAtom

          _In_ ATOM nAtom
    """
    xrk_api_call("GlobalDeleteAtom", regs)


def run_GlobalFindAtomA(regs):
    """
        kernel32.GlobalFindAtomA

        GlobalFindAtomA-->InternalFindAtom

          _In_ LPCTSTR lpString
    """
    esp = regs["ESP"]
    str_ = xrkutil.dbg_read_pstring(esp + 4)

    xrk_api_call("GlobalFindAtomA", regs, {"str": str_})


def run_GlobalFindAtomW(regs):
    """
        kernel32.GlobalFindAtomW

        GlobalFindAtomW-->InternalFindAtom

          _In_ LPCTSTR lpString
    """
    esp = regs["ESP"]
    str_ = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("GlobalFindAtomW", regs, {"str": str_})


def run_GlobalGetAtomNameA(regs):
    """
        kernel32.GlobalGetAtomNameA

        GlobalGetAtomNameA-->InternalGetAtomName

          _In_  ATOM   nAtom,
          _Out_ LPTSTR lpBuffer,
          _In_  int    nSize
    """
    xrk_api_call("GlobalGetAtomNameA", regs)


def run_GlobalGetAtomNameW(regs):
    """
        kernel32.GlobalGetAtomNameW

        GlobalGetAtomNameW-->InternalGetAtomName

          _In_  ATOM   nAtom,
          _Out_ LPTSTR lpBuffer,
          _In_  int    nSize
    """
    xrk_api_call("GlobalGetAtomNameW", regs)


# -------------------------------------------------------------------------
# CLIPBOARD
# -------------------------------------------------------------------------


def run_EmptyClipboard(regs):
    """
        user32.EmptyClipboard

        EmptyClipboard-->NtUserEmptyClipboard

         void
    """
    xrk_api_call("EmptyClipboard", regs)


def run_GetClipboardData(regs):
    """
        user32.GetClipboardData

        GetClipboardData-->NtUserGetClipboardData

          _In_ UINT uFormat
    """
    xrk_api_call("GetClipboardData", regs)


def run_OpenClipboard(regs):
    """
        user32.OpenClipboard

        OpenClipboard-->NtUserOpenClipboard

          _In_opt_ HWND hWndNewOwner
    """
    xrk_api_call("OpenClipboard", regs)


def run_SetClipboardData(regs):
    """
        user32.SetClipboardData

        SetClipboardData-->NtUserSetClipboardData

          _In_     UINT   uFormat,
          _In_opt_ HANDLE hMem
    """
    xrk_api_call("SetClipboardData", regs)


# -------------------------------------------------------------------------
# MOUSE KEY SCREEN
# -------------------------------------------------------------------------


def run_GetKeyboardState(regs):
    """
        user32.GetKeyboardState

        GetKeyboardState-->NtUserGetKeyboardState

          _Out_ PBYTE lpKeyState
    """
    xrk_api_call("GetKeyboardState", regs)


def run_SetKeyboardState(regs):
    """
        user32.SetKeyboardState

        SetKeyboardState-->NtUserSetKeyboardState

          _In_  LPBYTE lpKeyState
    """
    xrk_api_call("SetKeyboardState", regs)


def run_GetAsyncKeyState(regs):
    """
        user32.GetAsyncKeyState

        GetAsyncKeyState-->NtUserGetAsyncKeyState

          _In_ int vKey
    """
    xrk_api_call("GetAsyncKeyState", regs)


def run_GetKeyState(regs):
    """
        user32.GetKeyState

        GetKeyState-->NtUserGetKeyState

          _In_ int nVirtKey
    """
    xrk_api_call("GetKeyState", regs)


def run_keybd_event(regs):
    """
        user32.keybd_event

        keybd_event-->NtUserSendInput

          _In_ BYTE      bVk,
          _In_ BYTE      bScan,
          _In_ DWORD     dwFlags,
          _In_ ULONG_PTR dwExtraInfo
    """
    xrk_api_call("keybd_event", regs)


def run_mouse_event(regs):
    """
        user32.mouse_event

        mouse_event-->NtUserSendInput

          _In_ DWORD     dwFlags,
          _In_ DWORD     dx,
          _In_ DWORD     dy,
          _In_ DWORD     dwData,
          _In_ ULONG_PTR dwExtraInfo
    """
    xrk_api_call("mouse_event", regs)


def run_GetCursorPos(regs):
    """
        user32.GetCursorPos

        GetCursorPos-->NtUserCallOneParam

          _Out_ LPPOINT lpPoint
    """
    xrk_api_call("GetCursorPos", regs)


def run_GetWindowRect(regs):
    """
        user32.GetWindowRect

        GetWindowRect-->_GetWindowRect

          _In_  HWND   hWnd,
          _Out_ LPRECT lpRect
    """
    xrk_api_call("GetWindowRect", regs)


def run_ScreenToClient(regs):
    """
        user32.ScreenToClient

        ScreenToClient-->_ScreenToClient

          HWND hWnd,
          LPPOINT lpPoint
    """
    xrk_api_call("ScreenToClient", regs)


def run_ClientToScreen(regs):
    """
        user32.ClientToScreen

        ClientToScreen-->_ClientToScreen

          HWND hWnd,
          LPPOINT lpPoint
    """
    xrk_api_call("ClientToScreen", regs)


def run_CreateCompatibleDC(regs):
    """
        gdi32.CreateCompatibleDC

        CreateCompatibleDC-->NtGdiCreateCompatibleDC

          HDC hdc
    """
    xrk_api_call("CreateCompatibleDC", regs)


def run_CreateCompatibleBitmap(regs):
    """
        gdi32.CreateCompatibleBitmap

        CreateCompatibleBitmap-->NtGdiCreateCompatibleBitmap

          HDC hdc,
          int nWidth,
          int nHeight
    """
    xrk_api_call("CreateCompatibleBitmap", regs)


def run_BitBlt(regs):
    """
        gdi32.BitBlt

        BitBlt-->NtGdiBitBlt

         int x,
         int y,
         int nWidth,
         int nHeight,
         CDC* pSrcDC,
         int xSrc,
         int ySrc,
         DWORD dwRop
    """
    xrk_api_call("BitBlt", regs)


# -------------------------------------------------------------------------
# WIN / MSG BOX
# -------------------------------------------------------------------------


def run_DialogBoxParamA(regs):
    """
        user32.DialogBoxParamA

        DialogBoxParamA-->pfnFindResourceExA/.../DialogBoxIndirectParamAorW

          _In_opt_ HINSTANCE hInstance,
          _In_     LPCTSTR   lpTemplateName,
          _In_opt_ HWND      hWndParent,
          _In_opt_ DLGPROC   lpDialogFunc,
          _In_     LPARAM    dwInitParam
    """
    esp = regs["ESP"]
    template_name = xrkutil.dbg_read_pstring(esp + 8)
    cbk_func = xrkdbg.readLong(esp + 0x10)

    xrk_api_call("DialogBoxParamA", regs, {"template_name": template_name, "cbk_func": cbk_func})


def run_DialogBoxParamW(regs):
    """
        user32.DialogBoxParamW

        DialogBoxParamW-->pfnFindResourceExW/.../DialogBoxIndirectParamAorW

          _In_opt_ HINSTANCE hInstance,
          _In_     LPCTSTR   lpTemplateName,
          _In_opt_ HWND      hWndParent,
          _In_opt_ DLGPROC   lpDialogFunc,
          _In_     LPARAM    dwInitParam
    """
    esp = regs["ESP"]
    template_name = xrkutil.dbg_read_pwstring(esp + 8)
    cbk_func = xrkdbg.readLong(esp + 0x10)

    xrk_api_call("DialogBoxParamW", regs, {"template_name": template_name, "cbk_func": cbk_func})


def run_MessageBoxTimeoutW(regs):
    """
        user32.MessageBoxTimeoutW

        MessageBoxA-->MessageBoxExA-->MessageBoxTimeoutA-->MessageBoxTimeoutW-->MessageBoxWorker-->ServiceMessageBox
        MessageBoxW-->MessageBoxExW-->MessageBoxTimeoutW==>||

          IN HWND hWnd,
          IN LPCWSTR lpText,
          IN LPCWSTR lpCaption,
          IN UINT uType,
          IN WORD wLanguageId,
          IN DWORD dwMilliseconds
    """
    esp = regs["ESP"]
    txt = xrkutil.dbg_read_pwstring(esp + 8)
    caption = xrkutil.dbg_read_pwstring(esp + 0xC)
    msecs = xrkdbg.readLong(esp + 0x18)

    xrk_api_call("MessageBoxTimeoutW", regs, {"txt": txt, "caption": caption, "msecs": msecs})


def parse_msgbox_params(p_params):
    """
        typedef struct {
          UINT           cbSize;
          HWND           hwndOwner;
          HINSTANCE      hInstance;
          LPCTSTR        lpszText;
          LPCTSTR        lpszCaption;
          DWORD          dwStyle;
          LPCTSTR        lpszIcon;
          DWORD_PTR      dwContextHelpId;
          MSGBOXCALLBACK lpfnMsgBoxCallback;
          DWORD          dwLanguageId;
        } MSGBOXPARAMS, *PMSGBOXPARAMS;

        dwStyle:
            MB_ABORTRETRYIGNORE     0x00000002L
            MB_CANCELTRYCONTINUE    0x00000006L
            MB_HELP                 0x00004000L
            MB_OK                   0x00000000L
            MB_OKCANCEL             0x00000001L
            MB_RETRYCANCEL          0x00000005L
            MB_YESNO                0x00000004L
            MB_YESNOCANCEL          0x00000003L

        @return: TUPLE: (txt, caption, style_str, fn_cbk)
    """
    txt = xrkutil.dbg_read_pstring(p_params + 0xC)
    caption = xrkutil.dbg_read_pstring(p_params + 0x10)
    style = xrkdbg.readLong(p_params + 0x14)
    fn_cbk = xrkdbg.readLong(p_params + 0x20)

    style_str = ""
    if style & 0x00000002:
        style_str = "MB_ABORTRETRYIGNORE"
    if style & 0x00000006:
        style_str = style_str + " | MB_CANCELTRYCONTINUE"
    if style & 0x00004000:
        style_str = style_str + " | MB_HELP"
    if style & 0x00000000:
        style_str = style_str + " | MB_OK"
    if style & 0x00000001:
        style_str = style_str + " | MB_OKCANCEL"
    if style & 0x00000005:
        style_str = style_str + " | MB_RETRYCANCEL"
    if style & 0x00000004:
        style_str = style_str + " | MB_YESNO"
    if style & 0x00000003:
        style_str = style_str + " | MB_YESNOCANCEL"
    style_str = style_str.strip(" | ")

    return (txt, caption, style_str, fn_cbk)


def run_MessageBoxIndirectA(regs):
    """
        user32.MessageBoxIndirectA

        MessageBoxIndirectA-->MessageBoxWorker

          _In_ const LPMSGBOXPARAMS lpMsgBoxParams
    """
    esp = regs["ESP"]
    p_params = xrkdbg.readLong(esp + 4)
    txt, caption, style_str, fn_cbk = parse_msgbox_params(p_params)

    xrk_api_call("MessageBoxIndirectA", regs, {"txt": txt, "caption": caption, "style_str": style_str, "fn_cbk": fn_cbk})


def run_MessageBoxIndirectW(regs):
    """
        user32.MessageBoxIndirectW

        MessageBoxIndirectW-->MessageBoxWorker

          _In_ const LPMSGBOXPARAMS lpMsgBoxParams
    """
    esp = regs["ESP"]
    p_params = xrkdbg.readLong(esp + 4)
    txt, caption, style_str, fn_cbk = parse_msgbox_params(p_params)

    xrk_api_call("MessageBoxIndirectW", regs, {"txt": txt, "caption": caption, "style_str": style_str, "fn_cbk": fn_cbk})


def parse_winclass_params(p_class):
    """
        typedef struct tagWNDCLASS {
          UINT      style;
          WNDPROC   lpfnWndProc;
          int       cbClsExtra;
          int       cbWndExtra;
          HINSTANCE hInstance;
          HICON     hIcon;
          HCURSOR   hCursor;
          HBRUSH    hbrBackground;
          LPCTSTR   lpszMenuName;
          LPCTSTR   lpszClassName;
        } WNDCLASS, *PWNDCLASS;

        @return: TUPLE: (fn_cbk, menu_name, class_name)
    """
    fn_cbk = xrkdbg.readLong(p_class + 0x4)
    menu_name = xrkutil.dbg_read_pstring(p_class + 0x20)
    class_name = xrkutil.dbg_read_pstring(p_class + 0x24)

    return (fn_cbk, menu_name, class_name)


def run_RegisterClassA(regs):
    """
        user32.RegisterClassA

        RegisterClassA-->RegisterClassExWOWA-->NtUserRegisterClassExWOW

          _In_ const WNDCLASS *lpWndClass
    """
    esp = regs["ESP"]
    p_class = xrkdbg.readLong(esp + 0x4)
    fn_cbk, menu_name, class_name = parse_winclass_params(p_class)

    xrk_api_call("RegisterClassA", regs, {"fn_cbk": fn_cbk, "menu_name": menu_name, "class_name": class_name})


def run_RegisterClassW(regs):
    """
        user32.RegisterClassW

        RegisterClassW-->RegisterClassExWOWW-->NtUserRegisterClassExWOW

          _In_ const WNDCLASS *lpWndClass
    """
    esp = regs["ESP"]
    p_class = xrkdbg.readLong(esp + 0x4)
    fn_cbk, menu_name, class_name = parse_winclass_params(p_class)

    xrk_api_call("RegisterClassW", regs, {"fn_cbk": fn_cbk, "menu_name": menu_name, "class_name": class_name})


def parse_winclassex_params(p_class):
    """
        typedef struct tagWNDCLASSEX {
          UINT      cbSize;
          UINT      style;
          WNDPROC   lpfnWndProc;
          int       cbClsExtra;
          int       cbWndExtra;
          HINSTANCE hInstance;
          HICON     hIcon;
          HCURSOR   hCursor;
          HBRUSH    hbrBackground;
          LPCTSTR   lpszMenuName;
          LPCTSTR   lpszClassName;
          HICON     hIconSm;
        } WNDCLASSEX, *PWNDCLASSEX;

        @return: TUPLE: (fn_cbk, menu_name, class_name)
    """
    fn_cbk = xrkdbg.readLong(p_class + 0x8)
    menu_name = xrkutil.dbg_read_pstring(p_class + 0x24)
    class_name = xrkutil.dbg_read_pstring(p_class + 0x28)

    return (fn_cbk, menu_name, class_name)


def run_RegisterClassExA(regs):
    """
        user32.RegisterClassExA

        RegisterClassExA-->RegisterClassExWOWA=>>||

          _In_ const WNDCLASSEX *lpwcx
    """
    esp = regs["ESP"]
    p_class = xrkdbg.readLong(esp + 0x4)
    fn_cbk, menu_name, class_name = parse_winclassex_params(p_class)

    xrk_api_call("RegisterClassExA", regs, {"fn_cbk": fn_cbk, "menu_name": menu_name, "class_name": class_name})


def run_RegisterClassExW(regs):
    """
        user32.RegisterClassExW

        RegisterClassExW-->RegisterClassExWOWW==>>||

          _In_ const WNDCLASSEX *lpwcx
    """
    esp = regs["ESP"]
    p_class = xrkdbg.readLong(esp + 0x4)
    fn_cbk, menu_name, class_name = parse_winclassex_params(p_class)

    xrk_api_call("RegisterClassExW", regs, {"fn_cbk": fn_cbk, "menu_name": menu_name, "class_name": class_name})


def run_CreateWindowExA(regs):
    """
        user32.CreateWindowExA

        CreateWindowExA-->_CreateWindowEx

          _In_     DWORD     dwExStyle,
          _In_opt_ LPCTSTR   lpClassName,
          _In_opt_ LPCTSTR   lpWindowName,
          _In_     DWORD     dwStyle,
          _In_     int       x,
          _In_     int       y,
          _In_     int       nWidth,
          _In_     int       nHeight,
          _In_opt_ HWND      hWndParent,
          _In_opt_ HMENU     hMenu,
          _In_opt_ HINSTANCE hInstance,
          _In_opt_ LPVOID    lpParam
    """
    esp = regs["ESP"]
    class_name = xrkutil.dbg_read_pstring(esp + 8)
    win_name = xrkutil.dbg_read_pstring(esp + 0xC)
    x = xrkdbg.readLong(esp + 0x14)
    y = xrkdbg.readLong(esp + 0x18)
    width = xrkdbg.readLong(esp + 0x1C)
    height = xrkdbg.readLong(esp + 0x20)
    rect = "(%d,%d)->(%d,%d)" % (x, y, x + width, y + height)

    xrk_api_call("CreateWindowExA", regs, {"class_name": class_name, "win_name": win_name, "rect": rect})


def run_CreateWindowExW(regs):
    """
        user32.CreateWindowExW

        CreateWindowExW-->_CreateWindowEx

          _In_     DWORD     dwExStyle,
          _In_opt_ LPCTSTR   lpClassName,
          _In_opt_ LPCTSTR   lpWindowName,
          _In_     DWORD     dwStyle,
          _In_     int       x,
          _In_     int       y,
          _In_     int       nWidth,
          _In_     int       nHeight,
          _In_opt_ HWND      hWndParent,
          _In_opt_ HMENU     hMenu,
          _In_opt_ HINSTANCE hInstance,
          _In_opt_ LPVOID    lpParam
    """
    esp = regs["ESP"]
    class_name = xrkutil.dbg_read_pwstring(esp + 8)
    win_name = xrkutil.dbg_read_pwstring(esp + 0xC)
    x = xrkdbg.readLong(esp + 0x14)
    y = xrkdbg.readLong(esp + 0x18)
    width = xrkdbg.readLong(esp + 0x1C)
    height = xrkdbg.readLong(esp + 0x20)
    rect = "(%d,%d)->(%d,%d)" % (x, y, x + width, y + height)

    xrk_api_call("CreateWindowExW", regs, {"class_name": class_name, "win_name": win_name, "rect": rect})


def run_CreateWindowStationA(regs):
    """
        user32.CreateWindowStationA

        CreateWindowStationA-->CommonCreateWindowStation

          _In_opt_ LPCTSTR               lpwinsta,
                   DWORD                 dwFlags,
          _In_     ACCESS_MASK           dwDesiredAccess,
          _In_opt_ LPSECURITY_ATTRIBUTES lpsa
    """
    esp = regs["ESP"]
    win_name = xrkutil.dbg_read_pstring(esp + 4)

    xrk_api_call("CreateWindowStationA", regs, {"win_name": win_name})


def run_CreateWindowStationW(regs):
    """
        user32.CreateWindowStationW

        CreateWindowStationW-->CommonCreateWindowStation

          _In_opt_ LPCTSTR               lpwinsta,
                   DWORD                 dwFlags,
          _In_     ACCESS_MASK           dwDesiredAccess,
          _In_opt_ LPSECURITY_ATTRIBUTES lpsa
    """
    esp = regs["ESP"]
    win_name = xrkutil.dbg_read_pwstring(esp + 4)

    xrk_api_call("CreateWindowStationW", regs, {"win_name": win_name})


def parse_msg_params(p_msg):
    """
        typedef struct tagMSG {
          HWND   hwnd;
          UINT   message;
          WPARAM wParam;
          LPARAM lParam;
          DWORD  time;
          POINT  pt;
        } MSG, *PMSG, *LPMSG;

        @return: msg
    """
    msg = xrkdbg.readLong(p_msg + 4)

    return msg


def run_DispatchMessageA(regs):
    """
        user32.DispatchMessageA

        DispatchMessageA-->DispatchMessageWorker

          _In_ const MSG *lpmsg
    """
    esp = regs["ESP"]
    p_msg = xrkdbg.readLong(esp + 4)
    msg = parse_msg_params(p_msg)

    xrk_api_call("DispatchMessageA", regs, {"msg": msg})


def run_DispatchMessageW(regs):
    """
        user32.DispatchMessageW

        DispatchMessageW-->DispatchMessageWorker

          _In_ const MSG *lpmsg
    """
    esp = regs["ESP"]
    p_msg = xrkdbg.readLong(esp + 4)
    msg = parse_msg_params(p_msg)

    xrk_api_call("DispatchMessageA", regs, {"msg": msg})


def run_PeekMessageA(regs):
    """
        user32.PeekMessageA

        PeekMessageA-->_PeekMessage/NtUserGetThreadState

          _Out_    LPMSG lpMsg,
          _In_opt_ HWND  hWnd,
          _In_     UINT  wMsgFilterMin,
          _In_     UINT  wMsgFilterMax,
          _In_     UINT  wRemoveMsg
    """
    xrk_api_call("PeekMessageA", regs)


def run_PeekMessageW(regs):
    """
        user32.PeekMessageW

        PeekMessageW-->_PeekMessage/NtUserGetThreadState

          _Out_    LPMSG lpMsg,
          _In_opt_ HWND  hWnd,
          _In_     UINT  wMsgFilterMin,
          _In_     UINT  wMsgFilterMax,
          _In_     UINT  wRemoveMsg
    """
    xrk_api_call("PeekMessageW", regs)


def run_PostMessageA(regs):
    """
        user32.PostMessageA

        PostMessageA-->SendMessageA/NtUserPostMessage

          _In_opt_ HWND   hWnd,
          _In_     UINT   Msg,
          _In_     WPARAM wParam,
          _In_     LPARAM lParam
    """
    esp = regs["ESP"]
    msg = xrkdbg.readLong(esp + 8)

    xrk_api_call("PostMessageA", regs, {"msg": msg})


def run_PostMessageW(regs):
    """
        user32.PostMessageW

        PostMessageW-->SendMessageW/NtUserPostMessage

          _In_opt_ HWND   hWnd,
          _In_     UINT   Msg,
          _In_     WPARAM wParam,
          _In_     LPARAM lParam
    """
    esp = regs["ESP"]
    msg = xrkdbg.readLong(esp + 8)

    xrk_api_call("PostMessageW", regs, {"msg": msg})


def run_PostQuitMessage(regs):
    """
        user32.PostQuitMessage

        PostQuitMessage-->NtUserCallOneParam

          _In_ int nExitCode
    """
    esp = regs["ESP"]
    code = xrkdbg.readLong(esp + 4)

    xrk_api_call("PostQuitMessage", regs, {"code": code})


def run_SendMessageA(regs):
    """
        user32.SendMessageA

        SendMessageA-->SendMessageWorker/gapfnScSendMessage/NtUserMessageCall

          _In_ HWND   hWnd,
          _In_ UINT   Msg,
          _In_ WPARAM wParam,
          _In_ LPARAM lParam
    """
    esp = regs["ESP"]
    msg = xrkdbg.readLong(esp + 4)

    xrk_api_call("SendMessageA", regs, {"msg": msg})


def run_SendMessageW(regs):
    """
        user32.SendMessageW

        SendMessageW-->SendMessageWorker/gapfnScSendMessage/NtUserMessageCall

          _In_ HWND   hWnd,
          _In_ UINT   Msg,
          _In_ WPARAM wParam,
          _In_ LPARAM lParam
    """
    esp = regs["ESP"]
    msg = xrkdbg.readLong(esp + 4)

    xrk_api_call("SendMessageA", regs, {"msg": msg})


def run_RegisterServicesProcess(regs):
    """
        user32.RegisterServicesProcess

        RegisterServicesProcess-->CsrClientCallServer

          DWORD dwProcessId
    """
    esp = regs["ESP"]
    pid = xrkdbg.readLong(esp + 4)

    xrk_api_call("RegisterServicesProcess", regs, {"pid": pid})


# -------------------------------------------------------------------------
# COM
# -------------------------------------------------------------------------


def run_CoInitializeEx(regs):
    """
        ole32.CoInitializeEx

        CoInitialize-->CoInitializeEx-->wCoInitializeEx
        CoInitializeWOW-->CoInitializeEx==>>||

          LPVOID pvReserved,
          DWORD dwCoInit

        there is another api, but we don't care much: CoInitializeSecurity
    """
    xrk_api_call("CoInitializeEx", regs)


def run_CoCreateInstanceEx(regs):
    """
        ole32.CoCreateInstanceEx

        CoCreateInstance-->CoCreateInstanceEx

          _In_    REFCLSID     rclsid,
          _In_    IUnknown     *punkOuter,
          _In_    DWORD        dwClsCtx,
          _In_    COSERVERINFO *pServerInfo,
          _In_    DWORD        dwCount,
          _Inout_ MULTI_QI     *pResults
    """
    xrk_api_call("CoCreateInstanceEx", regs)


# -------------------------------------------------------------------------
# ENF OF FILE
# -------------------------------------------------------------------------
