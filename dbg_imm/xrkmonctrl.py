# -*- coding: utf-8 -*-

"""
    xrkmon ctrl

    there are 3 types of hooks:
        1. hooked:  dll loaded, api hooked
        2. hooking: dll not loaded, will convert to hooked when dll is loaded
        3. others:  not added, which means we don't need these apis for now

    sometimes, we need to do some global stuff or to some apis that belong to all 3 types of hooks, like: global pause/un_pause/pt_cstk/pt_call
    so, we shall do that to all 3 types of hooks.

    for pause/un_pause, because dbg.pause()/dbg.run() doesn't work in run_cbk, so we have to handle all 3 types of hooks:
        1. hooked:  call api_hk.gua_set_pause() --> convert to pause mode
        2. hooking: call api_hk.gua_set_pause() --> set api_hk.shall_pasue flag
        3. others:  set k_api_config[api_name]["cmn"].shall_pause = True
    !+ remember, for hooked/hooking apis, we still have to update k_api_config[api_name]["cmn"].shall_pause,
       because that has to take function when api is removed then added again.

    for pt_cstk/pt_call, we just update k_api_config[api_name]["cmn"].is_pt_cstk/is_pt_call, and check these flags at run_cbk, everything is done
"""

import os
import sys
import inspect
import debugger
import traceback

try:
    import xrklog
    import xrkdbg
    import xrkdef
    import xrkhook
    import xrkcstk
    import xrkutil
    import xrkcloud
    import xrkpefilex
    import xrkmonapis
    from xrkhook import PausableHook
except:
    this_path = os.path.split(os.path.realpath(inspect.stack()[-1][1]))[0]
    sys.path.append(this_path)
    try:
        import xrklog
        import xrkdbg
        import xrkdef
        import xrkhook
        import xrkcstk
        import xrkutil
        import xrkcloud
        import xrkpefilex
        import xrkmonapis
        from xrkhook import PausableHook
    except Exception, e:
        import immlib as dbglib
        dbg = dbglib.Debugger()
        dbg.log("xrkmon ctrl import error: %s" % e, highlight=1)
        error = traceback.format_exc()
        while len(error) > 200:
            tmp = error[:200]
            dbg.log("  %s" % tmp, highlight=1)
            error = error[200:]
        dbg.log("  %s" % error, highlight=1)

        assert False


# ---------------------------------------------------------------------------
# hook ctrl
# ---------------------------------------------------------------------------


class ctrlCmn:
    # ---------------------------------------------------------------------------
    # comman controls over all apis
    # ---------------------------------------------------------------------------
    def __init__(self, shall_pause=False, cdl_pause=None,
                 is_pt_cstk=False, cdl_pt_cstk=None,
                 is_pt_call=True,
                 is_always_success=False):
        """
            @param: shall_pause       : BOOL : shall debugger pause when api hit
            @param: cdl_pause         : obj  : obj of xrkdef.cbkStruct, or None: if not None and cdl_pause.invoke() return True when api hit, then pause debugger
            @param: is_pt_cstk        : BOOL : shall print call stack when api hit
            @param: cdl_pt_cstk       : obj  : obj of xrkdef.cbkStruct, or None
            @param: is_pt_call        : BOOL : shall print call invoke when api hit
            @param: is_always_success : BOOL : shall modify result of api to make sure it "success"
        """
        # ---------------------------------------------------------------------------
        # this flag only works when new api hook is added.
        # then, if api will not be added again(removed first), this flag works for nothing, will be store as: PausableApiHook.shall_pause
        # but when api is re-added, this flag function again
        self.shall_pause = shall_pause

        # ---------------------------------------------------------------------------
        # whether pause, depend on:
        #     1. hook mode: pause or un pause
        #     2. has conditional pause
        self.cdl_pause = cdl_pause

        # ---------------------------------------------------------------------------
        # whether print call stack, depend on:
        #     1. these two flags
        self.is_pt_cstk = is_pt_cstk
        self.cdl_pt_cstk = cdl_pt_cstk

        # ---------------------------------------------------------------------------
        # whether print call details, depend on:
        #     1. this flag
        self.is_pt_call = is_pt_call

        # is change ret of api
        self.is_always_success = is_always_success

    def __str__(self):
        """
            get description string, for printing...

            @return: STRING
        """
        ret = ""
        if self.shall_pause is not False:
            ret = ret + "shall_pause" + ", "
        # ...
        # TODO
        # ...
        if self.is_always_success is not False:
            ret = ret + "always_success" + ", "
        return ret.strip(", ")

    def to_dict(self):
        """
            get dict description, for printing...

            @return: DICT:
        """
        return {"shall_pause": type(self.shall_pause),
                "cdl_pause": type(self.cdl_pause),
                "is_pt_cstk": self.is_pt_cstk,
                "cdl_pt_cstk": type(self.cdl_pt_cstk),
                "is_pt_call": self.is_pt_call,
                "is_always_success": self.is_always_success}

    def update_from_dict(self, pairs):
        """
            update filed from dict

            @param: pairs : DICT : like this: {"shall_pause": True, "is_pt_cstk": True, ...}

            @return: BOOL: is real changes made
        """
        dict_ = self.to_dict()
        not_change_cnt = 0
        for (d, x) in pairs.items():

            if d not in dict_:
                xrklog.error("error: update_from_dict: attr: %s" % d)
                continue

            if d == "shall_pause" and self.shall_pause != x:
                    self.shall_pause = x

            elif d == "cdl_pause" and self.cdl_pause != x:
                    self.cdl_pause = x

            elif d == "is_pt_cstk" and self.is_pt_cstk != x:
                    self.is_pt_cstk = x

            elif d == "cdl_pt_cstk" and self.cdl_pt_cstk != x:
                    self.cdl_pt_cstk = x

            elif d == "is_pt_call" and self.is_pt_call != x:
                    self.is_pt_call = x

            elif d == "is_always_success" and self.is_always_success != x:
                    self.is_always_success = x

            else:
                # don't need to update
                not_change_cnt = not_change_cnt + 1

        return not_change_cnt != len(pairs)

    def check_has_cfg(self, str_):
        """
            check has config

            @param: str_: STRING

            @return: BOOL
        """
        return str_ in ["shall_pause",
                        "cdl_pause",
                        "is_pt_cstk",
                        "cdl_pt_cstk",
                        "is_pt_call",
                        "is_always_success"]


class callSumApiRecordStacks:
    # ---------------------------------------------------------------------------
    # debugtypes.Stack list and it's invoke count, for call summary
    # ---------------------------------------------------------------------------
    def __init__(self, stacks):
        """
            @param: stacks : LIST : debugtypes.Stack list
        """
        self.stacks = stacks
        self.invoke_cnt = 1

    def is_same_record(self, stacks):
        """
            compare specifed debugtypes.Stack list with self.stacks, check if it's same

            @param: stacks : LIST : debugtypes.Stack list to compare

            @return: BOOL
        """
        return xrkcstk.check_is_same_stack(self.stacks, stacks)


class callSumApiRecordStacksEx:
    # ---------------------------------------------------------------------------
    # xrkcstk.StackEx list and it's invoke count, for call summary
    # ---------------------------------------------------------------------------
    def __init__(self, stacks_record):
        """
            @param: stacks_record : obj : obj of callSumApiRecordStacks
        """
        self.stacks_ex = xrkcstk.stacks_to_stacks_ex(stacks_record.stacks)
        self.invoke_cnt = stacks_record.invoke_cnt


class callSumApiRecord:
    # ---------------------------------------------------------------------------
    # for api call summary
    # each obj represents one "call path", or "record" we may call it.
    #
    # a list of callSumApiRecord look "like" this:    #
    #    {"GetProcAddress": {"call_cnt": 37, "no_stack_cnt": 0, "stacks_list": [stack, stack, stack, stack, ....], "is_ok_cstk_list": [True, True, ...], "is_ok_tid_list": [True, True, ...]},
    #     "LoadLibraryExW": {"call_cnt": 20, "no_stack_cnt": 1, "stacks_list": [stack, stack, stack, stack, ....], "is_ok_cstk_list": [True, True, ...], "is_ok_tid_list": [True, True, ...]},
    #     "send": {"call_cnt": 1, "no_stack_cnt": 1, "stacks_list": []}}
    # ---------------------------------------------------------------------------
    def __init__(self, api_name):
        """
           @param: api_name: STRING: api name.
        """
        self.api_name = api_name

        # total times api hit
        self.call_cnt = 0

        # total times that imm get call stack fail, when api hit
        self.no_stack_cnt = 0

        # a list of normal stacks
        self.stacks_list = []

        # sync to self.stack_list, if stacks pass call stack filter
        self.is_ok_cstk_list = []

        # sync to self.stack_list, if stacks pass tid filter
        self.is_ok_tid_list = []

    def add_record(self, is_ok_cstk, is_ok_tid):
        """
            this "record" is invoked again, add info

            @param: is_ok_cstk: BOOL
            @param: is_od_tid: BOOL
        """
        self.call_cnt = self.call_cnt + 1

        cur_stacks = xrkdbg.callStack()
        if cur_stacks is None or len(cur_stacks) == 0:
            self.no_stack_cnt = self.no_stack_cnt + 1

        else:
            # these 3 lists have to keep sync with each other
            # TODO: replace with a list of TUPLE ?
            self.stacks_list.append(cur_stacks)
            self.is_ok_cstk_list.append(is_ok_cstk)
            self.is_ok_tid_list.append(is_ok_tid)


class monCtrl:
    # ---------------------------------------------------------------------------
    # provide common control interfaces to all knolwdges.
    # !+ no special interface or user interface provided by this class.
    # ---------------------------------------------------------------------------
    def __init__(self):
        """
            set default all
        """
        self.dft_all()

    # ---------------------------------------------------------------------------
    # update

    def update(self):
        """
            update self to cloud

            !+ take care of python's class modeling.....
        """
        xrkcloud.cloud_set(v_id_monCtrl, self)

    def update_global_cfgs(self, pairs):
        """
            update local self.__global_cfgs__, and may update to cloud if something really changed.

            @param: pairs : DICT : dict, like: {"work_mode": "debug", ...}

            !+ self.__global_cfgs__ dict is not complex, so we can invoke xrkutil.update_dict_deep()
        """
        self.__global_cfgs__ = xrkutil.update_dict_directly(self.__global_cfgs__, pairs)
        self.update()

    def update_api_config(self, pairs):
        """
            update local self.__api_config__, and may update to cloud if something really changed.

            @param: pairs : DICT : dict, like: {"Sleep": {"xxxx": xxxx}}

            !+ self.__api_config__ dict is very complex, if huge amount of changes is make, please invoke self.update() directly.
        """
        self.__api_config__, is_changed = xrkutil.update_dict_deep(self.__api_config__, pairs)
        if is_changed:
            self.update()

    def update_md_names(self, pairs):
        """
            update local self.__md_names__, and may update to cloud if something really changed

            @param: pairs : DICT : dict, like: {}

            !+ self.__md_names__ dict is not complex, so we can invoke xrkutil.update_dict_deep()
        """
        self.__md_names__, is_changed = xrkutil.update_dict_deep(self.__md_names__, pairs)
        if is_changed:
            self.update()

    def update_tid(self, pairs):
        """
            update local self.__tid__, and may update to cloud if something really changed

            @param: pairs : DICT : dict, like: {}

            !+ self.__tid__ dict is not complex, so we can invoke xrkutil.update_dict_deep()
        """
        self.__tid__, is_changed = xrkutil.update_dict_deep(self.__tid__, pairs)
        if is_changed:
            self.update()

    def update_param_summary(self, pairs):
        """
            update local self.__param_summary__ dict, then update to cloud

            @param: pairs : DICT : dict, like: {}
        """
        self.__param_summary__ = xrkutil.update_dict_directly(self.__param_summary__, pairs)
        self.update()

    def update_call_summary(self, pairs):
        """
            update local self.__call_summary__ dict, then update to cloud

            @param: pairs : DICT : dict, like: {api_name: callSumApiRecord}

            !+ update dict directly. or the comparison of dict deep would take too much time, even freeze ui
        """
        self.__call_summary__ = xrkutil.update_dict_directly(self.__call_summary__, pairs)
        self.update()

    def update_itd_list(self, pairs):
        """
            update self.__itd_list__ dict, and may update to cloud if something really changed

            @param: pairs : DICT : dict, like: {}

            !+ self.__itd_list__ dict is not complex, so we can invoke xrkutil.update_dict_deep()
        """
        self.__itd_list__, is_changed = xrkutil.update_dict_deep(self.__itd_list__, pairs)
        if is_changed:
            self.update()

    def update_load_dll_hks(self, list_):
        """
            update self.load_dll_hks, and update to cloud directly

            @param: list_ : LIST : a list of xrkdef.loadDllCbkStruct
        """
        self.load_dll_hks = list_
        self.update()

    # ---------------------------------------------------------------------------
    # dft

    def dft_global_cfgs(self):
        """
            default global config, and update to cloud
        """
        xrklog.info("default monCtrl: global config", add_prefix=False)
        # ---------------------------------------------------------------------------
        # work_dir            : STRING : base dir to create/save/backup files/dirs
        #
        # work_mode           : STRING : available work modes:
        #                                "debug" : apply all filters, and print everything
        #                                "log"   : add everything to cloud, and pt sometimes
        #
        # is_log_time_elasped : BOOL   : is log time that run_cbk take(default False)
        #
        # is_log_params       : BOOL   : (debug mode)is log api call params
        # is_log_cstk         : BOOL   : (debug mode)is log call stack
        #
        # verbose             : BOOL   : is log verbose
        # ---------------------------------------------------------------------------
        self.__global_cfgs__ = {
            "work_dir": r"C:\\Documents and Settings\\Administrator\\Desktop\\__work_dir__\\",
            "work_mode": "debug",
            "is_log_time_elasped": False,
            "is_log_params": True,
            "is_log_cstk": True,
            "verbose": True}
        self.update()

    def dft_api_config(self):
        """
            default all apis, and update to cloud
        """
        xrklog.info("default monCtrl: api config", add_prefix=False)

        k_special_apis = {
            "connect": {"is_redirect": False, "cdl_redirect": None, "redirect_ip": ""},
            "send": {"is_pt_send": True},
            "sendto": {"is_pt_send": True},
            "WSASendTo": {"is_pt_send": True},
            "WSASend": {"is_pt_send": True},
            "WSAConnect": {"is_redirect": False, "cdl_redirect": None, "redirect_ip": ""},
            "MoveFileWithProgressW": {"is_backup_file": True},
            "RemoveDirectoryW": {"is_backup_file": True},
            "ReplaceFileW": {"cmn": ctrlCmn(shall_pause=True), "is_backup_file": True},
            "DeleteFileW": {"cmn": ctrlCmn(shall_pause=True), "is_backup_file": True},
            "CreateThread": {"is_log_new_thread_start": True, "is_bp_new_thread_start": True},
            "CreateRemoteThread": {"is_log_new_thread_start": False, "is_bp_new_thread_start": False},
            "SleepEx": {"shorten_edge": 100, "shorten_to_": 0},
            "GetModuleFileNameW": {"fake_md_name": None}}

        k = {}

        for api_name in xrkmonapis.iter_all_api_names():

            # sepcial config of special api
            if api_name in k_special_apis:
                k[api_name] = k_special_apis[api_name]

            # assign config for non-special api
            if api_name not in k:
                k[api_name] = {}

            # "cmn" for all api
            if "cmn" not in k[api_name]:
                k[api_name]["cmn"] = ctrlCmn()

        self.__api_config__ = k
        self.update()

    def dft_md_names(self):
        """
            default all module names, and update to cloud

            is_care             : BOOL : do we care about md name filter
            md_names            : LIST : a list of strings that we're insterested in
                                            1111:       because i always rename sample to 1111.exe and debug
                                            svchost:    sample always copy to another folder and rename as svchost.exe then exec it. we negelect the trouble of executing another command line to add this stuff.
            is_no_stack_as_true : BOOL : xx
                                         we take this as True, but it will result to some apis that shall be filter are not filtered. like:
                                            lstrlenA <-- crypt32.CryptInitOIDFunctionSet || str1 : "CryptDllEncodePublicKeyAndParameters"
                                            lstrcpynW <-- comctl32.7745B789 || str2 : "\WindowsShell.Manifest"; str1 : ""; size : 0x000000FA;
                                            GetModuleFileNameW <-- ole32.ThreadNotification || handle : 0x00000000;
                                         after all, u shall update the way to get stacks.... that's everything.
            is_no_md_as_true    : BOOL : xx
        """
        xrklog.info("default monCtrl: md names", add_prefix=False)

        self.__md_names__ = {"is_care": True,
                             "md_names": ["1111", "svchost"],
                             "is_no_stack_as_true": True,
                             "is_no_md_as_true": True}

        # update to cloud
        self.update()

    def dft_tid(self):
        """
            default all tids, and update to cloud
        """
        xrklog.info("default monCtrl: tid", add_prefix=False)
        self.__tid__ = {"is_include_main_thread": False,
                        "is_exclude_main_thread": False,
                        "is_only_care_include_tids": False,
                        "include_tids": [],
                        "is_only_care_exclude_tids": False,
                        "exclude_tids": []}
        self.update()

    def dft_param_summary(self):
        """
            default all param summary, and update to cloud
        """
        xrklog.info("default monCtrl: param summary", add_prefix=False)
        self.__param_summary__ = {"strs": [],
                                  "svcs": [],
                                  "svc_names": [],
                                  "io_ctrl_codes": [],
                                  "file_dirs": [],
                                  "mutexs": [],
                                  "reg_sucks": [],
                                  "ws2_32s": [],
                                  "internets": [],
                                  "windows": [],
                                  "cbk_procs": [],
                                  "send_lens": [],
                                  "alloc_sizes": []}
        self.update()

    def dft_call_summary(self):
        """
            {api_name: callSumApiRecord}

                {"GetProcAddress": {"call_cnt": 37, "no_stack_cnt": 0, "stacks_list": [stack, stack, stack, stack, ....], "is_ok_cstk_list": [True, True, ...], "is_ok_tid_list": [True, True, ...]},
                 "LoadLibraryExW": {"call_cnt": 20, "no_stack_cnt": 1, "stacks_list": [stack, stack, stack, stack, ....], "is_ok_cstk_list": [True, True, ...], "is_ok_tid_list": [True, True, ...]},
                 "send": {"call_cnt": 1, "no_stack_cnt": 1, "stacks_list": []}}
        """
        xrklog.info("default monCtrl: call summary", add_prefix=False)
        self.__call_summary__ = {}
        self.update()

    def dft_itd_list(self):
        """
            itd list
        """
        xrklog.info("default monCtrl: itd list", add_prefix=False)
        self.__itd_list__ = {"itd_strs": {"is_care": False, "items": [], "is_pause": False},
                             "itd_file_names": {"is_care": False, "items": [], "is_pause": False},
                             "itd_lib_names": {"is_care": False, "items": ["KERNEL32.DLL", "SFC_OS.DLL"], "is_pause": False},
                             "itd_reg_names": {"is_care": False, "items": ["Run"], "is_pause": False},
                             "itd_mm_sizes": {"is_care": False, "items": [], "is_pause": False}}
        self.update()

    def dft_load_dll_hks(self):
        """
            []

            k: a list of xrkdef.loadDllCbkStruct.
            because k is not a dict, so no interface: may_init_update_k_config_load_dll_hks().

            loadDllCallCbksHook access this list, call cbks if list has newly loaded dll_name, then remove dll from the list

            struct:
                k: [] xrkdef.loadDllCbkStruct
                    loadDllCbkStruct:
                                      dll_name
                                      cbks: [] cbkStruct
                        cbk:
                            cbk
                            param1
                            param2
                            param3
                            param4
        """
        xrklog.info("default monCtrl: load dll hks", add_prefix=False)
        self.load_dll_hks = []
        self.update()

    def dft_all(self):
        """
            default all cloud thing
        """
        self.dft_global_cfgs()
        self.dft_api_config()
        self.dft_md_names()
        self.dft_tid()
        self.dft_param_summary()
        self.dft_call_summary()
        self.dft_itd_list()
        self.dft_load_dll_hks()

    # ---------------------------------------------------------------------------
    # get

    def get_global_cfgs(self):
        return self.__global_cfgs__

    def get_api_config(self):
        return self.__api_config__

    def get_md_names(self):
        return self.__md_names__

    def get_tid(self):
        return self.__tid__

    def get_param_summary(self):
        return self.__param_summary__

    def get_call_summary(self):
        return self.__call_summary__

    def get_itd_list(self):
        return self.__itd_list__

    def get_load_dll_hks(self):
        return self.load_dll_hks

    # ---------------------------------------------------------------------------
    # check has key

    def check_global_cfgs_has_key(self, key):
        return key in self.__global_cfgs__

    def check_api_config_has_key(self, key, kk=None):
        if kk is None:
            return key in self.__api_config__
        else:
            return kk in self.__api_config__[key]

    def check_md_names_has_key(self, key):
        return key in self.__md_names__

    def check_tid_has_key(self, key):
        return key in self.__tid__

    def check_itd_list_has_key(self, key, kk=None):
        if kk is None:
            return key in self.__itd_list__
        else:
            return kk in self.__itd_list__[key]

    # ---------------------------------------------------------------------------
    # get value type of key

    def get_global_cfgs_key_value_type(self, key):
        """
            @return: type, None if no key
        """
        return key in self.__global_cfgs__ and type(self.__global_cfgs__[key]) or None

    def get_api_config_key_value_type(self, key, kk=None):
        """
            @return: type, None if no key
        """
        if kk is not None:
            return key in self.__api_config__ and type(self.__api_config__[key]) or None
        else:
            return kk in self.__api_config__[key] and type(self.__api_config__[key][kk]) or None

    def get_md_names_key_value_type(self, key):
        """
            @return: type, None if no key
        """
        return key in self.__md_names__ and type(self.__md_names__[key]) or None

    def get_tid_key_value_type(self, key):
        """
            @return: type, None if no key
        """
        return key in self.__tid__ and type(self.__tid__[key]) or None

    def get_itd_list_key_value_type(self, key, kk=None):
        """
            @return: type, None if no key
        """
        if kk is not None:
            return key in self.__itd_list__ and type(self.__itd_list__[key]) or None
        else:
            return kk in self.__itd_list__[key] and type(self.__itd_list__[key][kk]) or None

    # ---------------------------------------------------------------------------
    # get attr types descriptions

    def get_global_cfgs_attr_types_desc(self, header="global flags attr types"):
        return xrklog.get_dict_attrs_descriptions_as_table(self.__global_cfgs__, header=header)

    def get_api_config_attr_types_desc(self, header="api config attr types"):
        return xrklog.get_dict_attrs_descriptions_as_table(self.__api_config__, header=header)

    def get_md_names_attr_types_desc(self, header="md names attr types"):
        return xrklog.get_dict_attrs_descriptions_as_table(self.__md_names__, header=header)

    def get_tid_attr_types_desc(self, header="tid attr types"):
        return xrklog.get_dict_attrs_descriptions_as_table(self.__tid__, header=header)

    def get_itd_list_attr_types_desc(self, header="itd list attr types"):
        return xrklog.get_dict_attrs_descriptions_as_table(self.__itd_list__, header=header)

    # ---------------------------------------------------------------------------
    # get attr details descriptions

    def get_global_cfgs_attr_details_desc(self, header="global flags attr details"):
        return xrklog.get_dict_details_descriptions_as_table(self.__global_cfgs__, header=header)

    def get_api_config_attr_details_desc(self, header="api config attr details"):
        return xrklog.get_dict_details_descriptions_as_table(self.__api_config__, header=header)

    def get_md_names_attr_details_desc(self, header="md names attr details"):
        return xrklog.get_dict_details_descriptions_as_table(self.__md_names__, header=header)

    def get_tid_attr_details_desc(self, header="tid attr details"):
        return xrklog.get_dict_details_descriptions_as_table(self.__tid__, header=header)

    def get_param_summary_attr_details_desc(self, header="param summary attr details", only_ok=False):
        return xrklog.get_dict_details_descriptions_as_table(self.__param_summary__, header=header)

    def get_call_summary_attr_details_desc(self, header="call summary attr details", only_ok=False):
        """
            {"GetProcAddress": {"call_cnt": 37, "no_stack_cnt": 0, "stacks_list": [stack, stack, stack, stack, ....], "is_ok_cstk_list": [True, True, ...], "is_ok_tid_list": [True, True, ...]},
             "LoadLibraryExW": {"call_cnt": 20, "no_stack_cnt": 1, "stacks_list": [stack, stack, stack, stack, ....], "is_ok_cstk_list": [True, True, ...], "is_ok_tid_list": [True, True, ...]},
             "send": {"call_cnt": 1, "no_stack_cnt": 1, "stacks_list": []}}

            ==>

            api: GetProcAddress
                                call_cnt: 37, no_stack_cnt: 0
                                procedure call cnt: 14
                                                       xxxx kernel32.GetProcAddress
                                                       xxxx 1111.xxxx
                                procedure call cnt: 23
                                                       xxxx kernel32.GetProcAddress
                                                       yyyy 1111.yyyy
                                                       zzzz 1111.zzzz
            api: LoadLibraryExW
                                call_cnt: 20, no_stack_cnt: 1
                                procedure call cnt: 19
                                                       xxxx kernel32.LoadLibraryExW
                                                       xxxx 1111.xxxx
            api: send
                      call_cnt: 1, no_stack_cnt: 1
                      no procedures recorded
        """
        if len(self.__call_summary__) == 0:
            return xrklog.get_dict_details_descriptions_as_table({}, header=header + ": empty")
        else:
            lines = []
            for (api_name, record) in self.__call_summary__.items():
                lines.append("api: %s" % api_name)
                lines.append("call_cnt: %d, no_stack_cnt: %d" % (record.call_cnt, record.no_stack_cnt))
                stacks_list = record.stacks_list
                if len(stacks_list) == 0:
                    lines.append("no procedures recorded")
                else:
                    # sum same stacks, and convert to stacks record
                    stacks_record_list = []
                    for stacks in stacks_list:
                        if only_ok:
                            # negelect not ok ones
                            index = stacks_list.index(stacks)
                            if not record.is_ok_cstk_list[index] or not record.is_ok_tid_list[index]:
                                continue
                        is_exist = False
                        for stacks_record in stacks_record_list:
                            if stacks_record.is_same_record(stacks):
                                stacks_record.invoke_cnt = stacks_record.invoke_cnt + 1
                                is_exist = True
                                break
                        if not is_exist:
                            stacks_record_list.append(callSumApiRecordStacks(stacks))

                    # convert to stacksEx record
                    stacks_ex_record_list = []
                    for stacks_record in stacks_record_list:
                        stacks_ex_record_list.append(callSumApiRecordStacksEx(stacks_record))

                    # gather info
                    for stacks_ex_record in stacks_ex_record_list:
                        lines.append("procedure call cnt: %d" % (stacks_ex_record.invoke_cnt))
                        last_called_from = 0
                        for stack_ex in stacks_ex_record.stacks_ex:
                            if last_called_from != stack_ex.stack.calledfrom:
                                last_called_from = stack_ex.stack.calledfrom
                                lines.append("    %20s      %s" % (stack_ex.calledfrom_symbol_ex, stack_ex.stack.procedure))
                            else:
                                lines.append("    %20s      %s" % (" ", stack_ex.stack.procedure))
                lines.append(" ")
            return lines

    def get_itd_list_attr_details_desc(self, header="itd list attr details"):
        return xrklog.get_dict_details_descriptions_as_table(self.__itd_list__, header=header)

    # ENF OF CLASS monCtrl
    # ---------------------------------------------------------------------------

#
# structure of monCtrl:
#       monCtrl
#
v_id_monCtrl = "monCtrl"


def get_cloud_monCtrl():
    """
        get global control from cloud. if not exists in cloud, create one first.

        all modifications of any knowledge should by this
    """
    k = xrkcloud.cloud_get(v_id_monCtrl)
    if k is None:
        # with construction of object instance, cloud will be updated to default.
        # this is done by class.__init__
        monCtrl()
        k = xrkcloud.cloud_get(v_id_monCtrl)
        assert k is not None
    return k


# ---------------------------------------------------------------------------
# api config
# ---------------------------------------------------------------------------


def api_config_get(api_name):
    """
        get config of api

        @param: api_name : STRING : api name

        @return: DICT : api config dict, like this: {"cmn": ctrlCmn(), "xx": xx}
    """
    k_api_config = get_cloud_monCtrl().get_api_config()
    assert api_name in k_api_config
    return k_api_config[api_name]


def api_config_get_common(api_name):
    """
        get common config of api

        @param: api_name : STRING : api name

        @return: obj : obj of ctrlCmn
    """
    return api_config_get(api_name)["cmn"]


def api_config_update(api_name, pairs):
    """
        update api config by pairs

        @param: api_name : STRING : api name
        @param: pairs    : DICT   : api config dict, like this: {"cmn": ctrlCmn(xx=xx), "redirect_to": None}
    """
    get_cloud_monCtrl().update_api_config({api_name: pairs})


def api_config_update_cmn(api_name, pairs):
    """
        update common api config by pairs

        @param: api_name : STRING : api name
        @param: pairs    : DICT   : api common config dict, like this: {"shall_pause": True, "is_pt_cstk": True}
    """
    api_cmn = api_config_get_common(api_name)
    if api_cmn.update_from_dict(pairs):
        get_cloud_monCtrl().update_api_config({api_name: {"cmn": api_cmn}})


# ---------------------------------------------------------------------------
# api hooks: hooked/hooking
# ---------------------------------------------------------------------------

#
# this is UGLY!!!
#


def proxy_install_api_hook_by_name(dll_name, api_name, api_addr):
    """
        when dll loaded and api(dll export) address resolved(by pefile, and imm not analized dll yet), install hook for it.

        @param: dll_name : STRING : dll name that is newly loaded
        @param: api_name : STRING : api name that is newly available
        @param: api_addr : STRING : address of api_name

        !+ obj of PausableApiHook can be "pickled", and it's not too complicated to store a list of PausableApiHook objs in xrkdef.loadDllCbkStruct then "pickle" obj of xrkdef.loadDllCbkStruct
        !+ but the real problem is, it's not easy to modify "pickled" PausableApiHook in xrkdef.loadDllCbkStruct
        !+ so, if i wanna pause/unpause at api send(which is not available yet), i have to ...
    """
    api_hooks_manager = get_api_hooks_manager()
    for api_hk in api_hooks_manager.api_hooks:

        if api_hk.api_name == api_name:

            # install hook
            api_hk.install_real(api_addr)

            # update cloud
            api_hooks_manager.update()

            return


class PausableApiHook(PausableHook):
    # ---------------------------------------------------------------------------
    # api hook has two stages:
    #   1. hook not installed. if dll is already loaded, then this stage doesn't exist.
    #   2. hook installed
    #
    # this thing has two modes:
    #   1. pause mode, with pause bp
    #   2. un pause mode, with logging bp
    #
    # mode switch:
    #   1. original mode is depended by field: self.shall_pause.
    #      whether dll is loaded or not, this field determines orignal mode.
    #   2. call method obj.gua_set_pause()/obj.gua_set_un_pause() to switch to pause mode/un pause mode.
    #
    # afterall:
    #   1. if dll is loaded, set to that mode directly.
    #   2. if dll not loaded, udpate fields, so will set to that mode when install
    #
    # if we don't have large amound of api hooks to add at the same time, PausableApiHook.gua_install() works fine.
    # but, if we do have many api hooks to add, please use apiHooksManager.add_apis()
    #
    # user just need to provide api_name and run_cbk, this class will:
    #   1. set api_name as desc(if no desc set)
    #   2. calc addr of api, add hook automatically(if gua_install called)
    #      if dll is not loaded, add proxy_install_api_hook_by_name cbk to k, call cbk when dll loaded, then hook will be installed
    #
    # !+ so, this class contains and manages both hooked and hooking apis. u should always remember this
    # !+ when field of this object changes, we need to re-pickle it.
    # ---------------------------------------------------------------------------
    def __init__(self, api_name, run_cbk, shall_pause):
        """
            @param: api_name    : STRING : api name
            @param: run_cbk     : METHOD : method with prototype: run_xx(regs)
            @param: shall_pause : BOOL   : shall pause or not when api invoke
        """
        PausableHook.__init__(self)
        self.api_name = api_name
        self.run_cbk = run_cbk
        self.shall_pause = shall_pause

        # a flag indicating whether a api is hooked or hooking.
        # if true: api is already hooked.
        # !+ even if manually unhooked by user(cleared bp or cloud), this will not update.
        self.is_installed = False

    def run(self, regs):
        """
            invoke self.run_cbk

            @param: regs : DICT : reg dict

            !+ if some other params is required to run_cbk, provide that in knowledge, as api_config
        """
        assert self.is_installed

        k = get_cloud_monCtrl()
        if k.get_global_cfgs()["is_log_time_elasped"]:

            import datetime
            start = datetime.datetime.now()

            # invoke self.run_cbk
            self.run_cbk(regs)

            end = datetime.datetime.now()

            xrklog.info("api call -- run, time: %.8d msecs, api: %s" % ((end - start).microseconds / 1000, self.api_name), add_prefix=True)

        else:
            # xrklog.info("api call: %s" % (self.api_name), add_prefix=True)
            self.run_cbk(regs)

    def get_is_installed(self):
        """
            get if api hook real installed.

            @return: BOOL : whether hook is really installed
        """
        return self.is_installed

    def install_real(self, addr):
        """
            dll is loaded

            @param: addr: INT: address of api

            1. update comment
            2. install hook

            !+ this is not called from source code of this class, but from proxy_install_api_hook_by_name
        """
        assert not self.is_installed
        assert xrkutil.validate_addr(addr)

        xrkutil.may_update_comment(addr, self.api_name)

        # !+ set field before "pickle"
        self.is_installed = True

        # set bp, pickle
        PausableHook.add(self, self.api_name, addr, self.shall_pause)

        xrklog.info("install api hook: %-25s - 0x%.8X" % (self.api_name, addr), verbose=True)

    def gua_install(self):
        """
            guarantee hook for this api will be installed, whether dll loaded or not.

            1. if dll loaded, install hook
            2. if dll not loaded, add proxy_install_api_hook_by_name to k

            !+ instance method can't be pickled, so can't provide "install_real" here, instead we provide proxy_install_api_hook_by_name, which will invoke "install_real" internally.
            !+ xrkutil.check_has_module takes about 400 mescs, so u'd better not call this.

            !+ if we don't have large amound of api hooks to add at the same time, PausableApiHook.gua_install() works fine.
            !+ but, if we do have many api hooks to add, please use apiHooksManager.add_apis()
        """
        assert not self.is_installed

        # if dll is not installed, and cbk is updated to cloud, but, we need to change updated obj_instance of cbk, so...
        dll_name = xrkmonapis.get_dll_name_by_api_name(self.api_name)

        # this take 400 mescs
        if xrkutil.check_has_module(dll_name):
            addr = xrkdbg.getAddress(self.api_name)
            if addr != -1:
                self.install_real(addr)
            else:
                xrklog.highlight("gua install, get api address fail: %s" % self.api_name)
                assert False

        else:
            xrkhook.register_load_dll_cbk("xrkmon_monCtrl", cbk_new_dll_load_monCtrl, force_update=False)
            load_dll_cbks_add_api(self.api_name, proxy_install_api_hook_by_name)

    def remove(self):
        """
            hooked is installed, un hook.

            !+ api hooks container shall remove this obj
        """
        assert self.is_installed
        PausableHook.remove(self)

        self.is_installed = False

    def gua_remove(self):
        """
            1. if hook installed: un hook
            2. if hook not installed: remove install run_cbk from some list
        """
        if self.is_installed:
            self.remove()

        else:
            raise Exception("not implemented")

    def gua_set_pause(self):
        """
            gua dbg pause when api invoked

            1. if hook installed: convert to pause mode
            2. shall_pause set to True
        """
        if self.is_installed:

            PausableHook.set_pause(self)
            # xrklog.info("set shall_pause flag to hooked api and really pause it: %s" % self.api_name)

        else:
            xrklog.info("set shall_pause flag to hooking api: %s" % self.api_name)

        self.shall_pause = True

    def gua_set_un_pause(self):
        """
            gua dbg will not pause when api invoked

            1. if hook installed: convert to un pause mode
            2. shall_pause set to False
        """
        if self.is_installed:

            PausableHook.set_un_pause(self)
            # xrklog.info("set un pause to hooked api: %s" % self.api_name)

        else:
            xrklog.info("set un shall_pause flag to hooking api: %s" % self.api_name)

        self.shall_pause = False

    def get_shall_pause(self):
        """
            get shall pause when api hook hit

            @return: BOOL :
        """
        return self.shall_pause


class apiHooksManager:
    # ---------------------------------------------------------------------------
    # manages all hooked and hooking apis, and relevant breakpoints.
    #
    # 2 types:
    #    hooked  : dll is loaded, hook is installed
    #    hooking : dll is not loaded, but cbk to install hook is added to k_config_load_dll_hks(hook_run)
    #
    # bps:
    #   when re-add, bp might already removed
    # ---------------------------------------------------------------------------
    def __init__(self):
        """
            init obj, and update to cloud.
        """
        # a list of PausableApiHook
        self.api_hooks = []

        self.__update()

    # ---------------------------------------------------------------------------
    # misc

    def update(self):
        """
            update to cloud

            !+ most of self.__update() shall be called only by method of apiHooksManager.
            !+ for self.update(), there is only one caller: proxy_install_api_hook_by_name()
        """
        self.__update()

    def __update(self):
        """
            update to cloud
        """
        xrkcloud.cloud_set(v_id_api_hooks_manager, self)

        xrklog.info("update api hooks manager to cloud", verbose=True)

    def __get_apis(self):
        """
            get all api names

            @return: LIST : a list of api names
        """
        apis = []
        for api_hk in self.api_hooks:

            assert api_hk.api_name not in apis
            apis.append(api_hk.api_name)

        return apis

    def __is_api_installed(self, api_name):
        """
            check is api installed by api_name

            @param: api_name : STRING : api name

            @return: BOOL :
        """
        for api_hk in self.api_hooks:

            if api_hk.api_name == api_name:
                return True

        return False

    # ---------------------------------------------------------------------------
    # add

    def __add_apis_by_pairs(self, k_api_config, pairs):
        """
            hook, add pairs to list. update to k if something new added

            @param: k_api_config : obj  : cloud of api config, to determine whether pause or not
            @param: pairs        : DICT : {api_name: run_cbk, ...}

            @return: LIST : ret by self.__add_apis_by_pairs_x()

            !+ generate a new dict, and proxy to self.__add_apis_by_pairs_x()
            !+ apis might not belong to same dll, but that doesn't matter.
            !+ whether hook original mode is pause or unpause, depend on k_api_config
        """
        new_pairs = {}

        for (api_name, run_cbk) in pairs.items():
            assert not self.__is_api_installed(api_name)
            dll_name = xrkmonapis.get_dll_name_by_api_name(api_name).lower()

            # gather newe_pairs
            if dll_name not in new_pairs:
                new_pairs[dll_name] = {}
            assert api_name not in new_pairs[dll_name]
            new_pairs[dll_name][api_name] = run_cbk

        # add, and will update to cloud
        return self.__add_apis_by_pairs_x(k_api_config, new_pairs)

    def __add_apis_by_pairs_x(self, k_api_config, pairs):
        """
            hook, add pairs to list, update to k if something new added.

            @param: k_api_config : obj  : api config in cloud
            @param: pairs        : DICT : {dll_name: {api_name: run_cbk, api_name: run_cbk, ...}, dll_name: {api_name: run_cbk, ...}, ...}

            @return: LIST: empty List
        """
        # ---------------------------------------------------------------------------
        # get all module list.
        # we add api hooks in this way, because the process of getting module list alone, takes 400 mescs.
        # if we get module list for each api, time consumed will untoleratable.
        # ---------------------------------------------------------------------------
        all_md_keys_tmp = xrkdbg.getAllModules().keys()
        all_md_keys = []
        for tmp in all_md_keys_tmp:
            all_md_keys.append(tmp.lower())

        for (dll_name, x) in pairs.items():

            # x: {api_name: run_cbk, api_name: run_cbk, ...}
            for (api_name, run_cbk) in x.items():

                api_ = PausableApiHook(api_name, run_cbk, k_api_config[api_name]["cmn"].shall_pause)
                if dll_name.lower() in all_md_keys:

                    # dll loaded, api ready, install hook directly.
                    addr = xrkdbg.getAddress(api_name)
                    if addr != -1:
                        api_.install_real(addr)
                    else:
                        raise Exception("add apis by pairs x, get api address fail: %s" % api_name)

                else:
                    # dll not loaded, register load dll cbk, install hooks when dll loaded
                    xrkhook.register_load_dll_cbk("xrkmon_monCtrl", cbk_new_dll_load_monCtrl, force_update=False)
                    load_dll_cbks_add_api(api_name, proxy_install_api_hook_by_name)

                # add to self.api_hooks list.
                self.api_hooks.append(api_)

        # update to cloud
        self.__update()

        return []

    def add_apis(self, api_names):
        """
            hook apis by names(use pre-defined run_cbks)

            @param: api_names : LIST : a list of api names
            @return: LIST: installed_apis: [api1, api2]

            !+ generate a new dict, and proxy to self.__add_apis_by_pairs()
            !+ will update to cloud by method: self.__add_apis_by_pairs(), so this doesn't need to call: self.__update()
        """
        k_api_config = get_cloud_monCtrl().get_api_config()
        installed_apis = []
        pairs = {}

        for api_name in api_names:

            if self.__is_api_installed(api_name):

                # !+ hook already installed, by set bp anyway, because bp might already be removed
                addr = xrkdbg.getAddress(api_name)
                if xrkutil.check_has_bp(addr) and xrkutil.validate_addr(addr):

                    # set corrent bp
                    shall_pause = False
                    if api_name in k_api_config:
                        shall_pause = k_api_config[api_name]["cmn"].shall_pause

                    if shall_pause:
                        xrkdbg.setBreakpoint(addr)
                    else:
                        xrkdbg.setLoggingBreakpoint(addr)

                else:
                    xrklog.warn("re-bp already installed api hook: %s, addr 0x%.8X not valid" % (api_name, addr), addr=addr, verbose=True)

                # gather installed apis as ret
                installed_apis = xrkutil.add_to_set(installed_apis, api_name)[0]

            else:
                # hook not installed, add to pairs
                run_cbk = xrkmonapis.get_run_cbk_by_api_name(api_name)
                assert run_cbk is not None
                pairs[api_name] = run_cbk

        # proxy to self.__add_apis_by_pairs()
        self.__add_apis_by_pairs(k_api_config, pairs)

        return installed_apis

    def add_dlls(self, dll_names):
        """
            hook apis by dll names.

            @param: dll_names : LIST : a list of dll names

            @return: LIST : a list of api names that's already installed.

            !+ proxy to self.add_apis()
            !+ will update to cloud by method: self.__add_apis_by_pairs(), so this doesn't need to call: self.__update()
        """
        return self.add_apis(xrkmonapis.get_apis_by_dlls(dll_names))

    # ---------------------------------------------------------------------------
    # remove

    def remove_all(self):
        """
            1. gua all hooked/hooking apis are unhooked/removed from k_load_dll_hks
            2. clear field: self.api_hooks
            3. update to k

            @return: LIST: []
        """
        for api_hk in self.api_hooks:
            api_hk.gua_remove()

        self.api_hooks = []
        self.__update()

        # we never call this when we want to remove only all api hooks, because there are some other helper hooks.
        # dbg.cleanHooks()

        return []

    def remove_apis(self, api_names):
        """
            remove api hooks by api names

            @param: api_names : LIST : a list of api names

            @return: LIST: not exist apis: [api1, api2]

            1. gua specified hooked/hooking apis are unhooked/remove from k_load_dll_hks
            2. update field: self.api_hooks
            3. update to k, if something really removed
            4. !+ _RETN series
        """
        is_changed = False
        ret_apis = []
        for api_name in api_names:

            is_exist = False
            for api_hk in self.api_hooks:
                if api_hk.api_name == api_name:

                    # remove
                    api_hk.gua_remove()
                    self.api_hooks.remove(api_hk)

                    # set flag
                    is_exist = True
                    is_changed = True

                    xrklog.info("remove api hook: %s" % api_name)

                    # check other apis
                    break

            if not is_exist:
                ret_apis.append(api_name)
                xrklog.high("remove not exist api hook: %s" % api_name)

        # changed, update to cloud
        if is_changed:
            self.__update()

        for api_name in api_names:
            if api_name + "_RETN" in xrkdbg.listHooks():
                xrklog.info("remove api retn hook: %s" % api_name)
                debugger.remove_hook(api_name + "_RETN")
                # TODO: del bp

        return ret_apis

    def remove_dlls(self, dll_names):
        """
            removed specifed hooked/hooking dlls

            @param: dll_names : LIST : a list of dll names

            !+ proxy to self.remove_apis()
            !+ method self.remove_apis() will update to k
        """
        return self.remove_apis(xrkmonapis.get_apis_by_dlls(dll_names))

    # ---------------------------------------------------------------------------
    # pause

    def set_pause_all(self):
        """
            all hooked/hooking apis will pause when hit.

            @return: LIST : empty list

            1. pause all hooked/hooking apis
            2. update to k

            !+ this only applys to all apis that in self.api_hooks, but not newly added apis.
        """
        for api_hk in self.api_hooks:
            api_hk.gua_set_pause()

        self.__update()

        return []

    def set_pause_apis(self, api_names):
        """
            specified hooked/hooking apis will pause when hit

            @param: api_names : LIST : a list of api names

            @return: LIST : a list of not exist api names

            1. pause specified hooked/hooking apis
            2. update to k, if some changes really happened
        """
        is_changed = False
        ret_apis = []
        for api_name in api_names:

            is_exist = False
            for api_hk in self.api_hooks:
                if api_hk.api_name == api_name:

                    # set pause
                    api_hk.gua_set_pause()

                    # set flag
                    is_exist = True
                    is_changed = True

                    # next
                    break

            if not is_exist:
                ret_apis.append(api_name)
                xrklog.error("pause not exist api: %s" % api_name, verbose=True)

        # update to cloud
        if is_changed:
            self.__update()

        return ret_apis

    def set_pause_dlls(self, dll_names):
        """
            pause specified hooked/hooking dlls

            @param: dll_names : LIST : a list of dll names

            @return: LIST : a list of not exist api names

            !+ method self.set_pause_apis() will update to k
        """
        return self.set_pause_apis(xrkmonapis.get_apis_by_dlls(dll_names))

    # ---------------------------------------------------------------------------
    # un pause

    def set_un_pause_all(self):
        """
            unpause all hooked/hooking apis when api hit

            @return: LIST : empty list

            1. un pause all hooked/hooking apis
            2. update to k
        """
        for api_hk in self.api_hooks:
            api_hk.gua_set_un_pause()

        self.__update()

        return []

    def set_un_pause_apis(self, api_names):
        """
            unpause specified hooked/hooking apis when api hit

            @param: api_names : LIST : a list of api names

            @return: LIST : a list of not exist api names

            1. un pause specified hooked/hooking apis
            2. update to k, if some changed really happened
        """
        is_changed = False
        ret_apis = []
        for api_name in api_names:
            is_exist = False
            for api_hk in self.api_hooks:
                if api_hk.api_name == api_name:

                    # un pause
                    api_hk.gua_set_un_pause()

                    # set flag
                    is_exist = True
                    is_changed = True

                    # check next
                    break

            if not is_exist:
                ret_apis.append(api_name)
                xrklog.error("un pause not exist api: %s" % api_name, verbose=True)

        if is_changed:
            self.__update()
        return ret_apis

    def set_un_pause_dlls(self, dll_names):
        """
            un pause specified hooked/hooking dlls when api hit

            @param: dll_names : LIST : a list of dll names

            @return: LIST : a list of not exist api names

            !+ method self.set_un_pause_apis will update to k
        """
        return self.set_un_pause_apis(xrkmonapis.get_apis_by_dlls(dll_names))

    # ---------------------------------------------------------------------------
    # get

    def get_hooked_apis(self):
        """
            get hooked apis

            @return: LIST : a list of PausableApiHook
        """
        hooked_apis = []

        for api_hook in self.api_hooks:
            if api_hook.get_is_installed():
                hooked_apis.append(api_hook)

        return hooked_apis

    def get_hooking_apis(self):
        """
            get hooking apis

            @return: LIST : a list of PausableApiHook
        """
        hooking_apis = []

        for api_hook in self.api_hooks:
            if not api_hook.get_is_installed():
                hooking_apis.append(api_hook)

        return hooking_apis

    def get_hooked_apis_desc(self):
        """
            get hooked apis desc

            @return: LIST : a list of strings, like this:
                ---------------------------------------------------------------------------
                | send            | WS2_32.DLL    | hooked    | pause     | optional   | is_always_success=True,
                | InternetOpenA   | WININET.DLL   | hooked    | un pause  | critical   | is_always_success=True,
                ---------------------------------------------------------------------------
        """
        hooked_apis = self.get_hooked_apis()
        if len(hooked_apis) == 0:
            return ["hooked api empty"]

        len_col_1 = []
        for api_hook in hooked_apis:
            if len(api_hook.api_name) not in len_col_1:
                len_col_1.append(len(api_hook.api_name))
        len_col_1_max = max((sorted(len_col_1))[-1], 25)

        # header
        lines = ["hooked api cnt: %d" % len(hooked_apis)]
        lines.append("-" * 100)

        k_api_config = get_cloud_monCtrl().get_api_config()
        for api_hook in hooked_apis:

            spa_col_1 = " " * (len_col_1_max - len(api_hook.api_name))
            is_pause_str = api_hook.get_shall_pause() and "pause" or "un pause"
            level_str = xrkmonapis.get_api_level(api_hook.api_name)

            k_api = k_api_config[api_hook.api_name]
            cmn_cfg_str = str(k_api["cmn"])

            lines.append("| %s%s | %15s | %7s | %8s | %10s | %s" %
                         (api_hook.api_name, spa_col_1, xrkmonapis.get_dll_name_by_api_name(api_hook.api_name), "hooked", is_pause_str, level_str, cmn_cfg_str))

        # tail
        lines.append("-" * 100)

        return lines

    def get_hooking_apis_desc(self):
        """
            get hooking apis desc

            @return: LIST : a list of strings, like this:
                ---------------------------------------------------------------------------
                | send            | WS2_32.DLL    | hooking    | pause     | optional   | is_always_success=True
                | InternetOpenA   | WININET.DLL   | hooking    | un pause  | critical   | is_always_success=True
                ---------------------------------------------------------------------------
        """
        hooking_apis = self.get_hooking_apis()
        if len(hooking_apis) == 0:
            return ["hooking api empty"]

        len_col_1 = []
        for api_hook in hooking_apis:
            if len(api_hook.api_name) not in len_col_1:
                len_col_1.append(len(api_hook.api_name))
        len_col_1_max = max((sorted(len_col_1))[-1], 25)

        lines = ["hooking api cnt: %d" % len(hooking_apis)]
        lines.append("-" * 100)

        k_api_config = get_cloud_monCtrl().get_api_config()
        for api_hook in hooking_apis:
            spa_col_1 = " " * (len_col_1_max - len(api_hook.api_name))
            is_pause_str = api_hook.get_shall_pause() and "pause" or "un pause"
            level_str = xrkmonapis.get_api_level(api_hook.api_name)

            k_api = k_api_config[api_hook.api_name]
            cmn_cfg_str = k_api["cmn"].desc_str()

            lines.append("| %s%s | %15s | %7s | %8s | %10s | %s" %
                         (api_hook.api_name, spa_col_1, xrkmonapis.get_dll_name_by_api_name(api_hook.api_name), "hooking", is_pause_str, level_str, cmn_cfg_str))

        lines.append("-" * 100)
        return lines

    def get_all_apis_desc(self):
        """
            @return: LIST : a list of strings
        """
        lines = ["hooked/hooking api cnt: %d" % len(self.api_hooks)]
        return lines + self.get_hooked_apis_desc() + self.get_hooking_apis_desc()

    # ---------------------------------------------------------------------------
    # END OF apiHooksManager
    # ---------------------------------------------------------------------------


#
# structure of api hook manager:
#       apiHooksManager
#
v_id_api_hooks_manager = "id_config_api_hooks_manager"


def get_api_hooks_manager():
    """
        get cloud apiHooksManager. if not exists in cloud, create one.

        @return: obj : obj of apiHooksManager
    """
    k = xrkutil.get_k(v_id_api_hooks_manager)
    if k is None:
        apiHooksManager()
        k = xrkutil.get_k(v_id_api_hooks_manager)
        assert k is not None
    return k


# ---------------------------------------------------------------------------
# load dll hks: monCtrl
# ---------------------------------------------------------------------------

def cbk_new_dll_load_monCtrl(evt, image_name, image_path):
    """
        check cloud load_dll_hks, if we have any cbk to invoke for this newly loaded dll

        @param: evt        : obj    : obj of libevent.LoadDllEvent
        @param: image_name : STRING : newly loaded dll name
        @param: image_path : STRING : newly loaded dll full path

        !+ cbk when new dll is loaded, for monCtrl
    """
    k = get_cloud_monCtrl()
    k_load_dll_hks = k.get_load_dll_hks()

    for load_dll in k_load_dll_hks:

        # load_dll: xrkdef.loadDllCbkStruct
        if load_dll.dll_name.lower() == image_name.lower():

            #
            # we do have cbk to invoke for this newly loaded dll
            #

            # xrklog.high("load new dll, parse: %s" % image_path)

            # pefile.py can't parse loaded mm page here, because it's "loaded".
            # so, we parse file on disk
            export_dict = xrkpefilex.XPE(name=image_path).get_export_dict()
            if export_dict is not None and len(export_dict) != 0 and len(load_dll.cbks) != 0:
                for cbk in load_dll.cbks:

                    # cbk: cbkStructApiValid, providing api address
                    if cbk.api_name in export_dict:
                        cbk.invoke(evt.lpBaseOfDll + export_dict[cbk.api_name])

                    else:
                        xrklog.error("load dll %s, invoke cbk for api %s, but api not in parsed exports" % (image_name, cbk.api_name))

            # we've done it, remove from cloud
            k_load_dll_hks.remove(load_dll)
            k.update_load_dll_hks(k_load_dll_hks)

            return


def load_dll_cbks_add_api(api_name, cbk_proxy):
    """
        add cbk_proxy to load_dll_hks(indirectly), and invoke that cbk_proxy when dll is newly loaded

        @param: api_name  : STRING : api name that will invoke cbk_proxy
        @param: cbk_proxy : method : cbk to invoke when dll loaded and api ready

        1. if dll_name in the list, add cbk to dll's cbks list
        2. if dll_name not in the list, create cbk for dll, then add cbk to it's cbks list, add dll to k
    """
    dll_name = xrkmonapis.get_dll_name_by_api_name(api_name)

    k = get_cloud_monCtrl()
    k_load_dll_hks = k.get_load_dll_hks()

    for i in range(len(k_load_dll_hks)):

        if k_load_dll_hks[i].dll_name.lower() == dll_name.lower():

            # dll in list, direct add

            if k_load_dll_hks[i].add_cbk(api_name, cbk_proxy):

                # xrklog.info("add cbk to existing dll: %s - obj_instance_id: 0x%X" % (dll_name, id(api_name)), verbose=True)
                pass

            # upload to cloud
            k.update_load_dll_hks(k_load_dll_hks)
            return

    # dll not in list. create cbk_obj first, then add

    # xrklog.info("add new dll to cbk list: %s - obj_instance_id: %d" % (dll_name, id(api_name)), verbose=True)

    cbk_obj = xrkdef.loadDllCbkStruct(dll_name.lower())
    cbk_obj.add_cbk(api_name, cbk_proxy)
    k_load_dll_hks.append(cbk_obj)

    # upload to cloud
    k.update_load_dll_hks(k_load_dll_hks)


def load_dll_cbks_remove_apis(api_names):
    """
        remove api cbks from load_dll_hks(indirectly)
        proxy to load_dll_cbks_remove_apis_x

        @param: api_names : LIST : a list of api names
    """
    load_dll_cbks_remove_apis_x(xrkmonapis.get_dll_api_dict_by_api_names(api_names))


def load_dll_cbks_remove_apis_x(pairs):
    """
        remove api cbks from load_dll_hks

        @param: pairs : DICT : dict, like this: {dll_name: {api_name, api_name, ...},
                                                 dll_name: {api_name, api_name, ...},
                                                 ...}
    """
    k = get_cloud_monCtrl()
    k_load_dll_hks = k.get_load_dll_hks()

    is_changed = False
    for (dll_name, api_names) in pairs:

        for load_dll_hk in k_load_dll_hks:

            # load_dll_hk: xrkdef.loadDllCbkStruct
            if load_dll_hk.dll_name.lower() == dll_name.lower():

                # remove
                load_dll_hk.remove_cbks(api_names)

                if not load_dll_hk.check_has_cbk():
                    k_load_dll_hks.remove(load_dll_hk)

                # set flag
                is_changed = True

    # update to cloud
    if is_changed:
        k.update_load_dll_hks(k_load_dll_hks)


def load_dll_hks_remove_dlls(dll_names):
    """
        remove dll cbks from load_dll_hks

        @param: dll_names : LIST : a list of dll names
    """
    k = get_cloud_monCtrl()
    k_load_dll_hks = k.get_load_dll_hks()

    is_changed = False
    for dll_name in dll_names:

        for load_dll_hk in k_load_dll_hks:

            # load_dll_hk: xrkdef.loadDllCbkStruct
            if load_dll_hk.dll_name.lower() == dll_name.lower():

                # remove
                k_load_dll_hks.remove(load_dll_hk)
                xrklog.info("remove dll from list: %s" % (dll_name), verbose=True)

                # set flag
                is_changed = True

    # update to cloud
    if is_changed:
        k.update_load_dll_hks(k_load_dll_hks)


def load_dll_hks_remove_all():
    """
        remove all dlls, just provide an empty list.
    """
    get_cloud_monCtrl().dft_load_dll_hks()


# ---------------------------------------------------------------------------
# load dll hks : other
# ---------------------------------------------------------------------------


def cbk_new_dll_load_miscCtrl(evt, image_name, image_path):
    pass


# ---------------------------------------------------------------------------
# coding interface
# ---------------------------------------------------------------------------


#
# structure of api_run_replace:
#       {api_name: cbk_run_obj,
#        api_name: cbk_run_obj, ...}
#
v_id_api_run_replace = "id_api_run_replace"


def gua_install_api_hook_replace(api_name, cbk_obj):
    """
        guarantee cbk_obj is invoked when api hit, instead of pre-defined run_cbk

        @param: api_name : STRING : api name
        @param: ckb_obj  : obj    : obj of xekdef.cbkStructRun
    """
    k = xrkcloud.cloud_get(v_id_api_run_replace, default={})
    k[api_name] = cbk_obj
    xrkcloud.cloud_set(v_id_api_run_replace, k)


def gua_install_api_hook_replace_x(api_name, run_cbk, param1=None, param2=None, param3=None, param4=None):
    """
        guarantee run_cbk is invoked when api hit, instead of pre-defined run_cbk.

        @param: api_name          : STRING : api name
        @param: run_cbk           : method : to invoke when api hit
        @param: param1/.../param4 : ...    : params pass to run_cbk when api hit

        create xekdef.cbkStructRun then proxy to gua_install_api_hook_replace()
    """
    gua_install_api_hook_replace(xrkdef.cbkStructRun(run_cbk, param1=param1, param2=param2, param3=param3, param4=param4))

#
# structure of api_run_append:
#       {api_name: {id_: cbk_run_obj, id_: cbk_run_obj, ...},
#        api_name: {id_: cbk_run_obj, id_: cbk_run_obj, ...},
#        ...}
#
v_id_api_run_append = "id_api_run_append"


def gua_install_api_hook_append(api_name, id_, cbk_obj):
    """
        pass
    """
    pass


def gua_install_api_hook_append_x(api_name, id_, run_cbk, param1=None, param2=None, param3=None, param4=None):
    """
        pass
    """
    pass


def gua_install_api_log_hook(api_name, info=None):
    """
        guarantee log api name and info when api hit

        @param: api_name : STRING : api name
        @param: info     : STRING
                           None
    """
    pass


def fake_main_md_name(fake_name):
    """
        fake main pe name, by modifying ret of GetModuleFileNameW

        @param: fake_name: STRING: new md name u wanna fake.
                                   this shall be exactily the same with the one latter passed to __strcmp()

        !+ we don't use xrkmon.exec_cmd_str() here, because fake_name may contains space char, which is very bad...
    """
    get_api_hooks_manager().add_apis(["GetModuleFileNameW"])
    k = get_cloud_monCtrl()
    k_api_config = k.get_api_config()
    k_api_config["GetModuleFileNameW"]["fake_md_name"] = fake_name
    k.update()


def get_work_dir():
    """
        get work dir from cloud

        @return: STRING
    """
    return get_cloud_monCtrl().get_global_cfgs()["work_dir"]


def install_addr_hook(addr, id_, cbk_obj, shall_pause=False):
    """
        install or update hook at addr

        @param: addr        : INT    : address to install hook
        @param: id_         : STRING : hook desc
        @param: cbk_obj     : obj    : obj of xrkdef.cbkStructRun
        @param: shall_pause : BOOL   : shall pause or not when hook hit

        @raise: Exception
    """
    if not xrkutil.validate_addr(addr):
        raise Exception("invalid address")

    if id_ in xrkdbg.listHooks():

        # remove old hook
        debugger.remove_hook(id_)

        # we don't know whether del bp or not, so we leave it alone

    h = xrkhook.pausableInvokeRunCbkHook(cbk_obj)
    h.add(id_, addr, shall_pause=shall_pause)


def install_addr_hook_ex(addr, id_, run_cbk, shall_pause=False, param1=None, param2=None, param3=None, param4=None):
    """
        install hook at addr, by porxy to: install_addr_hook

        @param: addr              : INT    : address to install hook
        @param: id_               : STRING : hook desc
        @param: run_cbk           : method : prototype: run_xx(regs, param1=None, param2=None, param3=None, param4=None)
        @param: shall_pause       : BOOL   : shall pause or not when hook hit
        @param: param1/.../param4 : ...    : params pass to run_cbk when api hit

        @raise: Exception
    """
    install_addr_hook(addr, id_, xrkdef.cbkStructRun(run_cbk, param1=param1, param2=param2, param3=param3, param4=param4), shall_pause=shall_pause)


def install_log_func_called_hooks_for_dll_exports(dll_name):
    """
        install logCommentHook for all dll exports

        @param: dll_name : STRING : dll name
        !+ dll shall be loaded already
    """
    # mn_mod = xrkmona.MnModule(dll_name)
    mn_mod = None
    assert mn_mod is not None
    eat = mn_mod.getEAT()
    h = xrkhook.logCommentHook()
    xrklog.info("setting func called hook on dll exports: %s, start" % dll_name, verbose=True)
    eop = mn_mod.moduleEntry
    xrklog.info("setting func called hook at: %s-%s" % (eop, "entry point"), verbose=True)
    xrkdbg.setComment(eop, "entry point")
    h.add("entry point", eop)
    lines = []
    for e in eat:
        comment = eat[e]
        xrkdbg.setComment(e, comment)
        h.add(comment, e)
        lines.append("setting func call hook at: 0x%X-%s" % (e, comment))
    xrklog.infos(lines, verbose=True)


def install_log_func_called_hooks_at_addrs(addrs):
    """
        install logCommentHook for each of these addrs

        @param: addrs : LIST : a list of address

        !+ addr shall be valid
    """
    lines = []
    h = xrkhook.logCommentHook()

    lines.append("setting func called hook on addrs: ")

    for i in addrs:

        comment = i.comment
        xrkdbg.setComment(i.addr, comment)

        h.add(comment, i.addr)

        lines.append("setting func called hook at: 0x%X-%s" % (i.addr, comment))

    lines.append("setting func called hook on addrs: ")
    for i in addrs:
        comment = i.comment
        xrkdbg.setComment(i.addr, comment)
        h.add(comment, i.addr)
        lines.append("setting func called hook at: 0x%X-%s" % (i.addr, comment))

    xrklog.infos(lines, verbose=True)


def install_api_called_hook(info):
    """
        install logCommentHook by the STRING, which can get addrs

        @param: info : STRING :
    """
    addr = xrkdbg.getAddress(info)
    if addr != 0:

        xrkdbg.setComment(addr, info)

        h = xrkhook.logCommentHook()
        h.add(info, addr)

        xrklog.info("setting func called hook: 0x%X-%s" % (addr, info))

    addr = xrkdbg.getAddress(info)
    if addr != 0:
        xrkdbg.setComment(addr, info)
        h = xrkhook.logCommentHook()
        h.add(info, addr)
        xrklog.info("setting func called hook: 0x%X-%s" % (addr, info))
    else:
        xrklog.error("setting func called hook, invalid name to get any addrs: %s" % info)


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
