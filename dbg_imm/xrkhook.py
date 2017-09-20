# -*- coding: utf-8 -*-

"""
    xrkhook
"""

import os
import sys
import pickle
import inspect
import debugger
import traceback
from immlib import Hook
from immlib import BpFlags
from immlib import LogBpHook
from immlib import LoadDLLHook
# from immlib import UnloadDLLHook
from immlib import AllExceptHook
from libhook import HookTypes


try:
    import xrkdef
    import xrklog
    import xrkdbg
    import xrkutil
    import xrkcloud
    # import xrkmona
except:
    this_path = os.path.split(os.path.realpath(inspect.stack()[-1][1]))[0]
    sys.path.append(this_path)
    try:
        import xrkdef
        import xrklog
        import xrkdbg
        import xrkutil
        import xrkcloud
        # import xrkmona
    except Exception, e:
        import immlib as dbglib
        dbg = dbglib.Debugger()
        dbg.log("xrkhook import error: %s" % e, highlight=1)
        error = traceback.format_exc()
        while len(error) > 200:
            tmp = error[:200]
            dbg.log("  %s" % tmp, highlight=1)
            error = error[200:]
        dbg.log("  %s" % error, highlight=1)

        assert False

# ---------------------------------------------------------------------------
# pausable hook
# ---------------------------------------------------------------------------


class PausableHook(Hook):
    # ---------------------------------------------------------------------------
    # Hook with pause/unpause. functionality
    # ---------------------------------------------------------------------------
    def __init__(self):
        Hook.__init__(self)
        self.desc = ""
        self.address = 0
        self.force = 0
        self.timeout = 0
        self.mode = 0

        self.shall_pause = False

    def add(self, desc, addr, shall_pause=False):
        """
            add hook at specified address

            @param: desc        : STRING : hook key
            @param: addr        : INT    : address
            @param: shall_pause : BOOL   : shall pause when hit

            1. add breakpoint/logging breakpoint, depending on shall_pause
            2. set self.type, add install hook

            !+ whether pause or not, depend on the bp type. not self.type(HookTypes)
        """
        # first, try to remove old one, though new one will replace old one
        # debugger.remove_hook(desc)

        self.desc = desc
        self.address = addr
        self.shall_pause = shall_pause

        xrkutil.may_update_comment(addr, desc)

        if shall_pause:
            self.type = HookTypes["ORDINARY_BP_HOOK"]
            debugger.set_breakpoint(self.address, BpFlags["TY_ACTIVE"], "")
        else:
            self.type = HookTypes["LOG_BP_HOOK"]
            debugger.set_logging_breakpoint(self.address)

        pickled_object = pickle.dumps(self)
        return debugger.add_hook(pickled_object, self.desc, self.type, self.address, self.force, self.timeout, self.mode)

    def remove(self):
        """
            remove bp and hook

            1. remove breakpoint
            2. remove hook
        """
        debugger.delete_breakpoints(self.address, 0)
        debugger.remove_hook(self.desc)

    def set_pause(self):
        """
            if hook is not pause mode, convert to pause mode.

            1. remove old breakpoint.
            2. remove old hook
            3. set new breakpoint
            4. add new hook
        """
        if self.shall_pause:
            xrklog.warn("hook is pause mode, do not convert: %s" % self.desc)

        else:
            self.shall_pause = True

            debugger.delete_breakpoints(self.address, 0)
            debugger.remove_hook(self.desc)

            debugger.set_breakpoint(self.address, BpFlags["TY_ACTIVE"], "")
            self.type = HookTypes["ORDINARY_BP_HOOK"]
            pickled_object = pickle.dumps(self)
            debugger.add_hook(pickled_object, self.desc, self.type, self.address, self.force, self.timeout, self.mode)

    def set_un_pause(self):
        """
            if hook is pause mode, convert to un pause mode

            1. remove old breakpoint.
            2. remove old hook
            3. set new logging breakpoint
            4. add new hook
        """
        if not self.shall_pause:
            xrklog.warn("hook is un pause mode, do not convert: %s" % self.desc)

        else:
            self.shall_pause = False

            debugger.delete_breakpoints(self.address, 0)
            debugger.remove_hook(self.desc)

            debugger.set_logging_breakpoint(self.address)
            self.type = HookTypes["LOG_BP_HOOK"]
            pickled_object = pickle.dumps(self)
            debugger.add_hook(pickled_object, self.desc, self.type, self.address, self.force, self.timeout, self.mode)


class pausableInvokeCbkHook(PausableHook):
    def __init__(self, cbk_struct):
        """
            @param: cbk_struct : obj : a obj of cbkStruct
        """
        PausableHook.__init__(self)
        self.cbk_struct = cbk_struct

    def run(self, regs):
        """
            invoke cbk run

            @param: regs : DICT : reg dict
        """
        self.cbk_struct.invoke(regs=regs)


class pausableInvokeRunCbkHook(PausableHook):
    def __init__(self, cbk_struct_run):
        """
            @param: cbk_struct_run : obj : a obj of xrkdef.cbkStructRun
        """
        PausableHook.__init__(self)
        self.cbk_struct_run = cbk_struct_run

    def run(self, regs):
        """
            invoke cbk run

            @param: regs : DICT : reg dict
        """
        self.cbk_struct_run.invoke(regs=regs)


def install_pausable_hook(desc, addr, run_cbk, shall_pause=False):
    """
        install pausable hook

        @param: desc        : STRING : as hook desc(id_)
        @param: addr        : INT    : address
        @param: run_cbk     : method : reg cbk
        @param: shall_pause : BOOL   : shall pause or not when api hit
    """
    if desc not in xrkdbg.listHooks():

        xrkutil.may_update_comment(addr, desc)

        # install hook
        h = pausableInvokeRunCbkHook(xrkdef.cbkStructRun(run_cbk))
        h.add(desc, addr, shall_pause=shall_pause)

    else:
        # hook already installed, re-set bp
        if shall_pause:
            xrkdbg.setBreakpoint(addr)
        else:
            xrkdbg.setLoggingBreakpoint(addr)


# ---------------------------------------------------------------------------
# log comment hook
# ---------------------------------------------------------------------------


class logCommentHook(LogBpHook):
    # ---------------------------------------------------------------------------
    # log function address comment when invoked
    # ---------------------------------------------------------------------------
    def __init__(self):
        LogBpHook.__init__(self)

    def run(args, regs):
        """
            @param: regs : DICT :
        """
        comment = xrkdbg.getComment(regs["EIP"])
        if comment == "":
            xrklog.info("func called: 0x%X(no comment set)" % (regs["EIP"]))
        else:
            xrklog.info("func called: %s" % comment)


# ---------------------------------------------------------------------------
# dll load cbks
# ---------------------------------------------------------------------------


class dllOepCallCbkHook(LogBpHook):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, dll_name, dll_base, cbk_list):
        """
            @param: dll_name : STRING : dll name
            @param: dll_base : INT    : dll base
            @param: cbk_list : LIST   : a list of obj cbkStruct
        """
        LogBpHook.__init__(self)
        self.dll_name = dll_name
        self.dll_base = dll_base
        self.cbk_list = cbk_list

    def run(self, regs):
        """
            this hook is one shot
        """
        if xrkdbg.isAnalysed(self.dll_base):
            if not xrkdbg.analyseCode(self.dll_base):
                xrklog.highlight("analyze dll %s (base: %X) fail, install hook may fail..." % (self.dll_name, self.dll_base))
        xrklog.info("oep of dll: %s, call cbk list" % self.dll_name, verbose=True)
        for cbk in self.cbk_list:
            cbk.invoke()
        # ? if UnHook here, later oep hooks will be invalid?
        LogBpHook.UnHook(self)


def get_image_path_by_load_dll_evt(evt):
    """
        !+ we access this method from run_cbk, so can't be private

        @return: STRING: image full path
    """
    assert evt.isLoadDll()
    image_path = ""
    if evt.fUnicode:
        image_path = xrkutil.dbg_read_pwstring(evt.lpImageName, default=None)
    else:
        image_path = xrkutil.dbg_read_pstring(evt.lpImageName, default=None)
    return image_path.lower()


def get_image_name_by_load_dll_evt(evt):
    """
        !+ we access this method from run_cbk, so can't be private

        @return: STRING: image name, no path, only name.
    """
    image_path = get_image_path_by_load_dll_evt(evt)
    assert image_path is not None and len(image_path) != 0
    return os.path.basename(image_path).lower()


class retLibraryExWHook(LogBpHook):
    # ---------------------------------------------------------------------------
    # at load lib return, invoke install api hook cbks
    # !+ TODO: sometimes, new dll loading process does not invoke LoadLibraryExW
    # ---------------------------------------------------------------------------
    def __init__(self, cbk_run):
        """
            @param: cbk_run: obj of crkStructRun
        """
        LogBpHook.__init__(self)
        self.cbk_run = cbk_run

    def run(self, regs):
        """
            invoke cbk
        """
        self.cbk_run.invoke(regs)


class retLdrLoadDllHook(LogBpHook):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, cbk_run):
        """
            @param: cbk_run: obj of crkStructRun
        """
        LogBpHook.__init__(self)
        self.cbk_run = cbk_run

    def run(self, regs):
        """
            invoke cbk
        """
        self.cbk_run.invoke(regs)


class allExceptionHook(AllExceptHook):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, cbk_run):
        """
            @param: cbk_run: obj of crkStructRun
        """
        AllExceptHook.__init__(self)
        self.cbk_run = cbk_run

    def run(self, regs):
        """
            invoke cbk
        """
        self.cbk_run.invoke(regs)


def install_all_exception_hook(desc, run_cbk):
    """
        install all exception hook

        @param: run_cbk: method with param (regs)
    """
    if desc not in xrkdbg.listHooks():
        h = allExceptionHook(xrkdef.cbkStructRun(run_cbk))
        h.add(desc)
        xrklog.info("installed all exception hook: %s" % desc, verbose=True)


# -------------------------------------------------------------------------
# HOOK INSTALL
# -------------------------------------------------------------------------


def __install_hook(addr, hook_class, comment, param1=None, param2=None, param3=None, param4=None):
    """
        install hook at specified addr

        !+ will update comment if no comment at this addr
    """
    if xrkutil.validate_addr(addr):
        xrkutil.may_update_comment(addr, comment)
        if param1 is None:
            h = hook_class()
            h.add(comment, addr)

        elif param2 is None:
            h = hook_class(param1)
            h.add(comment, addr)

        elif param3 is None:
            h = hook_class(param1, param2)
            h.add(comment, addr)

        elif param4 is None:
            h = hook_class(param1, param2, param3)
            h.add(comment, addr)

        else:
            h = hook_class(param1, param2, param3, param4)
            h.add(comment, addr)

        xrklog.info("install mm hook by rva, comment: %s, addr: 0x%X" % (comment, addr), verbose=True)

    else:
        xrklog.error("install mm hook, but addr invalid. comment: %s, addr: 0x%X" % (comment, addr), verbose=True)


def install_custom_hook(addr, hook_class, comment, param1=None, param2=None, param3=None, param4=None):
    """
        simplify install hook procudure
    """
    __install_hook(addr, hook_class, comment, param1, param2, param3, param4)


def install_hook_for_mm_by_rva(mm_base, rva, hook_class, comment):
    """
        set hook on mm page by rva
    """
    __install_hook(mm_base + rva, hook_class, comment)


def install_hooks_for_mm_by_rva(mm_base, hooks):
    """
        install hooks on mm page by rva
    """
    assert len(hooks) != 0
    for hk in hooks:
        __install_hook(mm_base + hk["rva"], hk["hook_class"], hk["comment"])


def install_hook_for_dll_by_rva(dll_name, rva, hook_class, comment):
    assert xrkutil.check_has_module(dll_name)
    # mn_mod = xrkmona.MnModule(dll_name)
    mn_mod = None
    assert mn_mod is not None
    install_hook_for_mm_by_rva(mn_mod.moduleBase, rva, hook_class, comment)


def install_hooks_for_dll_by_rva(dll_name, hooks):
    """
        install hooks on dll by rva
    """
    assert xrkutil.check_has_module(dll_name)
    # mn_mod = xrkmona.MnModule(dll_name)
    mn_mod = None
    assert mn_mod is not None
    install_hooks_for_mm_by_rva(mn_mod.moduleBase, hooks)


def install_hooks_for_dll_on_exports(dll_name, hook_class):
    """
        install hooks for dll on exports

        collect dll eat info, construct hooks, call other functions
    """
    assert xrkutil.check_has_module(dll_name)
    # mn_mod = xrkmona.MnModule(dll_name)
    mn_mod = None
    assert mn_mod is not None

    __install_hook(mn_mod.moduleEntry, logCommentHook, "%s entry point" % dll_name)

    eat = mn_mod.getEAT()
    for e in eat:
        __install_hook(e, logCommentHook, "%s -- %s" % (dll_name, eat[e]))


def install_api_hook_simple(name, hook_class, param1=None, param2=None, param3=None, param4=None):
    """
        get addr by name, add hook for c
    """
    addr = xrkdbg.getAddress(name)
    assert addr != 0
    __install_hook(addr, hook_class, comment=name, param1=param1, param2=param2, param3=param3, param4=param4)


# ---------------------------------------------------------------------------
# debugee modify hook
# ---------------------------------------------------------------------------


class debugeeModifyHook(LogBpHook):
    # ---------------------------------------------------------------------------
    # invoke modify when hook hit
    # ---------------------------------------------------------------------------
    def __init__(self, modify, comment, is_one_shot=False, stop_when_fail=False):
        """
            @param: modify: a debugeeModifies obj
        """
        LogBpHook.__init__(self)
        self.modify = modify
        self.comment = comment
        self.is_one_shot = is_one_shot
        self.stop_when_fail = stop_when_fail

    def run(self, regs):
        """
            run cbk
        """
        if not self.modify.invoke(regs=regs, stop_when_fail=self.stop_when_fail):
            xrklog.error("modify invoke failed..")
        if self.is_one_shot:
            self.UnHook()


def install_hook_to_modify_addr(addr, tar_addr, value, comment, is_one_shot=False, stop_when_fail=False, off_1=None, off_2=None, off_3=None, off_4=None):
    """
        @param: addr: shall be valid

        @return: STRING: desc, work like handle to remove hook
    """
    if xrkutil.validate_addr(addr):
        modify = xrkdef.debugeeModifies(xrkdef.vSetterDirect(tar_addr, value, off_1=off_1, off_2=off_2, off_3=off_3, off_4=off_4))
        id_ = xrkutil.time_str()
        h = debugeeModifyHook(modify, comment, is_one_shot, stop_when_fail)
        h.add(id_, addr)
        xrkutil.may_update_comment(addr, comment)
        return id_
    else:
        xrklog.error("installed modify addr hook: invalid addr: 0x%X - %s" % (addr, comment))
        return None


def install_hook_to_modify_reg(addr, reg, value, comment, is_one_shot=False, stop_when_fail=False, off_1=None, off_2=None, off_3=None, off_4=None):
    """
        @param: addr: shall be valid

        @return: STRING: desc, work like handle to remove hook
    """
    if xrkutil.validate_addr(addr):
        modify = xrkdef.debugeeModifies(xrkdef.vSetterReg(reg, value, off_1=off_1, off_2=off_2, off_3=off_3, off_4=off_4))
        id_ = xrkutil.time_str()
        h = debugeeModifyHook(modify, comment, is_one_shot, stop_when_fail)
        h.add(id_, addr)
        xrkutil.may_update_comment(addr, comment)
        return id_
    else:
        xrklog.error("installed modify reg hook: invalid addr: 0x%X - %s" % (addr, comment))
        return None


def install_hook_to_modify_reg_only(addr, reg_name, value, comment, is_one_shot=False, stop_when_fail=False):
    """
        @param: addr: shall be valid

        @return: STRING: desc, work like handle, to remove hook.
    """
    if xrkutil.validate_addr(addr):
        modify = xrkdef.debugeeModifies(xrkdef.vSetterRegOnly(reg_name, value))
        id_ = xrkutil.time_str()
        h = debugeeModifyHook(modify, comment, is_one_shot, stop_when_fail)
        h.add(id_, addr)
        xrkutil.may_update_comment(addr, comment)
        return id_
    else:
        xrklog.error("installed modify reg only hook: invalid addr: 0x%X - %s" % (addr, comment))
        return None


def install_hook_to_modify_stack(addr, stack_offset, value, comment, is_one_shot=False, stop_when_fail=False, off_1=None, off_2=None, off_3=None, off_4=None):
    """
        @param: addr: shall be valid

        @return: STRING: desc, work like handle to remove hook
    """
    if xrkutil.validate_addr(addr):
        modify = xrkdef.debugeeModifies(xrkdef.vSetterStack(stack_offset, value, off_1=off_1, off_2=off_2, off_3=off_3, off_4=off_4))
        id_ = xrkutil.time_str()
        h = debugeeModifyHook(modify, comment, is_one_shot, stop_when_fail)
        h.add(id_, addr)
        xrkutil.may_update_comment(addr, comment)
        return id_
    else:
        xrklog.error("installed modify stack hook: invalid addr: 0x%X - %s" % (addr, comment))
        return None


# -------------------------------------------------------------------------
# LOAD DLL THING
# -------------------------------------------------------------------------

#
# to gua that dll will be invoked right after module is loaded, we tried these methods:
#
#       1. LoadDllHook. we get newly loaded module base and name, but...
#           a. module is not analized(and xrkdbg.analyseCode() fails), meaning xrkdbg.getAddress() will fail. so, negative
#           b. set oep hook at oep of module, but this hook may function or not randomly(i don't know why). so, negative
#
#       2. at RETN of LoadLibraryExW. but some modules are loaded not by this way. so, negative
#
#       3. AllExceptHook. at each exception, we check if still has pending cbks. but...
#           a. still the same problem. for eaxmple:
#               WININET.DLL is just loaded, but we can't install WININET api hooks because it's not in module list, then, no other exception occured even if InternetOpenA is invoked.
#
#       4. PostAnalysisHook. doesn't work
#
# from above, we know that:
#       at each load dll event, new dll is not analized nor updated to module list. that will happen only after event is finished.
#
# and finally:
#       we take option 1: LoadDllHook
#       when run_LoadDLLHook invoke, we parse new dll exports using pefile.py, and set bp according to export rvas.
#

v_id_load_dll_cbks = "id_load_dll_cbks"


class loadDllCallCbksHook(LoadDLLHook):
    # ---------------------------------------------------------------------------
    # invoke cbks for dll if dll is newly loaded
    # ---------------------------------------------------------------------------
    def __init__(self, cbk_run):
        """
            @param: cbk_run: obj of crkStructRun
        """
        LoadDLLHook.__init__(self)
        self.cbk_run = cbk_run

    def run(self, regs):
        """
            invoke cbk
        """
        self.cbk_run.invoke(regs)


def run_LoadDLLHook(regs):
    """
        get name of loaded dll, invoke cloud cbks

        @param: regs: DICT: registery dict
        @raise: Exception
    """
    evt = xrkdbg.getEvent()
    if evt.isLoadDll():

        """
        field of LoadDLLEvent:
            self.hFile                 = event[1][0]
            self.lpBaseOfDll           = event[1][1]
            self.dwDebugInfoFileOffset = event[1][2]
            self.nDebugInfoSize        = event[1][3]
            self.lpImageName           = event[1][4] ==> this is a pointer. name is full path
            self.fUnicode              = event[1][5]
        """
        image_name = get_image_name_by_load_dll_evt(evt)
        image_path = get_image_path_by_load_dll_evt(evt)

        if not os.path.exists(image_path):
            xrklog.error("load dll, invalid image path: %s" % image_path)
            return

        k = xrkcloud.cloud_get(v_id_load_dll_cbks)

        # this hook is not necessary anymore, remove it
        if k is None or len(k) == 0:
            gua_remove_load_dll_hook()
            return

        # invoke registered cbks
        for (d, x) in k.items():
            x.invoke(evt, image_name, image_path)

    else:
        raise Exception("run_cbk of LoadDLLHook, but evt is not LoadDll. evt code: %s" % evt.dwDebugEventCode)


def gua_remove_load_dll_hook():
    """
        remove loadDllCallCbksHook if it is installed
    """
    if "my_load_dll_hook" in xrkdbg.listHooks():
        debugger.remove_hook("my_load_dll_hook")


def this_gua_load_dll_hook_installed():
    """
        shall only be available for this file,
        but will be called from hook, so can't be private
    """
    if "my_load_dll_hook" not in xrkdbg.listHooks():

        h = loadDllCallCbksHook(xrkdef.cbkStructRun(run_LoadDLLHook))
        h.add("my_load_dll_hook")

        xrklog.high("installed load dll hook: my_load_dll_hook")


def register_load_dll_cbk(id_, cbk, force_update=False):
    """
        register load dll cbk

        @param: id_: STRING: working as key of cloud dict: load_dll_cbks
        @param: cbk: method with prototype: cbk_xx(evt, image_name, image_path)
        @param: force_update: BOOL: whether force update cloud if cbk with same id_ already exists
    """
    this_gua_load_dll_hook_installed()

    k = xrkcloud.cloud_get(v_id_load_dll_cbks, default={})
    if id_ not in k or force_update:

        k[id_] = xrkdef.cbkStructDllLoaded(cbk)
        xrkcloud.cloud_set(v_id_load_dll_cbks, k)

    else:
        # ignore
        pass


def unregister_load_dll_cbk(id_):
    """
        unregister load dll cbk

        @param: id_: STRING: work as key of cloud dict
    """
    k = xrkcloud.cloud_get(v_id_load_dll_cbks, default={})
    if id_ in k:
        del k[id_]
        xrkcloud.cloud_set(v_id_load_dll_cbks, k)


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
