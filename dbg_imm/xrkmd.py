# -*- coding: utf-8 -*-

"""
md may represents:
    1. a pe(dll/exe)
    2. a memory pe(with or without pe header ect)
    3. a memory pe containing shellcode
things we do to generate valid md:
    1. set a hook, to set base of md.
       hook can set at a solid addrss(it's base never changes), or at the offset of another md(it's base changes)
    2.
things we can do to valid md(all by offset):
    1. set comment/bp
    2. install hook
    3. add sub_md
    !+ the advantage of md is: when it's base changes(rebase), all comment/bp/hook/sub_pe will be updated accordingly.


i might use it this way(in x.py):
    md = xrkmd.get_md_root("md_root", 0x400000, "client create md root", xrkdef.vGetterReg("EAX")) # get md from k, retn is a local one
    md.reset() # call this if u wanna a new md
    md.bp_add(0x123, "for xx")
    md.bp_add(0x124, "for yy")
    md.bp_remove("for zz") # call this if u wanna remove prevous install bp(u didn't call md.reset() beforewards)
    md.hook_add(0x125, hook_run_xxx, "hook_desc_xxx")
    md.hook_add(0x126, hook_run_yyy, "hook_desc_yyy")
    xrkmd.update_md_root("md_root", md)

when sub_md involved(in x.py):
    # sub_mds can only be added by code
    # hooks can only be added by code
    md = ...
    md.xx()/...
    md_1 = md.sub_md_add("md_1", 0x123, "md root create md 1", xrkdef.vGetterReg("EAX"))
    md_1.xx()/...
    md_2 = md_1.sub_md_add("md_2", 0x345, "md 1 create md 2", xrkdef.vGetterReg("EAX"))
    md_2.xx()/xxx
    xrkmd.update_md_root("md_root", md)

when any md involved(in cmd line):
    !xrkmd --name md_root/md_1 -a rebase --addr 0x400000 # manual rebase, which shall be avoided
    !xrkmd --name md_root/md1 -a reset # reset everything
    !xrkmd --name md_root/all --tar bp/hook -a pt
    !xrkmd --name md_root/all --tar bp -a add --addr 0x123 --desc xxxx
    !xrkmd --name md_root/all --tar bp -a remove/enable/disable --desc xxxx # if no desc provided, apply to all
    !xrkmd --name md_root/all --tar hook -a remove/pause/unpause --desc xxxx # if no desc provided, apply to all
    !xrkmd --name md_root/all --tar bp/hook -a clear
"""

import os
import sys
import pickle
import inspect
import debugger
import traceback
import optparse as optlib
from immlib import BpFlags
from libhook import HookTypes

try:
    import xrklog
    import xrkdbg
    import xrkdef
    import xrkhook
    import xrkutil
    # import xrkgame
    import xrkcloud
    from immlib import BpHook
except:
    this_path = os.path.split(os.path.realpath(inspect.stack()[-1][1]))[0]
    sys.path.append(this_path)
    try:
        import xrklog
        import xrkdbg
        import xrkdef
        import xrkhook
        import xrkutil
        # import xrkgame
        import xrkcloud
        from immlib import BpHook
    except Exception, e:
        import immlib as dbglib
        dbg = dbglib.Debugger()
        dbg.log("xrkmd import error: %s" % e, highlight=1)
        error = traceback.format_exc()
        while len(error) > 200:
            tmp = error[:200]
            dbg.log("  %s" % tmp, highlight=1)
            error = error[200:]
        dbg.log("  %s" % error, highlight=1)

        assert False


# -------------------------------------------------------------------------
# cloud
# -------------------------------------------------------------------------

#
# structure of knowledge:
#     {"md_root_1": obj_xrkmdRoot_1,
#      "md_root_2": obj_xrkmdRoot_2}
#
# to get/set whichever md(root or sub), u do it through root md
#
v_id_xrkmd = "id_xrkmd"


def get_xrkmd_cloud():
    """
        get md from cloud.

        @return: DICT : a dict of xrkmdRoot

        !+ there are too many usages, so, we provide this method
    """
    return xrkcloud.cloud_get(v_id_xrkmd, default={})


def set_xrkmd_cloud(value):
    """
        get md to cloud

        @param: value : DICT : shall be a dict of xrkmdRoot

        !+ there are too many usages, so, we provide this method
    """
    xrkcloud.cloud_set(v_id_xrkmd, value)


def get_md_root(md_root_name, md_root_desc, md_root_rebase_addr, md_root_unload_addr, md_root_base_getter, md_root_size_getter):
    """
        get md_root by md_root_name.

        @param: md_root_name        : STRING : name of xrkmdRoot
        @param: md_root_desc        : STRING : desc of xrkmdRoot
        @param: md_root_rebase_addr : INT    : address, when hit, rebase xrkmdRoot
        @param: md_root_unload_addr : INT    : address, when hit, unload xrkmdRoot
        @param: md_root_base_getter : obj    : obj of xrkdef.vGetterXXX. used to get base of xrkmdRoot when md_root_base_addr hit
        @param: md_root_size_getter : obj    : obj of xrkdef.vGetterXXX. used to get size of xrkmdRoot when md_root_base_addr hit

        @return: obj : obj of xrkmdRoot

        1. md in cloud: get from cloud
        2. md not in cloud: create from params, store in cloud, then return it
    """
    k = get_xrkmd_cloud()
    assert k is not None

    if md_root_name not in k:
        k[md_root_name] = xrkmdRoot(md_root_name, md_root_desc, md_root_rebase_addr, md_root_unload_addr, md_root_base_getter, md_root_size_getter)
        set_xrkmd_cloud(k)

    return k[md_root_name]


def update_md_root(md_root_name, md_root_value):
    """
        update xrkmdRoot to cloud by name.

        @param: md_root_name  : STRING : name of xrkmdRoot
        @param: md_root_value : obj    : obj of xrkmdRoot, as new value

        !+ cloud must have been created, and required xrkmdRoot must exists in cloud
    """
    k = get_xrkmd_cloud()
    assert k is not None and md_root_name in k

    k[md_root_name] = md_root_value
    set_xrkmd_cloud(k)


def update_md(md):
    """
        udpate specified md in cloud

        @param: md : obj : obj of xrkmdBase(whether xrkmdRoot or xrkmdSub)

        !+ we access that md by name chains
    """
    md_name_chains = md.get_md_name_chains()
    if len(md_name_chains) == 1:

        # this is xrkmdRoot
        update_md_root(md_name_chains[0], md)

    else:
        k = get_xrkmd_cloud()
        if md_name_chains[0] in k:

            md_tmp = k[md_name_chains[0]]

            # md_name_chains has name of this md, but we need to update it's parent, not this md itself

            # get it's parent
            for i in range(len(md_name_chains)):
                if i == 0:
                    continue
                if i == len(md_name_chains) - 1:
                    # this md_tmp is what we need to update
                    break
                md_tmp = md_tmp.sub_md_get_only(md_name_chains[i])

            # update it's parent
            md_tmp.sub_md_update(md_name_chains[-1], md)

            # update to cloud
            set_xrkmd_cloud(k)

        else:
            xrklog.error("update md, invalid name chains: %s" % (md_name_chains), add_prefix=True)


def get_md_root_only(md_root_name):
    """
        get root xrkmd by md_root_name

        @return: obj of xrkmdRoot, or None
    """
    k = get_xrkmd_cloud()
    assert k is not None
    return md_root_name in k and k[md_root_name] or None


def get_md_sub_only(md_name_chains):
    """
        get sub xrkmd by name chains

        @param: md_name_chains: LIST: a list of strings(md_names)

        @return: obj of xrkmdSub, or None
    """
    assert md_name_chains is not None and len(md_name_chains) > 1
    md_root = get_md_root_only(md_name_chains[0])
    if md_root is not None:
        return md_root.sub_md_get_only_by_chains(md_name_chains[1:])
    return None


def get_md_by_name_chains(md_name_chains):
    """
        get root md or sub md by name chains

        @param: md_name_chains: LIST: a list of strings(md_names)
    """
    if len(md_name_chains) == 1:
        return get_md_root_only(md_name_chains[0])
    else:
        return get_md_sub_only(md_name_chains)


def get_md_all():
    """
        get all xrkmds

        @return: LIST: a list of xrkmdBase obj
    """
    ret = []
    k = get_xrkmd_cloud()
    for (d, x) in k.items():
        ret.append(x)
        ret = ret + x.sub_md_get_all()
    return ret


def pt_all_mds():
    """
        print all mds
    """
    k = get_xrkmd_cloud()
    if k is not None:
        lines = ["xrkmdRoot count: %s" % len(k)]
        for (md_root_name, md_root) in k.items():
            # TODO
            lines.append("xrkmdRoot: %s(%s)" % (md_root.name, md_root.desc))
            lines.append("        %.8X + %.8X = %.0X" % (md_root.base, md_root.size, md_root.end))
            lines.append("        bp: %d, hook: %d, sub_md: %d" % (len(md_root.bp_dict), len(md_root.hook_dict), len(md_root.sub_mds)))
        xrklog.infos_ex(lines)
    else:
        xrklog.info("no xrkmd available", add_prefix=True)


def clear_all_mds():
    """
        clear all mds

        1. require all mds to clean themselves
        2. clean up cloud
    """
    k = get_xrkmd_cloud()
    for (md_root_name, md_root) in k.items():
        md_root_name.clear_md_chains()
    set_xrkmd_cloud({})


# -------------------------------------------------------------------------
# proxy
# -------------------------------------------------------------------------

#
# !+ this is the method for all mds when "rebase_hook" is hit, so this is the perfect place to update rebased-md to cloud
# !+ except manual rebase from command line
#


def proxy_rebase_xrkmdRoot(md_root_name, regs):
    """
        rebase for root xrkmd

        @param: md_root_name: STRING, name of root xrkmd
    """
    k = get_xrkmd_cloud()
    k[md_root_name].rebase_from_proxy(regs)
    set_xrkmd_cloud(k)


def proxy_rebase_xrkmdSub(md_name_chains, regs):
    """
        rebase for sub xrkmd

        @param: md_name_chains: LIST, a list of xrkmd names, from root to root's child to child's child to ... to this sub xrkmd's name
    """
    sub_md = get_md_by_name_chains(md_name_chains)
    if sub_md is not None:
        sub_md.rebase_from_proxy(regs)
        update_md(sub_md)
    else:
        xrklog.error("proxy_rebase_xrkmdSub error, name chains: %s" % md_name_chains, add_prefix=True)


def proxy_unload_xrkmdRoot(md_root_name, regs):
    """
        unload for root xrkmd

        @param: md_root_name: STRING, name of root xrkmd
    """
    k = get_xrkmd_cloud()
    k[md_root_name].unload(regs)
    set_xrkmd_cloud(k)


def proxy_unload_xrkmdSub(md_name_chains, regs):
    """
        unload sub xrkmd
    """
    sub_md = get_md_by_name_chains(md_name_chains)
    if sub_md is not None:
        sub_md.unload(regs)
        update_md(sub_md)
    else:
        xrklog.error("proxy_unload_xrkmdSub error, name chains: %s" % md_name_chains, add_prefix=True)

# -------------------------------------------------------------------------
# model
# -------------------------------------------------------------------------

# TODO: sometimes, a page is one module, or one module in one page.
# TODO: give call stack a name
# TODO: extract some common interface for stack log and compariation
# TODO: when bp manually removed, but we still need hook to be active


class xrkmdBase:
    # ---------------------------------------------------------------------------
    # the only thing xrkmdBase different from xrkmdRoot and xrkmdSub, is it doesn't care about when and how the first "rebase_hook" is installed.
    # and how the first "rebase_hook" is installed, is the only difference between xrkmdRoot and xrkmdSub, which happens in their install_rebase_hook() method
    #     for xrkmdRoot, it's called in it's __init__() method
    #     for xrkmdSub, it's called when it's parent rebases, and by it's parent.
    # ---------------------------------------------------------------------------
    def __init__(self, name, desc, md_name_chains, base_getter, size_getter):
        """
            @param: name: STRING: work as id of xrkmdRoot. there can be many xrkmdRoots, we use name for recognication
            @param: desc: STRING: only for logging, not for hooking
            @param: md_name_chains: LIST: a list of xrkmd names, from root to parent md, including this one
            @param: base_getter:
                    a object of xrkdef.vGetterXXX, which require regs as param, because we don't know base_getter's class, so we provide it with regs for sure.
                    use each time when hook at addr is hit, to rebase
            @param: size_getter:
                    a object of xrkdef.vGetterXXX
                    use each time when hook at addr is hit, to get it's new size

            !+ base_getter and size_getter is invoked at the same time, when some addr/offset hook is hit.
        """
        self.name = name
        self.desc = desc
        self.md_name_chains = md_name_chains
        self.base_getter = base_getter
        self.size_getter = size_getter
        self.base = 0
        self.size = 0
        self.end = 0

        # {"feat_1": (0x123, "00 01 02", ["00 01 02"]), "feat_2": (None, "00 ? 0B", ["00", 1, "0B"])}
        self.feat_dict = {}

        # {"bp_1": (0x123, True), "bp_2": (0x234, False)}
        self.bp_dict = {}
        # ---------------------------------------------------------------------------
        # {"feat_1": True, "feat_2": False}
        # True/False, means whether bp is enabled
        # ---------------------------------------------------------------------------
        self.bp_pending_dict = {}

        # {"hook_1": (0x123, cbk_run_obj_1, hk_obj_1), "hook_2": (0x234, cbk_run_obj_2, hk_obj_2)}
        self.hook_dict = {}
        # {"feat_1": (cbk_run_obj_1, True), "feat_2": (cbk_run_obj_2, False)}
        # True/False, means whether hook shall pause when hook hit
        self.hook_pending_dict = {}

        # {"md_1": obj_xrkmdSub_1, "md_2": obj_xrkmdSub_2}
        # !+ rebase/unload offset might not set. when parent rebase, check self.sub_mds_pending_dict --> calc feat --> set rebase/unload offset --> install rebase/unload hook
        self.sub_mds_dict = {}
        # {"pending_md_1": (rebase_feat_md_1, unload_feat_md_1), "pending_md_2": (rebase_feat_md_2, unload_feat_2)}
        self.sub_mds_pending_dict = {}

        self.sym_file_path = None
        # [(off_start_1, off_end_1, func_name_1), (off_start_2, off_end_2, func_name_2), ...]
        self.sym_list = []

    def install_rebase_hook(self):
        """
            this shall be overwritten by xrkmdRoot and xrkmdSub
        """
        assert False

    def install_unload_hook(self):
        """
            this shall be overwritten by xrkmdRoot and xrkmdSub
        """
        assert False

    # ---------------------------------------------------------------------------
    # rebase/re-apply
    # ---------------------------------------------------------------------------

    def rebase_from_proxy(self, regs):
        """
            hook at self.rebase_addr is hit, called from proxy_xrkmd_rebase()
        """
        self.rebase(self.base_getter.get(regs=regs), self.size_getter.get(regs=regs))

    def rebase(self, new_base, new_size):
        """
            1. if new base invalid: unload, return
            2. if new base valid:
                2.1 if base not changed, re-apply everything
                2.2 if base changed:
                    a. calc self.feat_dict
                    b. update self.bp_dict
                    c. update self.bp_pending_dict
                    d. update self.hook_dict
                    e. update self.sub_mds_dict
        """
        if not xrkutil.validate_addr(new_base):
            self.unload()
            return

        if new_base != self.base:
            assert xrkutil.validate_addr(new_base)
            assert xrkutil.validate_addr(new_base + new_size - 1)
            old_base = self.base
            # update basic info
            self.base = new_base
            self.size = new_size
            self.end = new_base + new_size

            xrklog.high("rebase md %s, new base: %.8X. feat-bp-pendingbp-hook-sub_md: %d-%d-%d-%d-%d" %
                        (self.name, self.base, len(self.feat_dict), len(self.bp_dict), len(self.bp_pending_dict), len(self.hook_dict), len(self.sub_mds_dict)))

            self.__rebase_feat()
            self.__rebase_bp(old_base)
            self.__rebase_hook(old_base)
            self.__rebase_sub_mds(old_base)

        else:
            xrklog.high("xrkmd %s rebase hook is hit but base is not changed: %.8X" % (self.name, self.base), add_prefix=True)
            self.re_apply_settings()

    def unload(self, regs=None):
        """
            xrkmd is unloading, or apply invalid base

            !+ ignore self.bp_pending_dict, and self.sub_mds_dict
        """
        xrklog.high("unloading md %s(%s), bp-pendingbp-hook-sub_md: %d-%d-%d-%d" %
                    (self.name, self.desc, len(self.bp_dict), len(self.bp_pending_dict), len(self.hook_dict), len(self.sub_mds_dict)))

        self.bp_unload_all()
        self.hook_unload_all()

    def re_apply_settings(self):
        """
            re apply everything.

            !+ derived class also implement this, and call just this

            1. rebase/unload hook (child classes)
            2. self.bp_dict
            3. self.bp_pending_dict
            4. self.hook_dict
            5. self.sub_mds_dict
        """
        xrklog.high("xrkmd %s re-apply everything" % (self.name), add_prefix=True)

        self.__re_apply_bp()
        self.__re_apply_hook()
        self.__re_apply_sub_mds()

    # ---------------------------------------------------------------------------
    # md basic info
    # ---------------------------------------------------------------------------

    def get_md_base(self):
        return self.base

    def get_md_size(self):
        return self.size

    def get_md_end(self):
        return self.end

    def is_belong_to_md(self, addr):
        return self.base <= addr and addr <= self.end

    # ---------------------------------------------------------------------------
    # sub_md
    # ---------------------------------------------------------------------------

    def __rebase_sub_mds(self, old_base):
        """
            suck sub md when rebase

            !+ self.base has already been updated
        """
        if len(self.sub_mds_dict) != 0:
            xrklog.info("rebase md %s, sub mds count: %d" % (self.name, len(self.sub_mds_dict)), add_prefix=True)
            # {"md_1": obj_xrkmdSub_1, "md_2": obj_xrkmdSub_2}
            for (d, x) in self.sub_mds_dict.items():

                if not x.is_offset_set():

                    assert d in self.sub_mds_pending_dict
                    rebase_offset = self.feat_calc(self.sub_mds_pending_dict[d][0])
                    unload_offset = self.feat_calc(self.sub_mds_pending_dict[d][1])
                    assert rebase_offset is not None and unload_offset is not None

                    x.init_offset(rebase_offset, unload_offset)
                    del self.sub_mds_pending_dict[d]

                assert x.is_offset_set()
                x.install_rebase_hook(self.base)
                x.install_unload_hook(self.base)
                xrklog.info("rebase md %s, install rebase/unload hook for sub md %s" % (self.name, d), add_prefix=True)

    def __re_apply_sub_mds(self):
        """
            reapply sub mds when rebase
        """
        if len(self.sub_mds_dict) != 0:
            xrklog.info("re-apply md %s, sub mds count: %d" % (self.name, len(self.sub_mds_dict)), add_prefix=True)
            # re install rebase/unload hook for sub md:
            # {"md_1": obj_xrkmdSub_1, "md_2": obj_xrkmdSub_2}
            for (d, x) in self.sub_mds_dict.items():

                if not x.is_offset_set():

                    assert d in self.sub_mds_pending_dict
                    rebase_offset = self.feat_calc(self.sub_mds_pending_dict[d][0])
                    unload_offset = self.feat_calc(self.sub_mds_pending_dict[d][1])
                    assert rebase_offset is not None and unload_offset is not None

                    x.init_offset(rebase_offset, unload_offset)
                    del self.sub_mds_pending_dict[d]

                assert x.is_offset_set()
                x.install_rebase_hook(self.base)
                x.install_unload_hook(self.base)
                xrklog.info("re-apply md %s, install rebase/unload hook for sub md %s" % (self.name, d), add_prefix=True)

    def sub_md_get_only(self, sub_md_name):
        """
            get xrkmd sub, get only

            @return: obj of xrkmdSub
                     None
        """
        return sub_md_name in self.sub_mds_dict and self.sub_mds_dict[sub_md_name] or None

    def sub_md_get_only_by_chains(self, sub_md_name_chains):
        """
            get xrkmd sub, get only, by name chains

            @param: sub_md_name_chains: LIST: a list of strings
        """
        assert len(sub_md_name_chains) != 0
        sub_md = self.sub_md_get_only(sub_md_name_chains[0])
        sub_sub_md_name_chains = sub_md_name_chains[1:]
        if sub_sub_md_name_chains is None or len(sub_sub_md_name_chains) == 0:
            return sub_md
        elif sub_md is not None:
            return sub_md.sub_md_get_only_by_chains(sub_sub_md_name_chains)
        else:
            xrklog.error("get xrkmdSub fail from xrkmd: %s, sub names: %s" % (self.name, sub_md_name_chains))

    def sub_md_get(self, sub_md_name, sub_md_desc, sub_md_rebase_offset, sub_md_unload_offset, sub_md_base_getter, sub_md_size_getter):
        """
            get xrkmd sub

            @param: sub_md_name: STRING: name of xrkmdSub
            @param: sub_md_desc: STRING: desc of xrkmdSub
            @param: sub_md_rebase_offset: INT: offset of xkrmdSub, when hit, rebase xrkmdSub
            @param: sub_md_unload_offset: INT: offset of xrkmdSub, when hit, unload xrkmdSub
            @param: sub_md_base_getter: obj of xrkdef.vGetterXXX. used to get base of xrkmdSub when (parent_base + sub_md_unload_offset) hit
            @param: sub_md_size_getter: obj of xrkdef.vGetterXXX. used to get size of xrkmdSub when (parent_base + sub_md_unload_offset) hit

            1. if exists in self.sub_mds_dict, return it
            2. if not exists in self.sub_mds_dict, create one from params, add to self.sub_mds_dict, return created obj

            @return: obj of xkrmdSub
        """
        xrkmd = None

        if sub_md_name not in self.sub_mds_dict:

            xrkmd = xrkmdSub(sub_md_name, sub_md_desc, self.md_name_chains + [sub_md_name], sub_md_base_getter, sub_md_size_getter)
            xrkmd.init_offset(sub_md_rebase_offset, sub_md_unload_offset)
            self.sub_mds_dict[sub_md_name] = xrkmd

            xrklog.info("created xrkmdSub %s(offset is valid), and added to self.sub_mds_xx_dict" % (sub_md_name), add_prefix=True)

        else:
            xrkmd = self.sub_mds_dict[sub_md_name]

        if self.__check_offset_valid(sub_md_rebase_offset):
            xrkmd.install_rebase_hook(self.base)
        if self.__check_offset_valid(sub_md_unload_offset):
            xrkmd.install_unload_hook(self.base)

        return xrkmd

    def sub_md_get_feat(self, sub_md_name, sub_md_desc, sub_md_rebase_feat, sub_md_unload_feat, sub_md_base_getter, sub_md_size_getter):
        """
            get xrkmd sub by feat

            @param: sub_md_name: STRING: name of xrkmdSub
            @param: sub_md_desc: STRING: desc of xrkmdSub
            @param: sub_md_rebase_feat: STRING: used to get offset of xkrmdSub, when hit, rebase xrkmdSub
            @param: sub_md_unload_feat: STRING: used to get offset of xrkmdSub, when hit, unload xrkmdSub
            @param: sub_md_base_getter: obj of xrkdef.vGetterXXX. used to get base of xrkmdSub when (parent_base + sub_md_unload_offset) hit
            @param: sub_md_size_getter: obj of xrkdef.vGetterXXX. used to get size of xrkmdSub when (parent_base + sub_md_unload_offset) hit

            1. if rebase/unload feat invalid, return None
            2. if rebase/unload feat valid:
                2.1 if rebase/unload offset invalid
                2.2 if rebase/unload offset valid

            @return: obj of xkrmdSub
        """
        if self.__check_has_feat(feat_desc=sub_md_rebase_feat) and self.__check_has_feat(feat_desc=sub_md_unload_feat):

            rebase_offset = self.feat_calc(sub_md_rebase_feat)
            unload_offset = self.feat_calc(sub_md_unload_feat)
            if rebase_offset is not None and unload_offset is not None:

                # offset valid
                return self.sub_md_get(sub_md_name, sub_md_desc, rebase_offset, unload_offset, sub_md_base_getter, sub_md_size_getter)
            else:
                if sub_md_name not in self.sub_mds_dict:

                    # add to self.sub_mds_pending_dict and self.sub_mds_dict
                    assert sub_md_name not in self.sub_mds_pending_dict

                    self.sub_mds_pending_dict[sub_md_name] = (sub_md_rebase_feat, sub_md_unload_feat)

                    self.sub_mds_dict[sub_md_name] = xrkmdSub(sub_md_name, sub_md_desc, self.md_name_chains + [sub_md_name], sub_md_base_getter, sub_md_size_getter)

                    xrklog.info("created xrkmdSub %s(offset still invalid), and added to self.sub_mds_xx_dict" % (sub_md_name), add_prefix=True)

                return self.sub_mds_dict[sub_md_name]
        else:
            xrklog.error("invalid feat_desc %s - %s to create xrkmdSub %s" % (sub_md_rebase_feat, sub_md_unload_feat, sub_md_name))
            return None

    def sub_md_update(self, sub_md_name, sub_md_value):
        """
            update xkrmdSub value directly
        """
        if sub_md_name in self.sub_mds_dict:
            self.sub_mds_dict[sub_md_name] = sub_md_value
        else:
            xrklog.error("update xrkmdSub %s, invalid sub_md_name: %s" % (self.name, sub_md_name))

    def sub_md_remove(self, sub_md_name):
        """
            remove xrkmdSub from self.sub_mds_dict by sub_md_name
        """
        if sub_md_name in self.sub_mds_dict:
            del self.sub_mds_dict[sub_md_name]
        else:
            xrklog.error("xrkmdSub %s not exists in parent xrkmd %s" % (sub_md_name, self.name))

    def sub_md_get_names(self, sp_cnt=0):
        """
            get sub mds names, like this:
                name_1
                    name_2
                        name_3
                    name_4
                        name_5
                        name_6
                            name_7
                    ...

            @parma: sp_cnt: INT: spacer count
        """
        lines = ["%s%s" % (sp_cnt * "    ", self.name)]
        for (d, x) in self.sub_mds_dict.items():
            lines = lines + x.sub_md_get_names(sp_cnt + 1)
        return lines

    def sub_md_get_all(self):
        """
            get all xrkmdSubs

            @return: LIST: a list of xrkmdSub objs
        """
        ret = []
        for (d, x) in self.sub_mds_dict.items():
            ret.append(x)
            ret = ret + x.sub_md_get_all()
        return ret

    # ---------------------------------------------------------------------------
    # internal
    # ---------------------------------------------------------------------------

    def check_base_valid(self):
        return self.__check_base_valid()

    def __check_base_valid(self):
        return self.base != 0 and xrkutil.validate_addr(self.base)

    def check_offset_valid(self, offset):
        """
            for external usage
        """
        return self.__check_offset_valid(offset)

    def __check_offset_valid(self, offset):
        """
            check if base not 0 and (base + offset) is valid address
        """
        return self.base != 0 and xrkutil.validate_addr(self.base + offset)

    def check_has_addr(self, addr):
        """
            check if addr in range of xrkmd
        """
        return self.base != 0 and (addr <= self.base + self.size) and (addr >= self.base)

    # ---------------------------------------------------------------------------
    # feat
    # ---------------------------------------------------------------------------

    def __rebase_feat(self):
        """
            suck feat when rebase

            !+ self.base has already been updated
        """
        if len(self.feat_dict) != 0:
            xrklog.info("rebase md %s, feat count: %d" % (self.name, len(self.feat_dict)), add_prefix=True)
            # calc none calced feat
            # {"feat_1": (0x123, "00 01 02", ["00 01 02"]), "feat_2": (None, "00 ? 0B", ["00", 1, "0B"])}
            for (d, x) in self.feat_dict.items():
                if x[0] is None:
                    # self.feat_dict will be updated in self.feat_calc()
                    feat_offset = self.feat_calc(d)
                    xrklog.info("rebase md %s, calc feat: %s - %.8X" % (self.name, d, feat_offset), add_prefix=True)

    def __check_has_feat(self, feat_desc=None, feat_desc_str=None):
        """
            check already has feature

            @param: feat_desc: STRING: desc string
            @param: feat_desc_str: STRING: something like "00 0A 0B"
        """
        assert not (feat_desc is None and feat_desc_str is None)
        if len(self.feat_dict) == 0:
            return False
        if feat_desc is not None:
            if feat_desc not in self.feat_dict:
                return False
            ret = feat_desc_str is None or self.feat_dict[feat_desc][1] == feat_desc_str
            assert ret is True
            return ret
        else:
            for (d, x) in self.feat_dict.items():
                if x[1] == feat_desc_str:
                    return True
            return False

    def feat_add(self, feat_desc, feat_desc_str):
        """
            add feature

            1. feat not added: add, try to calc if base valid
            2. feat added, but offset invalid: try to calc if base valid
            3. error

            @param: feat_desc: STRING: desc string
            @param: feat_desc_str: STRING: like "00 0A 0B"
        """
        if not self.__check_has_feat(feat_desc=feat_desc, feat_desc_str=feat_desc_str):

            addr = self.__check_base_valid() and self.search_desc_list_str(feat_desc_str) or None
            offset = addr is not None and (addr - self.base) or None
            self.feat_dict[feat_desc] = (offset, feat_desc_str, xrkdef.game_str_to_desc_list_only_q(feat_desc_str))

        elif self.feat_dict[feat_desc][0] is None and self.__check_base_valid():

            # calc feat
            self.feat_calc(feat_desc)

        else:
            xrklog.warn("failed re-add feat %s to xrkmd %s" % (self.name, feat_desc))

    def feat_add_many(self, feat_list):
        """
            add many features

            @param: feat_list: LIST: [(feat_desc_1, last_offset_1, feat_desc_str_1), (feat_desc_2, last_offset_2, feat_desc_str_2)]

            !+ "last_offset" of feat_list is not used.
        """
        for feat in feat_list:
            # we use feat[1] for nothing...
            self.feat_add(feat_desc=feat[0], feat_desc_str=feat[2])

    def feat_remove_all(self):
        """
            remove all features, but ignore "pending" ones...
        """
        pending_feat_descs = self.bp_pending_dict.keys()
        for (d, x) in self.feat_dict.items():
            if d not in pending_feat_descs:
                del self.feat_dict[d]

    def feat_calc(self, feat_desc):
        """
            calc feat offset, and set self.feat_dict

            @param: feat_desc: STRING: desc of feat

            @return: INT: offset of feat_desc

            !+ self.feat_dict will be updated in this method
        """
        # this is solid addr, not offset
        # {"feat_1": (0x123, "00 01 02", ["00 01 02"]), "feat_2": (None, "00 ? 0B", ["00", 1, "0B"])}
        offset = self.feat_dict[feat_desc][0]
        if offset is None:
            if self.__check_base_valid():
                addr = self.search_desc_list_str(self.feat_dict[feat_desc][1])
                if addr is None:
                    xrklog.error("feat calc error: %s" % feat_desc, add_prefix=True)
                    assert False
                offset = addr - self.base
                self.feat_dict[feat_desc] = (offset, self.feat_dict[feat_desc][1], self.feat_dict[feat_desc][2])
        return offset

    # ---------------------------------------------------------------------------
    # bp management for both bp and hook
    # ---------------------------------------------------------------------------

    def try_del_bp_by_bp(self, offset):
        """
            hook might still using this bp
        """
        if self.__check_offset_valid(offset):
            for (d, x) in self.hook_dict.items():
                if x[0] == offset:
                    assert x[2].offset == offset
                    # install log/pause bp
                    x[2].reset_bp()
                    return

            xrkdbg.deleteBreakpoint(self.base + offset)

    def try_disable_bp_by_bp(self, offset):
        """
            hook might still using this bp
        """
        self.try_del_bp_by_bp(offset)

    def try_del_bp_by_hook(self, offset):
        """
            bp might still using this bp
        """
        if self.__check_offset_valid(offset):
            for (d, x) in self.bp_dict.items():
                if x[0] == offset:
                    if x[1]:
                        xrkdbg.setBreakpoint(self.base + offset)
                        return
                    break
            xrkdbg.deleteBreakpoint(self.base + offset)

    def try_un_pause_by_by_hook(self, offset):
        """
            hook try to change bp type to logging, but bp may need it pause

            1. log hook --> log bp, or hook will not hit
            2. pause hook --> lob/puase bp, both will hit
        """
        pass

    # ---------------------------------------------------------------------------
    # bp
    # ---------------------------------------------------------------------------

    def __rebase_bp(self, old_base):
        """
            suck bp when rebase

            @param: old_base: INT: old base.

            !+ self.base has already been updated
        """
        if len(self.bp_dict) != 0:
            xrklog.info("rebase md %s, bp count: %d" % (self.name, len(self.bp_dict)), add_prefix=True)
            # re set bps
            # {"bp_1": (0x123, True), "bp_2": (0x234, False)}
            for (d, x) in self.bp_dict.items():
                offset = x[0]
                xrkutil.may_del_bp(old_base + offset)
                xrkutil.may_del_comment(old_base + offset)
                xrkutil.may_update_comment(self.base + offset, d)
                if x[1]:
                    xrkutil.may_bp(self.base + offset)
                xrklog.info("rebase md %s, update bp %s to %.8X" % (self.name, d, self.base + x[0]), add_prefix=True)

        if len(self.bp_pending_dict) != 0:
            xrklog.info("rebase md %s, pending feat bp count: %d" % (self.name, len(self.bp_pending_dict)), add_prefix=True)
            # install pending bps
            # {"feat_1": True, "feat_2": False}
            for (d, x) in self.bp_pending_dict.items():
                self.bp_add_by_feat(d, is_enabled=x)
                xrklog.info("rebase md %s, install pending enabled bp %s" % (self.name, d), add_prefix=True)
            self.bp_pending_dict = {}

    def __re_apply_bp(self):
        """
            base is not changed when re-base, re apply bps
        """
        if len(self.bp_dict) != 0:
            xrklog.info("re-apply md %s, bp count: %d" % (self.name, len(self.bp_dict)), add_prefix=True)
            # re set bps
            # {"bp_1": (0x123, True), "bp_2": (0x234, False)}
            for (d, x) in self.bp_dict.items():
                offset = x[0]
                xrkutil.may_update_comment(self.base + offset, d)
                if x[1]:
                    xrkutil.may_bp(self.base + offset)

        if len(self.bp_pending_dict) != 0:
            xrklog.info("re-apply md %s, pending bp count: %d" % (self.name, len(self.bp_pending_dict)), add_prefix=True)
            # install pending bps
            # {"feat_1": True, "feat_2": False}
            for (d, x) in self.bp_pending_dict.items():
                self.bp_add_by_feat(d, is_enabled=x)
                xrklog.info("re-apply md %s, install pending enabled bp %s" % (self.name, d), add_prefix=True)
            self.bp_pending_dict = {}

    def __check_has_bp_calced(self, desc=None, offset=None):
        """
            check bp with same offset and desc in self.bp_dict
        """
        assert not (desc is None and offset is None)
        if len(self.bp_dict) == 0:
            return False

        if desc is not None:
            if desc in self.bp_dict:
                assert offset is None or self.bp_dict[desc][0] == offset
                return True
            else:
                return False
        else:
            # desc is None, check offset only
            for (d, x) in self.bp_dict.items():
                if x[0] == offset:
                    return True
            return False

    def __check_has_bp_pending(self, desc):
        """
            check bp with same desc in self.bp_pending_dict
        """
        return desc in self.bp_pending_dict

    def __check_has_bp(self, desc=None, offset=None):
        """
            check bp with same offset and desc has already been installed, or pending...
        """
        return self.__check_has_bp_calced(desc, offset) or self.__check_has_bp_pending(desc)

    def bp_tmp(self, offset):
        """
            set temp bp at offset
        """
        if self.__check_offset_valid(offset):
            xrkutil.may_update_comment(self.base + offset, "tmp bp")
            xrkdbg.setBreakpoint(self.base + offset)
        else:
            xrklog.error("bp tmp at xrkmd: %s, addr invalid, base: 0x%.8X, offset: 0x%.8X" % (self.name, self.base, offset), add_prefix=True)

    def bp_add(self, desc, offset, is_enabled=True):
        """
            1. add to bp_dict
            2. set bp if addr valid

            @param: desc: STRING: as key
            @param: offset: INT: must be valid
            @param: is_enabled: BOOL: is enabled when installed
        """
        if not self.__check_has_bp(desc=desc, offset=offset):
            # neither in self.bp_dict, nor self.pending_feat_bp_dict, add to bp_dict
            self.bp_dict[desc] = (offset, is_enabled)

        elif not self.__check_has_bp_calced(desc=desc, offset=offset):
            # not in self.bp_dict, so, must in self.pending_feat_bp_dict, add to bp_dict
            self.bp_dict[desc] = (offset, is_enabled)
            del self.bp_pending_dict[desc]

        else:
            xrklog.warn("bp %s(%.8X) already exists in bp dict of xrkmd %s, can't add, but will add bp anyway" % (desc, offset, self.name))

        if self.__check_offset_valid(offset):
            xrkdbg.setBreakpoint(self.base + offset)
            xrkutil.may_update_comment(self.base + offset, desc)
            if not is_enabled:
                xrkdbg.disableBreakpoint(self.base + offset)

    def bp_add_by_feat(self, feat_desc, is_enabled=True):
        """
            add bp by feat_desc

            @param: feat_desc: STRING, key of self.feat_dict
        """
        if feat_desc not in self.feat_dict:
            xrklog.error("add bp by feat to xrkmd %s, but feat not exist: %s" % (self.name, feat_desc))
        else:
            offset = self.feat_calc(feat_desc)
            if offset is not None:
                self.bp_add(desc=feat_desc, offset=offset, is_enabled=is_enabled)
            else:
                self.bp_pending_dict[feat_desc] = is_enabled

    def bp_add_many(self, bp_list):
        """
            add a list of bps

            @param: bp_list: LIST: [(bp_desc_1, bp_offset_1, bp_enable_1), (bp_desc_2, bp_offset_2, bp_enable_2)]
        """
        for bp in bp_list:
            self.bp_add(desc=bp[0], offset=bp[1], is_enabled=bp[2])

    def bp_add_many_by_feat_list(self, feat_bp_list):
        """
            add a list of bps by feat list

            @param: feat_bp_list: LIST: [(feat_desc_1, bp_enable_1), (feat_desc_2, bp_enable_2)]
        """
        for feat_bp in feat_bp_list:
            self.bp_add_by_feat(feat_bp[0], feat_bp[1])

    def bp_add_many_by_feat_dict(self, feat_bp_dict):
        """
            add a list of bps by feat list

            @param: feat_bp_dict: DICT: {feat_desc_1: bp_enable_1, feat_desc_2: bp_enable_2}
        """
        for (d, x) in feat_bp_dict.items():
            self.bp_add_by_feat(d, x)

    def bp_remove(self, desc):
        """
            remove bp from bp_dict and bp_pending_dict by desc, and remove bp on address
        """
        if desc in self.bp_dict:

            self.try_del_bp_by_bp(self.bp_dict[desc][0])
            del self.bp_dict[desc]

        elif desc in self.bp_pending_dict:
            del self.bp_pending_dict[desc]

        else:
            xrkdbg.warn("bp %s not exist in bp_dict and bp_pending_dict of xrkmd %s, nothing to remove" % (desc, self.name))

    def bp_remove_many(self, desc_list):
        """
            remove a list of bps

            @param: desc_list: LIST, each element: bp_desc
        """
        for desc in desc_list:
            self.bp_remove(desc=desc)

    def bp_remove_all(self):
        """
            clear all bps
        """
        for (d, x) in self.bp_dict.items():
            self.try_del_bp_by_bp(x[0])

        self.bp_dict = {}
        self.bp_pending_dict = {}

        xrklog.info("remove all %d bps from xrkmd %s" % (len(self.bp_dict), self.name))

    def bp_unload(self, desc):
        """
            unload bp if bp is installed.

            !+ not remove from self.bp_dict nor self.bp_pending_dict
        """
        if desc in self.bp_dict:
            self.try_del_bp_by_bp(self.bp_dict[desc][0])

    def bp_unload_many(self, desc_list):
        """
            unload many bp if bp is installed

            @param: desc_list: LIST, each element: bp_desc
        """
        for desc in desc_list:
            self.bp_unload(desc=desc)

    def bp_unload_all(self):
        """
            unload all bps
        """
        for (d, x) in self.bp_dict.items():
            self.try_del_bp_by_bp(x[0])

    def bp_enable(self, desc):
        """
            enable bp by desc
        """
        if desc in self.bp_dict:

            offset = self.bp_dict[desc][0]
            if self.__check_offset_valid(offset):
                xrkdbg.setBreakpoint(self.base + offset)
            self.bp_dict[desc][1] = True

        elif desc in self.bp_pending_dict:
            self.bp_pending_dict[desc] = True

        else:
            xrkdbg.warn("bp %s not exist in bp_dict and bp_pending_dict of xrkmd %s, nothing to enable" % (desc, self.name))

    def bp_enable_many(self, desc_list):
        """
            enable a list of bps

            @param: desc_list: LIST, each element: bp_desc
        """
        for desc in desc_list:
            self.bp_enable(desc=desc)

    def bp_enable_all(self):
        """
            enable all bps
        """
        for (d, x) in self.bp_dict.items():

            if self.__check_offset_valid(x[0]):
                xrkdbg.setBreakpoint(self.base + x[0])
            x[1] = True

        for (d, x) in self.bp_pending_dict.items():
            self.bp_pending_dict[x] = True

    def bp_disable(self, desc):
        """
            disable bp by desc
        """
        if desc in self.bp_dict:

            self.try_disable_bp_by_bp(self.bp_dict[desc][0])
            self.bp_dict[desc][1] = False

        elif desc in self.bp_pending_dict:
            self.bp_pending_dict[desc] = False

        else:
            xrkdbg.warn("bp %s not exist in bp_dict and bp_pending_dict of xrkmd %s, nothing to disable" % (desc, self.name))

    def bp_disable_many(self, desc_list):
        """
            disable a list of bps

            @param: desc_list: LIST, each element: bp_desc
        """
        for desc in desc_list:
            self.bp_disable(desc=desc)

    def bp_disable_all(self):
        """
            disable all bps
        """
        for (d, x) in self.bp_dict.items():
            self.try_disable_bp_by_bp(x[0])
            self.bp_dict[d] = (x[0], False)

        for (d, x) in self.bp_pending_dict.items():
            self.bp_pending_dict[x] = False

    # ---------------------------------------------------------------------------
    # hook
    # ---------------------------------------------------------------------------

    def __rebase_hook(self, old_base):
        """
            suck hook when rebase

            !+ self.base has already been updated
        """
        if len(self.hook_dict) != 0:
            xrklog.info("rebase md %s, hook count: %d" % (self.name, len(self.hook_dict)), add_prefix=True)
            # re install hooks
            # # {"hook_1": (0x123, cbk_run_obj_1, hk_obj_1), "hook_2": (0x234, cbk_run_obj_2, hk_obj_2)}
            for (d, x) in self.hook_dict.items():

                offset = x[0]
                xrkutil.may_del_comment(old_base + offset)
                xrkutil.may_update_comment(self.base + offset, d)
                x[2].rebase(self.base)

                xrklog.info("rebase md %s, update hook %s to %.8X" % (self.name, d, self.base + x[0]), add_prefix=True)

        if len(self.hook_pending_dict) != 0:
            xrklog.info("rebase md %s, pending hook count: %d" % (self.name, len(self.hook_pending_dict)), add_prefix=True)
            # install hooks
            # {"feat_1": (cbk_run_obj_1, True), "feat_2": (cbk_run_obj_2, False)}
            for (d, x) in self.hook_pending_dict.items():

                offset = self.feat_dict[d][0]
                assert offset is not None
                # first remove from pending, or will take as re-pending
                del self.hook_pending_dict[d]
                self.__hook_add(desc=d, offset=offset, run_cbk_obj=x[0], shall_pause=x[1])
                xrklog.info("rebase md %s, install pending hook %s" % (self.name, d), add_prefix=True)

            self.hook_pending_dict = {}

    def __re_apply_hook(self):
        """
            re-apply hook when rebase
        """
        if len(self.hook_dict) != 0:

            xrklog.info("re-apply md %s, hook count: %d" % (self.name, len(self.hook_dict)), add_prefix=True)
            # {"hook_1": (0x123, cbk_run_obj_1, hk_obj_1), "hook_2": (0x234, cbk_run_obj_2, hk_obj_2)}
            for (d, x) in self.hook_dict.items():

                x[2].re_apply()

        if len(self.hook_pending_dict) != 0:

            xrklog.info("re-apply md %s, pending hook count: %d" % (self.name, len(self.hook_pending_dict)), add_prefix=True)
            # {"feat_1": (cbk_run_obj_1, True), "feat_2": (cbk_run_obj_2, False)}
            for (d, x) in self.hook_pending_dict.items():

                offset = self.feat_dict[d][0]
                assert offset is not None
                # first remove from pending, or will take as re-pending
                del self.hook_pending_dict[d]
                self.__hook_add(desc=d, offset=offset, run_cbk_obj=x[0], shall_pause=x[1])
                xrklog.info("re-apply md %s, install pending hook %s" % (self.name, d), add_prefix=True)

            self.hook_pending_dict = {}

    def __check_has_hook_calced(self, desc=None, offset=None):
        """
            check has hook that has valid offset
        """
        assert not (offset is None and desc is None)
        if len(self.hook_dict) == 0:
            return False

        if desc is not None:
            if desc in self.hook_dict:
                assert offset is None or self.hook_dict[desc][0] == offset
                return True
            else:
                return False
        else:
            # offset is valid
            for (d, x) in self.hook_dict.items():
                if x[0] == offset:
                    return True
            return False

    def __check_has_hook_pending(self, desc):
        """
            check has hook that offset is invalid yet
        """
        return desc in self.hook_pending_dict

    def __check_has_hook(self, desc=None, offset=None):
        """
            check has hook with same offset or desc already installed, or pending...
        """
        return self.__check_has_hook_calced(desc=desc, offset=offset) or self.__check_has_hook_pending(desc=desc)

    def __hook_add(self, desc, offset, run_cbk_obj, shall_pause=False):
        """
            add hook to self.hook_dict, and install if offset valid

            @param: desc: STRING: work as key for self.hook_dict, and real hook
            @param: offset: INT: offset to invoke hook, must be valid
            @param: run_cbk_obj: obj of cbkStructRun
            @param: shall_pause: BOOL: shall pause when hit
        """
        assert offset is not None and offset != 0
        if self.__check_has_hook_calced(desc, offset):

            xrklog.error("hook %s at offset %.8X already installed, can't re-install" % (desc, offset), add_prefix=True)

        elif self.__check_has_hook_pending(desc):

            # del from pending first, if comes from self.hook_pending_dict
            xrklog.error("hook %s at offset %.8X already pending, can't re-install" % (desc, offset), add_prefix=True)

        else:

            # {"hook_1": (0x123, cbk_run_obj_1, hk_obj_1), "hook_2": (0x234, cbk_run_obj_2, hk_obj_2)}
            h = xrkmdHitHook(desc, offset, run_cbk_obj)
            if self.__check_offset_valid(offset):
                h.rebase(self.base)

            # add h to cloud at last.
            self.hook_dict[desc] = (offset, run_cbk_obj, h)

    def hook_add(self, desc, offset, run_cbk, shall_pause=False, param1=None, param2=None, param3=None, param4=None):
        """
            add hook
        """
        self.__hook_add(desc, offset, xrkdef.cbkStructRun(run_cbk, param1=param1, param2=param2, param3=param3, param4=param4), shall_pause=shall_pause)

    def hook_add_by_desc_str(self, desc_str, run_cbk, shall_pause=False, param1=None, param2=None, param3=None, param4=None):
        """
            add hook by desc string

            1. if offset valid: add to self.hook_dict
            2. if offset invalid: add to self.hook_pending_dict
        """
        if desc_str in self.feat_dict:

            offset = self.feat_dict[desc_str][0]
            run_obj = xrkdef.cbkStructRun(run_cbk, param1=param1, param2=param2, param3=param3, param4=param4)

            if offset is not None:

                # del from self.hook_pending_dict first
                if desc_str in self.hook_pending_dict:
                    del self.hook_pending_dict[desc_str]

                self.__hook_add(desc_str, offset, run_obj)

            else:
                self.hook_pending_dict[desc_str] = (run_obj, shall_pause)
                xrklog.info("xrkmd %s add/update pending hook: %s" % (self.name, desc_str), add_prefix=True)

            """
            if desc_str in self.hook_pending_dict:

                # {"feat_1": (cbk_run_obj_1, True), "feat_2": (cbk_run_obj_2, False)}
                if self.feat_dict[desc_str][0] is not None:

                    # for some reason, offset become valid, then really install it.
                    self.__hook_add(desc_str, self.feat_dict[desc_str][0], run_obj)
                    del self.hook_pending_dict[desc_str]

                else:
                    self.hook_pending_dict[desc_str] = (run_obj, shall_pause)
                    xrklog.info("xrkmd %s update pending hook: %s" % (self.name, desc_str), add_prefix=True)

            else:
                offset = self.feat_dict[desc_str][0]
                if offset is not None:

                    self.__hook_add(desc_str, offset, run_obj)

                else:
                    self.hook_pending_dict[desc_str] = (run_obj, shall_pause)
                    xrklog.info("xrkmd %s add pending hook: %s" % (self.name, desc_str), add_prefix=True)
            """
        else:
            xrklog.error("desc string %s not exist in feat_dict of xrkmd %s" % (desc_str, self.name))

    def hook_add_many(self, hook_list):
        """
            add many hooks

            @param: hook_list: LIST: a list of TUPLE: [(desc_str, run_cbk, True), (desc_str, run_cbk, False), ...]
        """
        for hook_item in hook_list:
            self.hook_add_by_desc_str(hook_item[0], hook_item[1], hook_item[2])

    def hook_remove(self, desc):
        """
            remove hook
        """
        if desc in self.hook_dict:

            hook = self.hook_dict[desc]
            self.try_del_bp_by_hook(hook[0])
            hook[2].UnHook()
            del self.hook_dict[desc]

        elif desc in self.hook_pending_dict:
            del self.hook_pending_dict[desc]

        else:
            xrklog.error("hook %s not exist in xrkmd %s, nothing to remove" % (desc, self.name))

    def hook_remove_many(self, desc_list):
        """
            remove many hooks

            @param: desc_list: LIST: a list of strings(descs)
        """
        for desc in desc_list:
            self.hook_remove(desc)

    def hook_remove_all(self):
        """
            remove all hooks
        """
        for (d, x) in self.hook_dict.items():
            self.try_del_bp_by_hook(x[0])
            x[2].UnHook()

        self.hook_dict = {}
        self.hook_pending_dict = {}

    def hook_pause(self, desc):
        """
            pause when hook hit
        """
        if desc in self.hook_dict:
            self.hook_dict[desc][2].set_pause()

        elif desc in self.hook_pending_dict:
            self.hook_pending_dict[desc] = (self.hook_pending_dict[desc][0], True)

        else:
            xrklog.error("pause hook %s of xrkmd %s is not valid(offset not calced)" % (desc, self.name), add_prefix=True)

    def hook_pause_many(self, desc_list):
        """
            pause many hooks when hook hit

            @param: desc_list: LIST: a list of strings(descs)
        """
        for desc in desc_list:
            self.hook_pause(desc)

    def hook_pause_all(self):
        """
            pause all hooks when hook hit
        """
        for (d, x) in self.hook_dict.items():
            x[3].set_pause()

        for (d, x) in self.hook_pending_dict.items():
            self.hook_pending_dict[d] = (x[0], True)

    def hook_un_pause(self, desc):
        """
            un_pause when hook hit
        """
        if desc in self.hook_dict:
            self.hook_dict[desc][2].set_un_pause()

        elif desc in self.hook_pending_dict:
            self.hook_pending_dict[desc] = (self.hook_pending_dict[desc][0], False)

        else:
            xrklog.error("unpause hook %s of xrkmd %s is not valid(offset not calced)" % (desc, self.name), add_prefix=True)

    def hook_un_pause_many(self, desc_list):
        """
            un_pause many hook when hook hit

            @param: desc_list: LIST: a list of strings(descs)
        """
        for desc in desc_list:
            self.hook_un_pause(desc)

    def hook_un_pause_all(self):
        """
            un pause all hooks when hook hit
        """
        for (d, x) in self.hook_dict.items():
            x[3].set_un_pause()

        for (d, x) in self.hook_pending_dict.items():
            self.hook_pending_dict[d] = (x[0], False)

    def hook_unload(self, desc):
        """
            unload installed hook(prevent from hit by removing bp)
        """
        pass

    def hook_unload_many(self, desc_list):
        pass

    def hook_unload_all(self):
        pass

    # ---------------------------------------------------------------------------
    # pt
    # ---------------------------------------------------------------------------

    # !+ we don't use __str__() here, because result string would be quite large, and imm with split it into many lines

    def get_details_strs(self, sp_cnt=0):
        """
            get details strings. for external usage
        """
        return self.__get_details_strs(sp_cnt)

    def __get_details_strs(self, sp_cnt=0):
        """
            get description details strings

            @param: sp_cnt: INT: spacer count

            @return: LIST: a list of string
        """
        v_splitter = "-" * 100
        lines = []
        lines.append(v_splitter)
        lines.append("details of xrkmd %s" % self.name)
        lines.append("      basic info: %.8X + %.8X = %.8X" % (self.base, self.size, self.end))

        # feature
        lines.append("feat count: %d" % len(self.feat_dict))
        # {"feat_1": (0x123, "00 01 02", ["00 01 02"]), "feat_2": (None, "00 ? 0B", ["00", 1, "0B"])}
        for (d, x) in self.feat_dict.items():
            offset_str = x[0] is None and "None" or ("%.8X" % x[0])
            lines.append("        feat: %8s - %40s - %s" % (offset_str, d, x[1]))

        # bp
        lines.append("bp count: %d" % len(self.bp_dict))
        for (d, x) in self.bp_dict.items():
            enabled_str = x[1] is True and "Enabled" or "Disabled"
            lines.append("          bp: %.8X - %40s - %8s" % (x[0], d, enabled_str))

        # pending bp
        lines.append("pending bp count: %d" % len(self.bp_pending_dict))
        for (d, x) in self.bp_pending_dict.items():
            enabled_str = x is True and "Enabled" or "Disabled"
            lines.append("  pending bp: %40s - %s" % (d, enabled_str))

        # hook
        lines.append("hook count: %d" % len(self.hook_dict))
        # {"hook_1": (0x123, cbk_run_obj_1, hk_obj_1), "hook_2": (0x234, cbk_run_obj_2, hk_obj_2)}
        for (d, x) in self.hook_dict.items():
            lines.append("        hook: %.8X - %40s - %s" % (x[0], d, x[2].get_shall_pause_str()))

        # pending hook
        lines.append("pending hook count: %d" % len(self.hook_pending_dict))
        # {"feat_1": (cbk_run_obj_1, True), "feat_2": (cbk_run_obj_2, False)}
        for (d, x) in self.hook_pending_dict.items():
            shall_pause_str = x[1] and "Pause" or "Not-Pause"
            lines.append("pending hook: %40s - %s" % (d, shall_pause_str))

        # sub md
        lines.append("sub md count: %d" % len(self.sub_mds_dict))
        for (d, x) in self.sub_mds_dict.items():
            lines = lines + x.get_details_strs(sp_cnt + 1)

        lines.append(v_splitter)
        # return lines
        ret = []
        for line in lines:
            ret.append("%s%s" % (sp_cnt * "    ", line))
        return ret

    def pt(self):
        """
            print details
        """
        xrklog.infos(self.__get_details_strs())

    # ---------------------------------------------------------------------------
    # sym/stack
    # ---------------------------------------------------------------------------

    def __parse_sym_file(self, lines):
        """
            check lines, then parse

            @param: lines: LIST: a list of string. for each line: (4317740 4317746 j_GetStdHandle)

            @return: BOOL: True if all lines are valid
                           Flase if any line invalid(and self.sym_list will become empty)
        """
        new_syms_list = []
        for line in lines:

            line = line.strip("\n")
            if line.count(" ") != 2:

                xrklog.error("invalid line %s when parse sym for xrkmd %s" % (line, self.name))
                new_syms_list = []
                break

            else:

                splits = line.split(" ")
                assert len(splits) == 3
                new_syms_list.append((int(splits[0], 16), int(splits[1], 16), splits[2]))

        if len(new_syms_list) == 0:

            self.sym_list = []
            return False

        else:

            self.sym_list = new_syms_list
            return True

    def is_sym_file_set(self):
        """
            check if sym file set.
        """
        return self.sym_file_path is not None

    def set_sym_file(self, sym_file_path, force_update=False):
        """
            set sym file path, and parse sym file
        """
        if not self.is_sym_file_set() or force_update:
            if os.path.exists(sym_file_path):

                lines = []
                f = open(sym_file_path)
                lines = f.readlines()
                f.close()

                if self.__parse_sym_file(lines):
                    self.sym_file_path = sym_file_path
                else:
                    xrklog.error("xrkmd %s parse sym file %s fail" % (self.name, sym_file_path))
            else:
                xrklog.error("xrkmd %s parse sym file %s, buf file not exists" % (self.name, sym_file_path))
        else:
            xrklog.info("xrkmd %s sym file is already set, or not force update. ignore new file: %s" % (self.name, sym_file_path))

    def sym_get(self, addr):
        """
            get sym

            !+ addr shall be valid

            @return: STRING: func_abc+0x12
                     "Sym-Not-Set"
                     "Sym-Not-Found"
        """
        assert self.check_has_addr(addr)
        if self.is_sym_file_set():
            for sym in self.sym_list:
                if (self.base + sym[0]) <= addr and addr <= (self.base + sym[1]):
                    return "%s+0x%XL" % (sym[2], addr - self.base - sym[0])
            return "Sym-Not-Found"
        else:
            return "Sym-Not-Set"

    # ---------------------------------------------------------------------------
    # misc
    # ---------------------------------------------------------------------------

    def get_md_name_chains(self):
        """
            get a list of xrkmd names, from root name direct to name of this md

            @return: LIST: a list of strings
        """
        return self.md_name_chains

    def get_mm_pages(self):
        """
            get mm pages this md contains

            @return: DICT: {addr: MemoryPage, addr: MemoryPage,}
                     or, None

            !+ actually, any byte of each page shall belong to this xrkmd. which means, no "pending" mm page slices
        """
        if not xrkutil.validate_addr(self.base):
            xrklog.info("xrkmd %s base %.8X not valid, no pages available" % (self.name, self.base), verbose=True, add_prefix=True)
            return None

        ret = {}
        tmp_addr = self.base
        tmp_page = xrkdbg.getMemoryPageByAddress(tmp_addr)
        while tmp_page is not None:
            ret[tmp_addr] = tmp_page
            tmp_addr = tmp_addr + tmp_page.getSize()
            tmp_page = xrkdbg.getMemoryPageByAddress(tmp_addr)
        return ret

    def search_sd(self, sd):
        """
            search sd in this xrkmd

            @param: sd: obj of mmSearchDescriptor(xrkgame)

            @return: result address, or None
        """
        pass

    def search_sdg(self, sdg):
        """
            search sdg in this xrkmd

            @param: sdg: obj of sdg(xrkgame)

            @return: result address, or None
        """
        pages = self.get_mm_pages()
        if pages is not None and len(pages) != 0:
            return sdg.search_in_pages(pages=pages)
        else:
            return None

    def search_desc_list_str(self, desc_list_str):
        """
            search desc list in xrkmd pages

            @param: desc_list_str: STRING: like: 00 01 02
        """
        # sdg = xrkgame.sdg(xrkutil.time_str(), desc_list_str)
        # return self.search_sdg(sdg)
        return None

    def get_desc_by_offset(self, offset, min_len=10, max_len=100):
        """
            get desc by offset

            @return: LIST: [(desc_str_1, desc_str_1_size, search_cnt), (desc_str_2, desc_str_2_size, search_cnt), ...]
                     or None
        """
        pages = self.get_mm_pages()
        if pages is not None and len(pages) != 0:
            xrklog.info("get desc at addr: %.8X + %.8X = %.8X" % (self.base, offset, self.base + offset), verbose=True, add_prefix=True)
            # return xrkgame.get_desc_dict_from_addr_in_mm_pages(self.base + offset, pages, min_len=min_len, max_len=max_len)
            return None
        else:
            return None

    def clear_md_chains(self):
        """
            clear this md and sub md.
        """
        self.feat_remove_all()
        self.bp_remove_all()
        self.hook_remove_all()
        for (sub_md_name, sub_md) in self.sub_mds_dict.items():
            sub_md.clear_md_chains()
        self.sub_mds_dict = {}

    # ---------------------------------------------------------------------------
    # end of class
    # ---------------------------------------------------------------------------


class xrkmdHitHook(xrkhook.pausableInvokeRunCbkHook):
    def __init__(self, desc, offset, run_cbk_obj):
        """
            @param: desc: STRING: hook key
            @param: offset: INT: offset of xrkmd.
            @param: run_cbk_obj: obj of xrkdef.cbkStructRun

            !+ offset is solid for each hook, shall be set when __init__()
        """
        xrkhook.pausableInvokeRunCbkHook.__init__(self, run_cbk_obj)
        self.desc = desc
        self.offset = offset
        self.base = 0

    def is_addr_valid(self):
        """
            check if address valid
        """
        return self.base != 0 and xrkutil.validate_addr(self.base + self.offset)

    def add(self, desc, offset, shall_pause=False):
        """
            never call this. call self.rebase() instead
        """
        assert False

    def remove(self, old_base):
        """
            remove thing by old_base
        """
        xrkutil.may_del_hook(self.desc)
        xrkutil.may_del_bp(old_base + self.offset)
        xrkutil.may_del_comment(old_base + self.offset)

    def rebase(self, new_base):
        """
            set new base

            1. remove old hook if installed
            2. add new hook
        """
        assert xrkutil.validate_addr(new_base)
        xrklog.high("rebase hook: %s at %.8X + %.8X = %.0X" % (self.desc, new_base, self.offset, new_base + self.offset), add_prefix=True)

        old_base = self.base
        if old_base != new_base:
            self.base = new_base
            self.address = new_base + self.offset

            xrkutil.may_update_comment(self.address, self.desc)

            self.remove(old_base)

            if self.shall_pause:
                self.type = HookTypes["ORDINARY_BP_HOOK"]
                debugger.set_breakpoint(self.address, BpFlags["TY_ACTIVE"], "")
            else:
                self.type = HookTypes["LOG_BP_HOOK"]
                debugger.set_logging_breakpoint(self.address)
            pickled_object = pickle.dumps(self)
            return debugger.add_hook(pickled_object, self.desc, self.type, self.address, self.force, self.timeout, self.mode)

        else:
            xrklog.high("rebase hook: %s, but base not changed, will re-apply" % (self.desc), add_prefix=True)
            self.re_apply()

    def re_apply(self):
        """
            reapply
        """
        assert xrkutil.validate_addr(self.base)
        xrklog.high("re-apply hook: %s at %.8X + %.8X = %.0X" % (self.desc, self.base, self.offset, self.base + self.offset), add_prefix=True)

        xrkutil.may_update_comment(self.address, self.desc)

        self.remove(self.base)

        if self.shall_pause:
            self.type = HookTypes["ORDINARY_BP_HOOK"]
            debugger.set_breakpoint(self.address, BpFlags["TY_ACTIVE"], "")
        else:
            self.type = HookTypes["LOG_BP_HOOK"]
            debugger.set_logging_breakpoint(self.address)
        pickled_object = pickle.dumps(self)
        return debugger.add_hook(pickled_object, self.desc, self.type, self.address, self.force, self.timeout, self.mode)

    def set_pause(self):
        """
            set pause mode
        """
        if self.shall_pause:
            xrklog.info("hook %s is pause mode, do not convert" % (self.desc))

        elif self.is_addr_valid():

            self.shall_pause = True
            xrkutil.may_del_hook(self.desc)

            debugger.set_breakpoint(self.address, BpFlags["TY_ACTIVE"], "")
            self.type = HookTypes["ORDINARY_BP_HOOK"]
            pickled_object = pickle.dumps(self)
            debugger.add_hook(pickled_object, self.desc, self.type, self.address, self.force, self.timeout, self.mode)

        else:
            xrklog.info("hook %s addr invalid(offset: %.8X), will convert to pause mode when addr become valid" % (self.desc, self.offset))
            self.shall_pause = True

    def set_un_pause(self):
        """
            set un pause mode
        """
        if self.shall_pause:
            xrklog.info("hook %s is un pause mode, do not convert" % (self.desc))

        elif self.is_addr_valid():

            self.shall_pause = False
            xrkutil.may_del_hook(self.desc)

            debugger.set_logging_breakpoint(self.address)
            self.type = HookTypes["LOG_BP_HOOK"]
            pickled_object = pickle.dumps(self)
            debugger.add_hook(pickled_object, self.desc, self.type, self.address, self.force, self.timeout, self.mode)

        else:
            xrklog.info("hook %s addr invalid(offset: %.8X), will convert to un pause mode when addr become valid" % (self.desc, self.offset))
            self.shall_pause = False

    def reset_bp(self):
        """
            bp might manually removed, then we need to reset bp
        """
        if self.is_addr_valid():
            if self.shall_pause:
                debugger.set_breakpoint(self.address, BpFlags["TY_ACTIVE"], "")
            else:
                debugger.set_logging_breakpoint(self.address)

    def get_shall_pause(self):
        """
            get shall pause

            @return: BOOL:
        """
        return self.shall_pause

    def get_shall_pause_str(self):
        return self.shall_pause and "Pause" or "Not-Pause"


class xrkmdRebaseUnloadHook(xrkhook.pausableInvokeRunCbkHook):
    def __init__(self, rebase_unload_cbk, md_name_or_name_chains):
        xrkhook.pausableInvokeRunCbkHook.__init__(self, xrkdef.cbkStructRun(cbk=rebase_unload_cbk, param1=md_name_or_name_chains))


class xrkmdRoot(xrkmdBase):
    # ---------------------------------------------------------------------------
    # the word "Root" does not mean it's base is un-changed, on the contrary, it means this md is the first md that base changes.
    # ---------------------------------------------------------------------------
    def __init__(self, name, desc, rebase_addr, unload_addr, base_getter, size_getter):
        """
            @param: rebase_addr:
                    solid address, when xrkmdRoot's new base is valid
                    only used when install/reinstall hook
            @param: unload_addr:
                    solid address, when xrkmdRoot's unloading...
                    only used when install/reinstall hook
        """
        xrkmdBase.__init__(self, name, desc, [name], base_getter, size_getter)
        self.rebase_addr = rebase_addr
        self.unload_addr = unload_addr
        assert xrkutil.validate_addr(self.rebase_addr)
        self.rebase_hook_desc = ("xrkmdRoot_rebase_%s_%.8X" % (self.name, self.rebase_addr))
        self.unload_hook_desc = ("xrkmdRoot_unload_%s_%.8X" % (self.name, self.rebase_addr))

        self.install_rebase_hook()
        self.install_unload_hook()

        xrklog.info("created xrkmdRoot for %s at solid addr %.8X, desc: %s" % (self.name, self.rebase_addr, self.desc))

    def install_rebase_hook(self):
        """
            called by __init__()
        """
        assert self.rebase_hook_desc not in xrkdbg.listHooks()
        h = xrkmdRebaseUnloadHook(proxy_rebase_xrkmdRoot, self.name)
        h.add(self.rebase_hook_desc, self.rebase_addr)
        xrkutil.may_update_comment(self.rebase_addr, "xrkmdRoot_%s_rebase" % self.name)
        xrklog.info("install rebase hook for xrkmdRoot %s at %.8X" % (self.name, self.rebase_addr))

    def install_unload_hook(self):
        """
            called by __init__()
        """
        assert self.unload_hook_desc not in xrkdbg.listHooks()
        h = xrkmdRebaseUnloadHook(proxy_unload_xrkmdRoot, self.name)
        h.add(self.unload_hook_desc, self.unload_addr)
        xrkutil.may_update_comment(self.unload_addr, "xrkmdRoot_%s_unload" % self.name)
        xrklog.info("install unload hook for xrkmdRoot %s at %.8X" % (self.name, self.unload_addr))

    def re_apply_settings(self):
        """
            re-apply settings
        """
        xrkdbg.setLoggingBreakpoint(self.rebase_addr)
        xrkdbg.setLoggingBreakpoint(self.unload_addr)

        xrkmdBase.re_apply_settings(self)


class xrkmdSub(xrkmdBase):
    def __init__(self, name, desc, md_name_chains, base_getter, size_getter):
        """
            @param: name: STRING
            @param: desc: STRING
            @param: md_name_chains: xrkmd name chains, from root to parent, not including this xrkmdSub
            @param: base_getter: obj of xrkdef.vGetterXXX
            @param: size_getter: obj of xrkdef.vGetterXXX

            @param: rebase_offset: rebase_offset of md that this md belong to
        """
        xrkmdBase.__init__(self, name, desc, md_name_chains, base_getter, size_getter)
        self.rebase_offset = 0
        self.unload_offset = 0
        self.rebase_hook_desc = ""
        self.unload_hook_desc = ""
        xrklog.info("create xrkmdSub %s(%s)" % (self.name, self.desc))

    def is_offset_set(self):
        """
            check if offset is set
        """
        return self.rebase_offset != 0 and self.unload_offset != 0

    def init_offset(self, rebase_offset, unload_offset):
        """
            @caller: after xrkmdSub created, when offset is "known"

            @param: rebase_offset: INT: when hit, rebase
            @param: unload_offset: INT: when hit, unload
        """
        self.rebase_offset = rebase_offset
        self.unload_offset = unload_offset
        self.rebase_hook_desc = ("xrkmdSub_rebase_%s_%.8X" % (self.name, self.rebase_offset))
        self.unload_hook_desc = ("xrkmdSub_unload_%s_%.8X" % (self.name, self.unload_offset))
        xrklog.info("set offset for xrkmdSub %s at: %8X - %.8X" % (self.name, self.rebase_offset, self.unload_offset))

    def install_rebase_hook(self, parent_base):
        """
            install rebase hook

            !+ called by it's parent, when it's parent rebases, or when xrkmd newly added
        """
        assert self.rebase_offset != 0
        xrkutil.may_del_hook(self.rebase_hook_desc)
        xrkutil.may_del_comment(self.base + self.rebase_offset)

        h = xrkmdRebaseUnloadHook(proxy_rebase_xrkmdSub, self.get_md_name_chains())
        h.add(self.rebase_hook_desc, parent_base + self.rebase_offset)
        xrkutil.may_update_comment(parent_base + self.rebase_offset, "xrkmdSub_%s_rebase" % self.name)
        xrklog.info("install rebase hook for xrkmdSub %s at %.8X" % (self.name, parent_base + self.rebase_offset))

    def install_unload_hook(self, parent_base):
        """
            install unload hook

            !+ called by it's parent, when it's parent rebases, or when xrkmd newly added
        """
        assert self.unload_offset != 0

        xrkutil.may_del_hook(self.unload_hook_desc)
        xrkutil.may_del_comment(self.base + self.unload_offset)

        h = xrkmdRebaseUnloadHook(proxy_unload_xrkmdSub, self.get_md_name_chains())
        h.add(self.unload_hook_desc, parent_base + self.unload_offset)
        xrkutil.may_update_comment(parent_base + self.unload_offset, "xrkmdSub_%s_unload" % self.name)
        xrklog.info("install unoad hook for xrkmdSub %s at %.8X" % (self.name, parent_base + self.unload_offset))

    def re_apply_settings(self):
        """
            re-apply settings
        """
        # child class can't access private method of parent class
        if self.check_offset_valid(self.rebase_offset):
            xrkdbg.setLoggingBreakpoint(self.base + self.rebase_offset)
        if self.check_offset_valid(self.unload_offset):
            xrkdbg.setLoggingBreakpoint(self.base + self.unload_offset)

        xrkmdBase.re_apply_settings(self)


# -------------------------------------------------------------------------
# call stack
# -------------------------------------------------------------------------


class xrkmdStack:
    def __init__(self, cstk):
        self.cstk = cstk
        self.xrkmd_name = ""
        self.xrkmd_name_chains = []
        self.xrkmd_base = 0
        self.xrkmd_offset_procedure = 0
        self.xrkmd_offset_calledfrom = 0
        self.xrkmd_sym_calledfrom = ""

    def set_xrkmd_info(self, name, md_name_chains, base, md_sym):
        """
            set xrkmd thing

            @param: name: STRING: xrkmd name
            @param: md_name_chains: LIST: a list of strings, from xrkmdRoot to this xrkmd
            @param: base: INT: base address of xrkmd
            @param: md_sym: STRING: xrkmdmd symbol string
        """
        self.xrkmd_name = name
        self.xrkmd_name_chains = md_name_chains
        self.xrkmd_base = base
        # it's not that easy to get procedure_address...
        self.xrkmd_offset_procedure = 0
        self.xrkmd_offset_calledfrom = self.cstk.calledfrom - base
        self.xrkmd_sym_calledfrom = md_sym

    def check_is_from_xrkmd(self):
        """
            check is xrkmd
        """
        return self.xrkmd_base != ""

    def get_original_cstk(self):
        """
            get original debugtypes.Stack
        """
        return self.cstk

    def __str__(self):
        """
            get string description
        """
        fake_base = 0x10000000
        return "%s - %.8X + %.8X = %.8X - %s" % (self.xrkmd_name, fake_base, self.xrkmd_offset_calledfrom, fake_base + self.xrkmd_offset_calledfrom, self.xrkmd_sym_calledfrom)


def resolve_call_stack(cstks):
    """
        resolve call stack

        @param: cstks: LIST: a list of debugtypes.Stack

        @return: LIST: a list of xrkmdStack
    """
    xrkmd_all = get_md_all()
    ret = []
    for i in range(len(cstks)):
        cstk = cstks[i]
        tmp = xrkmdStack(cstk)
        for md in xrkmd_all:
            if md.check_has_addr(cstk.calledfrom):
                assert md.base != 0
                tmp.set_xrkmd_info(md.name, md.get_md_name_chains(), md.base, md.sym_get(cstk.calledfrom))
        ret.append(tmp)
    return ret


def is_same_cstks(xrkcstks_1, xrkcstk2_2):
    """
        compare two xrkmdcstks

        @param: xrkcstks_1: LIST: a list of xrkmdStack
        @param: xrkcstk2_2: LIST: a list of xrkmdStack

        @return: BOOL: True if two stacks are same, False if otherwise
    """
    if len(xrkcstks_1) == len(xrkcstk2_2):
        for i in range(len(xrkcstks_1)):
            if xrkcstks_1[i].xrkmd_offset_calledfrom != xrkcstk2_2[i].xrkmd_offset_calledfrom:
                return False
        return True
    return False


def get_xrkmd_cstks():
    """
        @return: LIST: a list of xrkmdStack obj
    """
    return resolve_call_stack(xrkdbg.callStack())


def pt_call_stack():
    """
        print xrkmd call stack
    """
    xrkmd_cstks = resolve_call_stack(xrkdbg.callStack())
    if len(xrkmd_cstks) != 0:
        lines = []
        for xrkmd_cstk in xrkmd_cstks:
            lines.append("%s" % xrkmd_cstk)
        xrklog.infos(lines)
    else:
        xrklog.error("invalid call stack")


# -------------------------------------------------------------------------
# parse args
# -------------------------------------------------------------------------


#
# -u/--usage                                        # print usage
# -t/--test                                         # exec test method
# -l/--list                                         # list all xrkmd chains(names)
# -p/--path pe_1,sub_pe,sub_pe                      # pe name chains, split by ","
# -a/--action bp_remove/bp_remove_all               # operate on bp: remove by desc, or remove all
# -a/--action bp_tmp                                # set tmp bp by offset
# -a/--action hk_remove/hk_enable/hk_disable        # operate on hk by desc
# -a/--action pt                                    # print xrkmd details
# -a/--action desc_get                              # get feat at specifed offset(-o)
# -a/--action calc_offset                           # calc addr by offset: self.base + offset
# -a/--action re_apply                              # md re-apply everything
# -a/--action pt_cstk                               # print xrkmd call stack
# -a/--action goto/goto_mm                          # goto address by offset in disasm/memory window
# -d/--desc bp_desc_1,bp_desc_2,                    # target bp/hk desc, split by ","
#                                                   # "all" means all
# -o/--offset 0x123                                 # offset, can be hex or dec, can split by ","
# -f/--flag a,b,c,                                  # optional flags, split by ","
#


def __xrkmd_parse_args(args):
    pr = optlib.OptionParser(usage="xrkmd usage")

    cmn_group = optlib.OptionGroup(pr, "common group", "most commonly used options")
    cmn_group.add_option("-u", "--usage", dest="usage", action="store_true", help="print usage")
    cmn_group.add_option("-t", "--test", dest="test", action="store_true", help="exec test method")
    cmn_group.add_option("-l", "--list", dest="list", action="store_true", help="print list of all xrkmd chains")
    cmn_group.add_option("-p", "--path", dest="path", help="name chain of xrkmd to operate")
    cmn_group.add_option("-a", "--action", dest="action", help="action to take")
    cmn_group.add_option("-d", "--desc", dest="desc", help="desc of bp/hook to take operate on")
    cmn_group.add_option("-o", "--offset", dest="offset", default="0", help="offset of bp/hook to take operate on. this is HEX")
    cmn_group.add_option("-f", "--flag", dest="flag", help="optional flags")
    pr.add_option_group(cmn_group)

    return pr.parse_args(args=args)


def usage():
    """
        print usage
    """
    pass


def list():
    """
        list
    """
    lines = ["xrkmd list:"]
    k = get_xrkmd_cloud()
    for (d, x) in k.items():
        lines.append("xrkmdRoot: %s" % d)
        lines = lines + x.sub_md_get_names()
    xrklog.infos(lines, add_prefix=True)


def pt():
    """
        print all
    """
    lines = []
    k = get_xrkmd_cloud()
    for (d, x) in k.items():
        lines = lines + x.get_details_strs()
    xrklog.infos(lines)


def xrkmd_exec_args(args):
    """
        parse args and take actions
    """
    if len(args) == 0:
        xrklog.error("no param, -u/--usage for usage")
        return False

    try:
        opts, args_remain = __xrkmd_parse_args(args)

        if opts.usage:
            xrklog.highlight("xrkmd usage...")
            usage()
        if opts.test:
            xrklog.highlight("xrkmd test...")
            test()
        if opts.list:
            xrklog.highlight("xrkmd list...")
            list()
        if opts.path:
            action = opts.action
            desc = opts.desc
            offset = opts.offset is None and None or int(opts.offset, 16)
            md = get_md_by_name_chains(opts.path.split(","))
            if md is not None:
                # -------------------------------------------------------------------------
                # bp
                if action == "bp_add" or action == "bp_enable":
                    md.bp_enable(desc)
                elif action == "bp_remove":
                    md.bp_remove(desc)
                elif action == "bp_remove_all":
                    md.bp_remove_all()
                elif action == "bp_disable":
                    md.bp_disable(desc)
                elif action == "bp_disable_all":
                    md.bp_disable_all()
                elif action == "bp_tmp":
                    md.bp_tmp(offset)
                # -------------------------------------------------------------------------
                # hook
                elif action == "hk_remove":
                    pass
                # -------------------------------------------------------------------------
                # misc
                elif action == "pt":
                    md.pt()

                elif action == "desc_get":
                    ret_list = md.get_desc_by_offset(offset)
                    if ret_list is not None:
                        xrklog.high("desc for xrkmd %s at offset %.8X:" % (md.name, offset))
                        for i in range(len(ret_list)):
                            x = ret_list[i]
                            xrklog.info("%d - %d - %s" % (x[1], x[2], x[0]))

                elif action == "calc_offset":
                    if offset != 0 and md.check_offset_valid(offset):
                        xrklog.high("%.8X + %.8X = %.8X" % (md.base, offset, md.base + offset), add_prefix=True)
                        xrkdbg.gotoDisasmWindow(md.base + offset)
                    else:
                        xrklog.error("invalid offset for xrkmd: %s - %.8X" % (md.name, offset), add_prefix=True)

                elif action == "re_apply":
                    md.re_apply_settings()

                elif action == "goto":
                    xrkdbg.gotoDisasmWindow(md.base + offset)

                elif action == "goto_mm":
                    xrkdbg.gotoDumpWindow(md.base + offset)

                # -------------------------------------------------------------------------
                # invalid
                else:
                    xrklog.error("invalid action %s" % action, add_prefix=True)

                # !+ udpate to cloud
                update_md(md)
            else:
                xrklog.error("invalid xrkmd name chains: %s" % opts.path, add_prefix=True)
        # -------------------------------------------------------------------------
        # action that require no xrkmd
        # -------------------------------------------------------------------------
        elif opts.action == "pt":
            xrklog.highlight("xrkmd print xrkmd details")
            pt()
        elif opts.action == "pt_cstk":
            xrklog.highlight("xrkmd print call stack")
            pt_call_stack()
        # -------------------------------------------------------------------------
        # invalid
        else:
            xrklog.error("no path")

        return True

    except Exception, e:
        log = []
        log.append("xrkmd parse args exception, plase check your params")
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


def xrkmd_exec_args_str(args_str):
    return xrkmd_exec_args(args_str.split(" "))


# -------------------------------------------------------------------------
# main
# -------------------------------------------------------------------------


class xxHook(BpHook):
    def __init__(self):
        BpHook.__init__(self)

    def run(self, regs):
        assert False


def test():
    md = get_md_root_only("pe_1_root")
    if md is not None and md.check_base_valid():
        v1 = xrkdbg.readLong(md.base + 0xA2830)
        v2 = xrkdbg.readLong(md.base + 0xA1B24)
        v3 = xrkdbg.readLong(md.base + 0xA1B28)
        v = v1 + (v2 ^ v3)
        xrklog.high("s0: %.8X" % v, add_prefix=True)


#
# !+ this bp/hook thing might not work, if "old" bp/hook didn't successfully removed.
#


def main(args):

    xrkmd_exec_args(args)
    return "xrkmd finish"
