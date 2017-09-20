# -*- coding: utf-8 -*-

"""
anything else
"""

import os
import re
import sys
import time
import socket
import struct
import random
import urllib
import urllib2
import hashlib
import _winreg
import chardet
import inspect
import traceback
from ctypes import c_uint16, c_uint32


try:
    import xrklog
    import xrkdbg
except:
    this_path = os.path.split(os.path.realpath(inspect.stack()[-1][1]))[0]
    sys.path.append(this_path)
    try:
        import xrklog
        import xrkdbg
    except Exception, e:
        lines = ["xrkutil import error: %s" % e]
        error = traceback.format_exc()
        while len(error) > 200:
            tmp = error[:200]
            lines.append("  %s" % tmp)
            error = error[200:]
        lines.append("  %s" % error)
        try:
            import immlib as dbglib
            dbg = dbglib.Debugger()
            for line in lines:
                dbg.log(line)
        except:
            for line in lines:
                print line

        assert False


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------

def test():
    xrkdbg.log("*" * 100, highlight=1)
    xrkdbg.log("this is test from xrkutil", highlight=1)
    xrkdbg.log("*" * 100, highlight=1)


# ---------------------------------------------------------------------------
# from immutils.py
# ---------------------------------------------------------------------------


def check_bits_consistancy(bits):
    assert not bits % 8, "bits should be sizeof(char) aligned, got %d" % bits


def dInt(sint):
    """
    Turns sint into an int, hopefully
    python's int() doesn't handle negatives with base 0 well
    """
    if sint is None or type(sint) in [type((1, 1)), type([1]), type({})]:
        # devlog("Type ERROR: dInt(%s)!"%str(sint))
        # should we call bugcheck here?
        # raise TypeError, "type %s for dInt(%s)" % (type(sint), str(sint))
        raise TypeError("type %s for dInt(%s)" % (type(sint), str(sint)))

    s = str(sint)
    if s[0:2] == "0x":
        return long(s, 0)
    else:
        # if you have long("5.0") it throws a horrible exception
        # so we convert to float and then back to long to avoid this
        return long(float(s))


def uint_bits(bits, c):
    # WARNING i dunno if dInt is safe here
    c = dInt(c)
    # [Python < 2.4] FutureWarning: x<<y losing bits or changing sign will return a long in Python 2.4 and up
    # [Python < 2.4] 1 << 32 = 0
    # so we force python < 2.4 to use a long.
    return c & ((long(1) << bits) - 1)


def split_int_bits(bits, i):
    check_bits_consistancy(bits)
    # we cast to uint_bits here to be sure to return (bits/8) x uint8
    u = uint_bits(bits, i)
    r = []
    for b in range(0, bits, 8):
        r += [(u >> (bits - (b + 8))) & 0xff]
    return r


def int2list_bits(bits, i, swap=0):
    check_bits_consistancy(bits)
    l = split_int_bits(bits, i)
    # devlog("int2list: l = %s" % l)
    lc = []
    for n in l:
        # devlog("int2list: n = 0x%x" % n)
        lc += [chr(n)]
    if swap:
        lc.reverse()
    return lc


def int2str_bits(bits, i, swap=0):
    check_bits_consistancy(bits)
    return "".join(int2list_bits(bits, i, swap=swap))


def int2str32(int32, swap=0):
    return int2str_bits(32, int32, swap=swap)


def int2str16(int16, swap=0):
    return int2str_bits(16, int16, swap=swap)


def int2str32_swapped(int32):
    return int2str_bits(32, int32, swap=1)


def int2str16_swapped(int16):
    return int2str_bits(16, int16, swap=1)


# ---------------------------------------------------------------------------
# util
# ---------------------------------------------------------------------------


def log_lines(lines, addr=0xbadf00d, highlight=False, gray=False, verbose=False):
    """
        xrkdbg.log for 1st line
        xrkdbg.logLines for other lines

        @param: lines     : LIST : a list of strings to print
        @param: addr      : INT  : address
        @param: highlight : BOOL : is print red
        @param: gray      : BOOL : is print white
        @param: verbose   : BOOL : is verbose log

        !+ TODO: check if __APP_NAME__ == IMM
        !+ TODO: flag: verbose, shall work
    """
    for i in range(len(lines)):
        if i == 0:
            try:
                xrkdbg.log(lines[i], addr=addr, highlight=highlight, gray=gray)
            except:
                xrkdbg.log("(excep)" + buf_to_str(lines[i]), addr=addr, highlight=highlight, gray=gray)
        else:
            try:
                xrkdbg.logLines(lines[i], highlight=highlight, gray=gray)
            except:
                xrkdbg.logLines("(excep)" + buf_to_str(lines[i]), highlight=highlight, gray=gray)


def cstk():
    """
        print python call stack

        !+ this is python call stack, not debugee call stack
    """
    xrklog.high(traceback.format_exc(), add_prefix=False)


def time_str():
    """
        time string in this format: xx

        @return: STRING :
    """
    return time.strftime('%Y%m%d_%H_%M_%S', time.localtime(time.time()))


def rand_str():
    """
        random string in this format: xx

        @return: STRING :
    """
    return "%d_%d_%d" % (random.randint(10, 99), random.randint(10, 99), random.randint(10, 99))


def time_rand_str():
    """
        xx
    """
    return time_str() + "_" + rand_str()


def value_desc(value):
    """
        to_str

        !+ ret must be 1 line string.
    """
    if value is None:
        return "NoneType"

    type_ = type(value)
    if type_ == type:
        return "Type"
    if type_ == str:
        try:
            return "\"%s\"" % value
        except:
            return buf_to_str(value)
    if type_ == int or type_ == long:
        return "0x%.8X" % value
    if type_ == float:
        return "%.8f" % value
    if type_ is bool:
        return "%s" % value
    if type_ == list:
        if len(value) == 0:
            return "empty list"
        return ', '.join('%s' % value_desc(v) for v in value)
        # return "%s" % value
    if type_ == dict:
        if len(value) == 0:
            return "empty dict"
        # ---------------------------------------------------------------------------
        # return must be 1 line string, so, we're not returing a table here.
        # inner table
        # return get_dict_as_table(value)
        # ---------------------------------------------------------------------------
        lines = []
        for (d, x) in value.items():
            # ---------------------------------------------------------------------------
            # no \t here, which would make table output ugly
            # ---------------------------------------------------------------------------
            lines.append("%s: %s, " % (value_desc(d), value_desc(x)))
        return '; '.join('%s' % line for line in lines)
    if type_ == tuple:
        if len(value) == 0:
            return "empty tuple"
        return ', '.join('%s' % value_desc(v) for v in value)

    if "instance" in str(type_):
        return "obj: %s" % str(value)

    xrklog.highlight("invalid value type: %s" % type(value))
    # assert here to check call stack
    assert False
    return type(value)


def value_type_desc(value):
    """
        value type to_str

        !+ ret must be 1 line string.
    """
    if type(value) == dict:
        lines = []
        for (d, x) in value.items():
            # ---------------------------------------------------------------------------
            # no \t here, which would make table output ugly
            # ---------------------------------------------------------------------------
            lines.append("%s: %s, " % (value_desc(d), value_type_desc(x)))
        return "dict: " + ''.join('%s' % line for line in lines)
    else:
        return "%s" % type(value).__name__


def validate_addr(addr):
    return xrkdbg.getMemoryPageByAddress(addr) is not None


def int2str8(int8, swap=0):
    return int2str_bits(8, int8, swap=swap)


def int2str8_swap(int8):
    return int2str_bits(8, int8, swap=1)


def log_call_tree():
    """
        print call tree
    """
    """
    eip = xrkdbg.getRegs()["EIP"]
    tree = dbg.getCallTree(eip)
    xrkdbg.log("call tree: ", highlight=1)
    for s in tree:
        xrkdbg.logLines("%s" % s, highlight=1)
    """
    pass


def write_to_file(buf, len, p1, ps=""):
    """
    write to file
    """
    pass


def write_to_new_file(file_name, lines):
    """
        create new file/clean existing one, write lines to it
    """
    # "w": if file exists, clean first, then open
    f = open(file_name, "w")
    f.writelines(lines)
    f.close()


def add_to_set(s, value):
    """
        add to set if value not exist in set

        @return: tuple
    """
    if value is not None and value not in s:
        s.append(value)
        return s, True
    return s, False


def merge_list(l1, l2):
    """
        merge

        @return: tuple
    """
    assert l1 is not None
    assert l2 is not None
    is_changed = False
    for l in l2:
        if l not in l1:
            l1.append(l)
            is_changed = True
    return l1, is_changed


def exclude_list(l1, l2):
    """
        exclude l2 from l1

        @return: tuple
    """
    assert l1 is not None
    assert l2 is not None
    is_changed = False
    for l in l1:
        if l in l2:
            l1.remove(l)
            is_changed = True
    return l1, is_changed


def exclude_keys_dict(dict_, exclude_keys=[]):
    """
        @return: tuple
    """
    if len(exclude_keys) == 0:
        return dict_, False
    is_changed = False
    ret = {}
    for (d, x) in dict_.items():
        if d not in exclude_keys:
            ret[d] = x
            is_changed = True
    return ret, is_changed


def update_dict(dict_, pairs):
    """
        update dict

        !+ only check first level(specifically for inner dict/list)

        @return: tuple
    """
    is_changed = False
    for (d, x) in pairs.items():
        if d in dict_.keys():
            # compare with !=, whatever type it is
            if dict_[d] != x:
                dict_[d] = x
                is_changed = True
        else:
            dict_[d] = x
            is_changed = True
    return dict_, is_changed


def update_dict_directly(dict_, pairs):
    for (d, x) in pairs.items():
        dict_[d] = x
    return dict_


def check_list(list1, list2):
    """
        check if two list has same contents

        !+ only check first level, and can only check first level.
        !+ no deep levels, because u don't know who to compare with
    """
    for l in list1:
        if l not in list2:
            return False
    for l in list2:
        if l not in list1:
            return False
    return True


def check_dict(dict1, dict2):
    """
        check if dict same

        !+ only check first level(specifically for inner dict/list)
    """
    for (d, x) in dict1.items():
        if d not in dict2:
            return False
    for (d, x) in dict2.items():
        if d not in dict1:
            return False
    for (d, x) in dict1.items():
        if dict1[d] != dict2[d]:
            return False
    return True


def check_dict_deep(dict1, dict2):
    """
        check if dict same

        !+ check inner dict/list recursivelly
    """
    for (d, x) in dict1.items():
        if d not in dict2:
            return False
    for (d, x) in dict2.items():
        if d not in dict1:
            return False
    for (d, x) in dict1.items():
        if type(x) == dict and not check_dict_deep(dict1[d], dict2[d]):
            return False
        elif type(x) == list and not check_list(dict1[d], dict2[d]):
            return False
        else:
            if dict1[d] != dict2[d]:
                return False
    return True


def update_dict_deep(dict_, pairs):
    """
        update dict

        !+ check inner dict/list recursivelly
    """
    is_changed = False
    for (d, x) in pairs.items():
        if d in dict_.keys():
            if type(x) == dict and not check_dict_deep(dict_[d], pairs[d]):
                dict_[d] = x
                is_changed = True
            elif type(x) == list and not check_list(dict_[d], pairs[d]):
                dict_[d] = x
                is_changed = True
            else:
                if dict_[d] != x:
                    dict_[d] = x
                    is_changed = True
        else:
            dict_[d] = x
            is_changed = True
    return dict_, is_changed


def x_contains(str_slices, tar_str1, tar_str2=None, tar_str3=None):
    for str_ in str_slices:
        if str_ in tar_str1 or tar_str1 in str_:
            return True
        elif tar_str2 is not None:
            if str_ in tar_str2 or tar_str2 in str_:
                return True
        elif tar_str3 is not None:
            if str_ in tar_str3 or tar_str3 in str_:
                return True
        continue
    return False


def x_contains_int(int_slices, int1, int2=None, int3=None):
    if int1 in int_slices:
        return True
    if int2 is not None and int2 in int_slices:
        return True
    if int3 is not None and int3 in int_slices:
        return True
    return False


def obj_inst_or_list_to_list(obj, type_str=str):
    """
        convert obj or list to list.
    """
    if isinstance(obj, type_str):
        obj = list(obj)
    return obj is list and obj or [obj]


def check_has_module(name):
    """
        check has module by name, ignore case sensitive.
        by default, imm modules keys check case sensitive

        !+ but, xrkdbg.getAddress() can work with both.

        !+ this alone, takes 400 msecs
    """
    mds = xrkdbg.getAllModules().keys()
    for md in mds:
        if md.lower() == name.lower():
            return True
    # xrklog.error("check has no module: %s" % name, verbose=True)
    return False


def pause(regs=None):
    """
        TODO: for now, set bp at next instruction. this should change
    """
    set_bp_at_next_instruction(regs=regs)


def addr_desc(addr):
    return addr_to_str(addr)


def check_is_hex_num_str(str_):
    return re.match(r"\b[0-9a-fA-F]+\b", str_) is not None


def get_floss_strs(md_name=None, is_static=True, is_stack=False, is_decode=False):
    """
        use FLOSS to get strings

        from floss import main as fm
        fm.main(["", r"c:\\pahaim.sys_"])

        for stack string, get funcs, etc.
    """
    pass


def get_md_name_by_addr(addr):
    md = xrkdbg.getModuleByAddress(addr)
    if md is not None:
        md_name = md.name
        assert "." in md_name
        splits = md_name.split(".")
        assert len(splits) == 2
        return splits[0]
    return None


def check_has_hook(desc):
    """
        check has specified hook by desc

        !+ actually, there is a bug in xrkdbg.listHooks().
        !+ if i add "a" and "aa" to hook, xrkdbg.listHooks() will only return "a"
    """
    return desc in xrkdbg.listHooks()
    """
    for hk in xrkdbg.listHooks():
        if desc == hk:
            return True
    return False
    """


def get_mds_eats(md_names):
    """
        get all exports of all mds

        @return: DICT: {md_name1: {"oep": 0x123,
                                   "func1": 0x234,
                                   "func2": 0x345},
                        md_name2: {"oep": 0x456,
                                   "func3": 0x567,
                                   "func4": 0x678}}

        !+ module shall be loaded already.
        !+ md_name shall be valid, like: kernel32.dll. if md_name == "kernel32", then this is invalid, will cause exception
    """
    if xrkdbg.getStatus() != 0:
        ret = {}
        for md_name in md_names:
            # mn_mod = xrkmona.MnModule(md_name)
            mn_mod = None
            if mn_mod is not None:
                """
                    eats structure: {0x123: ABC,
                                     0x234: BCD}
                    convert it to: {ABC: 0x123,
                                    BCD: 0x234}
                """
                ret_md = {}
                ret_md["oep"] = mn_mod.moduleEntry
                eats = mn_mod.getEAT()
                for (d, x) in eats.items():
                    ret_md[x] = d
                ret[md_name] = ret_md
            else:
                xrklog.error("invalid module name: %s" % md_name)
        return ret
    else:
        xrklog.error("dbg status is None....")
        return None


def get_evt_type(evt):
    """
        from libevent.py
    """
    if evt.isCreateProcess():
        return "CREATE_PROCESS_DEBUG_EVENT"
    if evt.isCreateThread():
        return "CREATE_THREAD_DEBUG_EVENT"
    if evt.isException():
        return "EXCEPTION_DEBUG_EVENT"
    if evt.isExitProcess():
        return "EXIT_PROCESS_DEBUG_EVENT"
    if evt.isExitThread():
        return "EXIT_THREAD_DEBUG_EVENT"
    if evt.isLoadDll():
        return "LOAD_DLL_DEBUG_EVENT"
    if evt.isOutputDebugString():
        return "OUTPUT_DEBUG_STRING_EVENT"
    if evt.isUnloadDll():
        return "UNLOAD_DLL_DEBUG_EVENT"
    if evt.isRipEvent():
        return "RIP_EVENT"
    return "UNKNOWN_EVENT"


def get_debugeed_file_path():
    """
        get debugeed file path
    """
    return xrkdbg.getModule(xrkdbg.getDebuggedName()).getPath()


def get_debugeed_parent_path():
    """
        get debugeed parent folder path
    """
    return os.path.dirname(get_debugeed_file_path())


def gen_debugeed_file_x_path(tail=""):
    """
        gen a path that in the same dir with debugeed, starts with debugeed name, but end with something else
    """
    return "%s%s" % (os.path.splitext(get_debugeed_file_path())[0], tail)


def strip_str(str_, has__=True, has_at=True, has_q=True):
    """
        strip string

        @param: has__:      _
        @param: has_at:     @
        @param: has_q:      ?

        !+ this is not elegent, i know...
    """
    str_ = str_.strip()
    if not has__:
        str_ = str_.strip("_")
    if not has_q:
        str_ = str_.strip("?")
    if not has_at:
        str_ = str_.strip("@")
    str_ = str_.strip()
    if not has__:
        str_ = str_.strip("_")
    if not has_q:
        str_ = str_.strip("?")
    if not has_at:
        str_ = str_.strip("@")
    return str_


def get_first_retn_addr(addr_start, max_opcode=1000):
    """
        get first addr that is "retn"
    """
    addr_tmp = addr_start
    for i in range(max_opcode):
        code = xrkdbg.disasmCode(addr_tmp)
        if code.isRet():
            return addr_tmp
        addr_tmp = addr_tmp + code.getSize()
    return None


def set_bp_may_pause(addr, is_pause):
    if is_pause:
        xrkdbg.setBreakpoint(addr)
    else:
        xrkdbg.setLoggingBreakpoint(addr)


def check_has_bp(addr):
    """
        TODO
    """
    return True


def get_name_by_handle(handle):
    """
        get name by handle

        @return: STRING, or None
    """
    hs = xrkdbg.getAllHandles()
    if handle in hs:
        ret = hs[handle].nativename
        if ret is not None and len(ret) != 0:
            return ret
    return None


def get_all_executable_pages_but_no_lib():
    """
        get all pages that can execute, but belongto no lib

        @return: DICT: {page_base_1: page_obj_1, page_base_2: page_obj_2, ...}
    """
    ret = {}
    pages = xrkdbg.getMemoryPages()
    for (d, x) in pages.items():
        access = x.access
        # PAGE_EXECUTE 0x10
        # PAGE_EXECUTE_READ 0x20
        # PAGE_EXECUTE_READWRITE 0x40
        # PAGE_EXECUTE_WRITECOPY 0x80
        if (access & 0x10) or (access & 0x20) or (access & 0x40) or (access & 0x80):
            md = xrkdbg.getModuleByAddress(x.getBaseAddress())
            if md is None:
                ret[d] = x
    return ret

# ---------------------------------------------------------------------------
# mm search
# ---------------------------------------------------------------------------


def get_v_from_mm_slice(mm_slice, offset, v_len=4):
    """
        get v_len integer from mm_slice by offset

        @param: mm_slice: a range of memory
        @param: offset: INT: can not be None.
        @param: v_len: INT: value lenght, default 4(int32)
    """
    assert offset is not None
    assert len(mm_slice) >= (offset + v_len)
    if v_len == 4:
        v = struct.unpack('<L', mm_slice[offset:offset + v_len])[0]
        v = c_uint32(v).value
    elif v_len == 2:
        v = struct.unpack('<h', mm_slice[offset:offset + v_len])[0]
        v = c_uint16(v).value
    elif v_len == 1:
        v = ord(mm_slice[offset:offset + v_len])
    else:
        assert False
    return v


def get_v_from_mm_slice_list(mm_slice_list, offset, v_len=4):
    """
        get value from a list of mm slices. all results shall be the same

        @param: offset: can't be None
    """
    assert offset is not None
    if len(mm_slice_list) == 0:
        # xrklog.error("mm_slice_list is empty", verbose=True)
        return None
    elif len(mm_slice_list) != 1:
        ret = 0
        for mm_slice in mm_slice_list:
            v = get_v_from_mm_slice(mm_slice, offset, v_len=v_len)
            if ret == 0:
                ret = v
                assert ret != 0
            else:
                if ret != v:
                    # xrklog.error("not same value from mm slices list: %.8X vs %.8X" % (ret, v), verbose=True)
                    # assert False
                    return None
        return ret
    else:
        return get_v_from_mm_slice(mm_slice_list[0], offset, v_len=v_len)


def search_str_in_mm(str_, mm, base=0):
    """
        search solid string in a range of memory

        @return: LIST: a list of mm offsets/address

        !+ dict key is offset or address depend on value of param base.
           if u need mm slices, don't set base
    """
    ret = []
    """
    for i in range(len(mm)):
        if mm[i:].startswith(str_):
            ret.append(i)
    """
    offset = 0
    mm_slices = mm.split(str_)
    for i in range(len(mm_slices)):
        offset = offset + len(mm_slices[i])
        if offset == len(mm) or offset + len(str_) == len(mm):
            break
        ret.append(offset + base)
        offset = offset + len(str_)
    return ret


def split_mm_into_slices(splitter_str, mm, slice_len=0, base=0):
    """
        split a range of memory into slices, by splitter_str. each slice has length of slice_len

        @return: DICT: a dict of slices: {off1/addr1: mm_slice1, off2/addr2: mm_slice2}

        !+ dict key is offset or address depend on value of param base.
    """
    slice_len = slice_len != 0 and slice_len or len(splitter_str)
    ret = {}
    # set base as 0, because we need mm slices
    offsets = search_str_in_mm(splitter_str, mm, base=0)
    for offset in offsets:
        if len(mm) - offset >= slice_len:
            ret[offset + base] = mm[offset:offset + slice_len]
    return ret


# -------------------------------------------------------------------------
# search function
# -------------------------------------------------------------------------


def get_desc_list_len(desc_list):
    ret = 0
    for desc in desc_list:
        if type(desc) == str:
            ret = ret + len(desc)
        elif type(desc) == int or type(desc) == long:
            ret = ret + desc
    return ret


#
# mm
#


def search_desc_list_in_mm(desc_list, mm, base=0):
    """
        search desc list in mm

        @return: DICT: a dict of slices: {off1/addr1: mm_slice1, off2/addr2: mm_slice2}

        !+ dict key is offset or address depend on value of param base.
    """
    assert len(desc_list) != 0 and type(desc_list[0]) is str
    cmp_index = len(desc_list[0])
    mm_dict = split_mm_into_slices(desc_list[0], mm, slice_len=get_desc_list_len(desc_list), base=base)
    for i in range(len(desc_list)):
        if i != 0:
            desc = desc_list[i]
            # not found in this mm
            if len(mm_dict) == 0:
                break
            if type(desc) == str:
                # whether d is offset or address, don't matter
                for (d, x) in mm_dict.items():
                    assert cmp_index < len(x)
                    if not x[cmp_index:].startswith(desc):
                        mm_dict.pop(d)
                cmp_index = cmp_index + len(desc)
            elif type(desc) == int or type(desc) == long:
                cmp_index = cmp_index + desc
            else:
                assert False
    return mm_dict


def search_sd_in_mm(sd, mm, base=0):
    """
        search sd in range of memory

        @param: sd: mmSearchDescriptor

        @return: DICT: a dict of slices: {off1/addr1: mm_slice1, off2/addr2: mm_slice2}

        !+ dict key is offset or address depend on value of param base.
    """
    return search_desc_list_in_mm(sd.desc_list, mm, base=base)


def search_desc_list_dict_in_mm(desc_list_dict, mm, base=0):
    """
        @param: desc_list_dict: a dict of desc_list: {"desc_1": desc_list_1, "desc_2": desc_list_2, ...}

        @return: DICT of DICT: {"desc_1": addr_mm_dict_1, "desc_2": addr_mm_dict_2, ...}
    """
    ret = {}
    for (d, x) in desc_list_dict.items():
        ret[d] = search_desc_list_in_mm(x, mm, base=base)
    return ret


#
# page
#


def search_desc_list_in_pages(desc_list, pages):
    """
        search desc list in specified mm pages

        @param: pages: DICT: {addr: MemoryPage, addr: MemoryPage,}

        @return: DICT: a dict of slices: {addr1: mm_slice1, addr2: mm_slice2}
    """
    ret = {}
    for (addr, page) in pages.items():
        tmp = search_desc_list_in_mm(desc_list, page.getMemory(), base=page.getBaseAddress())
        ret = dict(ret.items() + tmp.items())
    return ret


def search_desc_list_dict_in_pages(desc_list_dict, pages):
    """
        @param: desc_list_dict: a dict of desc_list: {"desc_1": desc_list_1, "desc_2": desc_list_2, ...}
        @param: pages: DICT: {addr: MemoryPage, addr: MemoryPage,}

        @return: DICT of DICT: {"desc_1": addr_mm_dict_1, "desc_2": addr_mm_dict_2, ...}
    """
    ret = {}
    for (addr, page) in pages.items():
        tmp = search_desc_list_dict_in_mm(desc_list_dict, page.getMemory(), base=page.getBaseAddress())
        for (d, x) in tmp.items():
            if d not in ret:
                ret[d] = {}
            if x is not None and len(x) != 0:
                ret[d] = dict(ret[d].items() + x.items())
    return ret


def search_sd_in_pages(sd, pages):
    """
        search sd in specified mm pages

        @param: sd: mmSearchDescriptor
        @param: pages: DICT: {addr: MemoryPage, addr: MemoryPage,}

        @return: DICT: a dict of slices: {addr1: mm_slice1, addr2: mm_slice2}
    """
    return search_desc_list_in_pages(sd.desc_list, pages)


#
# module
#


def search_desc_list_dict_in_module(desc_list_dict, md_name=None):
    """
        @param: desc_list_dict: a dict of desc_list: {"desc_1": desc_list_1, "desc_2": desc_list_2, ...}

        @return: DICT of DICT: {"desc_1": addr_mm_dict_1, "desc_2": addr_mm_dict_2, ...}
    """
    if md_name is not None:
        md = xrkdbg.getModule(md_name)
        if md is not None:
            mm = xrkdbg.readMemory(md.getBase(), md.getSize())
            return search_desc_list_dict_in_mm(desc_list_dict, mm, base=md.getBase())
        else:
            xrklog.error("search desc list dict in module, invalid module: %s" % md_name)
            return None
    else:
        # search from all pages
        return search_desc_list_dict_in_pages(desc_list_dict, xrkdbg.getMemoryPages())


def search_desc_list_in_modules(desc_list, md_name=None):
    """
        search desc list in specified module

        @param: md_name: if None, search all memory pages

        @return: DICT: a dict of slices: {addr1: mm_slice1, addr2: mm_slice2}
    """
    tmp = search_desc_list_dict_in_module({time_str(): desc_list}, md_name=md_name)
    return tmp.values()[0]


def search_sd_in_module(sd, md_name=None):
    """
        search sd in specified module

        @param: sd: mmSearchDescriptor
        @param: md_name: if None, search all memory pages

        @return: DICT: a dict of slices: {addr1: mm_slice1, addr2: mm_slice2}
    """
    return search_desc_list_in_modules(sd.desc_list, md_name=md_name)


#
# main module
#


def search_desc_list_in_main_module(desc_list):
    """
        search desc list in main module

        @return: DICT: a dict of slices: {addr1: mm_slice1, addr2: mm_slice2}
                 None
    """
    return search_desc_list_in_modules(desc_list, xrkdbg.getDebuggedName())


def search_desc_list_dict_in_main_module(desc_list_dict):
    """
        @param: desc_list_dict: a dict of desc_list: {"desc_1": desc_list_1, "desc_2": desc_list_2, ...}

        @return: DICT of DICT: {"desc_1": addr_mm_dict_1, "desc_2": addr_mm_dict_2, ...}
    """
    return search_desc_list_dict_in_module(desc_list_dict, xrkdbg.getDebuggedName())


def search_sd_in_main_module(sd):
    """
        search sd in main module

        @return: DICT: a dict of slices: {addr1: mm_slice1, addr2: mm_slice2}
                 None
    """
    return search_desc_list_in_main_module(sd.desc_list, xrkdbg.getDebuggedName())


# ---------------------------------------------------------------------------
# load file
# ---------------------------------------------------------------------------


def load_file(file_name):
    """
        alloc mm in debugee, load file content to allocated mm, return mm addr
    """
    size = os.path.getsize(file_name)
    f = open(file_name, "rb")
    if size != 0 and f is not None:
        buf_mm = xrkdbg.remoteVirtualAlloc(size)
        assert buf_mm != 0
        buf_f = f.read()
        f.close()
        xrkdbg.writeMemory(buf_mm, buf_f)
        xrkdbg.log("mm loaded for file, mm: 0x%X, file: %s" % (buf_mm, file_name), highlight=1)
        return buf_mm, size
    xrkdbg.log("load file, param invalid: %s" % file_name, highlight=1)
    return 0, 0


def load_file_ex(file_name):
    """
        load file, but also return page obj
    """
    buf, size = load_file(file_name)
    if buf != 0:
        return buf, size, xrkdbg.getMemoryPages()[buf]
    return 0, 0, None


# -------------------------------------------------------------------------
# log memory buffer
# -------------------------------------------------------------------------


def buf_decode(buf, code="utf-8"):
    """
        buf decode
    """
    ret = ""
    for c in buf:
        try:
            ret = ret + c.decode(code)
        except:
            ret = ret + "."
    return c


def buf_to_str(buf, col_len=16):
    """
        1 line, unlimited length
    """
    if col_len != 0:
        buf = len(buf) >= col_len and buf[:col_len] or buf
    return ' '.join('%02X' % ord(c) for c in buf)


def buf_to_str_with_0x(buf, col_len=16):
    """
        1 line
    """
    if col_len != 0:
        buf = len(buf) >= col_len and buf[:col_len] or buf
    return ''.join('\\x%02X' % ord(c) for c in buf)


def buf_to_str_with_decode(buf):
    """
        1 line
    """
    c1 = buf_to_str(buf)
    """
    c2 = buf_decode(buf)
    c3 = buf_decode(buf, "utf-16")
    return c1 + "    " + c2 + "    " + c3
    """
    return c1


def buf_to_str_with_0x_with_decode(buf):
    """
        1 line
    """
    c1 = buf_to_str_with_0x(buf)
    """
    c2 = buf_decode(buf)
    c3 = buf_decode(buf, "utf-16")
    return c1 + "    " + c2 + "    " + c3
    """
    return c1


def buf_to_str_rows(buf, cbk_row=buf_to_str, col_len=16):
    """
        rows

        @return: LIST: a list of string
    """
    len_ = len(buf)
    if len_ <= col_len:
        return [cbk_row(buf)]
    else:
        ret = []
        rows = 0
        if len_ % col_len == 0:
            rows = len_ / col_len
        else:
            rows = len_ / col_len + 1
        last_row_len = len_ - (rows - 1) * col_len
        for i in range(rows):
            start = i * col_len
            end = 0
            if i == rows - 1:
                end = start + last_row_len
            else:
                end = start + col_len
            buf_ = buf[start:end]
            ret.append(cbk_row(buf_))
        return ret


def buf_to_str_with_0x_rows(buf, col_len=16):
    """
        rows
    """
    return buf_to_str_rows(buf, buf_to_str_with_0x, col_len)


def buf_to_str_with_decode_rows(buf, col_len=16):
    """
        rows
    """
    return buf_to_str_rows(buf, buf_to_str_with_decode, col_len)


def buf_to_str_with_0x_with_decode_rows(buf, col_len=16):
    """
        rows
    """
    return buf_to_str_rows(buf, buf_to_str_with_0x_with_decode, col_len)


def addr_to_str(addr, len_=16):
    """
        xx
    """
    if validate_addr(addr):
        buf = xrkdbg.readMemory(addr, len_)
        return buf_to_str(buf)
    else:
        return None


def addr_to_str_with_0x(addr, len_=16):
    """
        xx
    """
    if validate_addr(addr):
        buf = xrkdbg.readMemory(addr, len_)
        return buf_to_str_with_0x(buf)
    else:
        return None


def addr_to_str_with_decode(addr, len_=16):
    """
        xx
    """
    if validate_addr(addr):
        buf = xrkdbg.readMemory(addr, len_)
        return buf_to_str_with_decode(buf)
    else:
        return None


def addr_to_str_with_0x_with_decode(addr, len_=16):
    """
        xx
    """
    if validate_addr(addr):
        buf = xrkdbg.readMemory(addr, len_)
        return buf_to_str_with_0x_with_decode(buf)
    else:
        return None


def addr_to_str_rows(addr, len_=16, col_len=16):
    """
        len_ better be less than 16
    """
    if validate_addr(addr):
        buf = xrkdbg.readMemory(addr, len_)
        return buf_to_str_rows(buf, col_len=col_len)
    else:
        return None


def addr_to_str_with_0x_rows(addr, len_=16, col_len=16):
    """
        x
    """
    if validate_addr(addr):
        buf = xrkdbg.readMemory(addr, len_)
        return buf_to_str_with_0x_rows(buf, col_len=col_len)
    else:
        return None


def addr_to_str_with_decode_rows(addr, len_=16, col_len=16):
    """
        len_ better be less than 16
    """
    if validate_addr(addr):
        buf = xrkdbg.readMemory(addr, len_)
        return buf_to_str_with_decode_rows(buf, col_len=col_len)
    else:
        return None


def addr_to_str_with_0x_with_decode_rows(addr, len_=16, col_len=16):
    """
        x
    """
    if validate_addr(addr):
        buf = xrkdbg.readMemory(addr, len_)
        return buf_to_str_with_0x_with_decode_rows(buf, col_len=col_len)
    else:
        return None


def pt_strs_rows(strs, addr=0, comment=None, line_prefix=None):
    """
        pt x
    """
    assert len(strs) != 0
    if comment is None or len(comment) == 0:
        comment = ""

    if validate_addr(addr):
        xrkdbg.log(comment, highlight=1, addr=addr)
    else:
        xrkdbg.log(comment, highlight=1)

    for str_ in strs:
        if line_prefix is not None and len(line_prefix) != 0:
            xrkdbg.logLines("%s    %s" % (line_prefix, str_), highlight=1)
        else:
            xrkdbg.logLines("%s" % str_, highlight=1)


def pt_addr_to_str_rows(addr, len_=16, col_len=16, comment=None, line_prefix=None):
    """
        pt x
    """
    strs = addr_to_str_rows(addr, len_, col_len)
    pt_strs_rows(strs, addr=addr, comment=comment, line_prefix=line_prefix)


def pt_addr_to_str_with_0x_rows(addr, len_=16, col_len=16, comment=None, line_prefix=None):
    """
        pt x
    """
    strs = addr_to_str_with_0x_rows(addr, len_, col_len)
    pt_strs_rows(strs, addr=addr, comment=comment, line_prefix=line_prefix)


def pt_addr_to_str_with_decode_rows(addr, len_=16, col_len=16, comment=None, line_prefix=None):
    """
        pt x
    """
    strs = addr_to_str_with_decode_rows(addr, len_, col_len)
    pt_strs_rows(strs, addr=addr, comment=comment, line_prefix=line_prefix)


def pt_addr_to_str_with_0x_with_decode_rows(addr, len_=16, col_len=16, comment=None, line_prefix=None):
    """
        pt x
    """
    strs = addr_to_str_with_0x_with_decode_rows(addr, len_, col_len)
    pt_strs_rows(strs, addr=addr, comment=comment, line_prefix=line_prefix)


# -------------------------------------------------------------------------
# dbg read/write
# -------------------------------------------------------------------------


def dbg_read_plong(addr, default="NULL"):
    p = xrkdbg.readLong(addr)
    if p == 0:
        return default
    return xrkdbg.readLong(p)


def dbg_read_string(addr, default="NULL"):
    """
        read string, return default is not valid
    """
    if validate_addr(addr):
        ret = xrkdbg.readString(addr)
        if ret is not None:
            if len(ret) != 0:
                encoding = chardet.detect(ret)["encoding"].lower()
                # xrklog.highlight("%s - %s" % (ret, encoding))
                if encoding != "ascii" and encoding != "utf-8" and encoding != "gb2312":
                    ret = ret.decode(encoding).encode("utf-8")
                    # print of ret might cause exception, if not re-encode
                    # xrklog.highlight("dbg read string encoding not ascii: %X" % (addr))
            return ret
    return default


def dbg_read_pstring(addr, default="NULL"):
    """
        read string, return default is not valid
    """
    if validate_addr(addr):
        return dbg_read_string(xrkdbg.readLong(addr))
    return default


def dbg_read_wstring(addr, default="NULL"):
    """
        read wstring

        len == 1 means:
            str: "\x00"
    """
    if validate_addr(addr):
        ret = xrkdbg.readWString(addr)
        if ret is not None:
            if len(ret) == 0 or len(ret) == 1:
                return ""
            if chardet.detect(ret)["encoding"] != "ascii":
                # print of ret might cause exception
                xrklog.highlight("dbg read wide string encoding not ascii: %X" % (addr))
            try:
                ret = ret.decode("UTF-16")
                try:
                    return ret.encode("UTF-8")
                except:
                    xrklog.error("encode str with UTF-8 occur exception")
            except:
                xrklog.error("decode str with UTF-16 occur exception")
    return default


def dbg_read_pwstring(addr, default="NULL"):
    """
        read p wstring
    """
    if validate_addr(addr):
        return dbg_read_wstring(xrkdbg.readLong(addr))
    return default


def dbg_read_long_with_offs(addr, off_1=None, off_2=None, off_3=None):
    """
        read long by offset
    """
    a = xrkdbg.readLong(addr)
    if off_1 is not None:
        b = xrkdbg.readLong(a + off_1)
        if off_2 is not None:
            c = xrkdbg.readLong(b + off_2)
            if off_3 is not None:
                return xrkdbg.readLong(c + off_3)
            else:
                return c
        else:
            return b
    else:
        return a


def write_byte(addr, value):
    assert value >= -0xFF
    assert value <= 0xFF
    xrkdbg.writeMemory(addr, int2str8_swap(value))


def write_word(addr, value):
    assert value >= -0xFFFF
    assert value <= 0xFFFF
    xrkdbg.writeMemory(addr, int2str16_swapped(value))


def write_v(addr, v, v_len):
    """
        write value at specified address

        @param: addr  : INT : address
        @param: v     : INT : value
        @param: v_len : INT : value width
        @raise: Exception
    """
    if not validate_addr(addr):
        raise Exception("addr invalid: %.8X" % addr)

    if v_len == 1:
        write_byte(addr, v)

    elif v_len == 2:
        write_word(addr, v)

    elif v_len == 4:
        xrkdbg.writeLong(addr, v)

    else:
        raise Exception("invalid value width %d at addr %.8X" % (v_len, addr))


def write_str(addr, str_, is_check=False):
    len_ = len(str_)
    if is_check:
        str_ori = xrkdbg.readString(addr)
        if len_ > len(str_ori):
            xrkdbg.log("write str check fail: %s --> %s" % (str_ori, str_))
            return
    for i in range(len_):
        write_byte(addr + i, ord(str_[i]))
    write_byte(addr + len_, 0)


def replace_str(addr, str_):
    write_str(addr, str_, is_check=True)


def write_wstr(addr, str_, is_check=False):
    """
        write wide string to addr

        @param: str_: STRING, normal string, not Unicode string

        !+ encode str_ first

        !+ TODO: might need to check length
    """
    assert chardet.detect(str_)["encoding"] == "ascii"
    try:
        str_ = str_.encode("UTF-16")
        # for some reason(i dont'w know why), the first 2 bytes are invalid
        str_ = str_[2:]
        len_ = xrkdbg.writeMemory(addr, str_)
        xrkdbg.writeMemory(addr + len_, '\x00\x00')
        return True
    except:
        xrklog.error("write_wstr, encode str with UTF-16 occur exception", verbose=True)
        return False


# -------------------------------------------------------------------------
# breakpoint/comment
# -------------------------------------------------------------------------


def may_bp(addr, bp_type="int_3"):
    if validate_addr(addr):
        if bp_type == "int_3":
            xrkdbg.setBreakpoint(addr)
        elif bp_type == "hd_exec":
            xrkdbg.setHardwareBreakpoint(addr)
        else:
            """
                TODO: complete other types
            """
            xrkdbg.setBreakpoint(addr)
    else:
        xrkdbg.log("-" * 100, highlight=1)
        xrkdbg.log("setting bp at invalid addr: 0x%X" % addr, highlight=1)
        xrkdbg.log("-" * 100, highlight=1)


def may_del_bp(addr):
    if validate_addr(addr):
        xrkdbg.deleteBreakpoint(addr)
    else:
        pass
        """
        xrkdbg.log("-" * 100, highlight=1)
        xrkdbg.log("deleting bp at invalid addr: 0x%X" % addr, highlight=1)
        xrkdbg.log("-" * 100, highlight=1)
        """


def may_del_hook(desc):
    if desc in xrkdbg.listHooks():
        xrkdbg.remove_hook(desc)


def may_del_comment(addr):
    if validate_addr(addr):
        xrkdbg.setComment(addr, "")


def may_update_comment(addr, comment, is_force=False):
    """
        set comment if addr has no comment
    """
    if validate_addr(addr):
        if len(comment) != 0:
            if is_force:
                xrkdbg.setComment(addr, comment)
            else:
                c = xrkdbg.getComment(addr)
                if c is None or len(c) == 0:
                    xrkdbg.setComment(addr, comment)
    else:
        xrkdbg.log("-" * 100, highlight=1)
        xrkdbg.log("update comment at invalid addr: 0x%X" % addr, highlight=1)
        xrkdbg.log("-" * 100, highlight=1)


def get_next_instruction(regs):
    """
        get next instructioni

        @return: LONG: next instruction address
    """
    eip = regs["EIP"]
    code = xrkdbg.disasmCode(eip)
    if code.isCall():
        return c_uint32(eip + 5 + xrkdbg.readLong(eip + 1)).value
    elif code.isJmp():
        # code.getSize() == 5
        # return c_uint32(eip + 5 + xrkdbg.readLong(eip + 1)).value
        return code.getJmpAddr()
    elif code.isConditionalJmp():
        # TODO
        # operand = code.result.split(" ")[0]
        # if operand in ["JB", "JNAE"] and
        # jmp_cdls = {"JB": check_jb}
        is_jmp_taken = False
        if is_jmp_taken:
            return code.getJmpAddr()
        else:
            xrklog.warn("we assume jmp not take, becasue we don't know it really.")
            return eip + code.getSize()
    elif code.isRet():
        return xrkdbg.readLong(regs["ESP"])
    else:
        return eip + code.getSize()


def set_bp_at_next_instruction(regs=None):
    """
    set breakpoint at next instruction
        TODO: complete instruction types
        TODO: complete bp types
    """
    regs = regs is not None and regs or xrkdbg.getRegs()
    xrkdbg.setBreakpoint(get_next_instruction(regs=regs))


def set_bp_on_dll_exports(dll_name, bp_type="int_3"):
    """
        set breakpoint on all exports of dll

        !+ dll shall be loaded already

        TODO: complete bp types
    """
    # mn_mod = xrkmona.MnModule(dll_name)
    mn_mod = None
    assert mn_mod is not None

    eop = mn_mod.moduleEntry
    xrkdbg.logLines("setting breakpoint at: 0x%X-%s" % (eop, "entry point"), highlight=1)
    xrkdbg.setComment(eop, "entry point")
    xrkdbg.setBreakpoint(eop)

    eat = mn_mod.getEAT()
    for e in eat:
        xrkdbg.setComment(e, eat[e])
        xrkdbg.setBreakpoint(e)
        xrkdbg.logLines("setting breakpoint at: 0x%X-%s" % (e, eat[e]), highlight=1)


def set_bp_on_dll_rvas(dll_name, rvas, bp_type="int_3"):
    """
        set breakpint on dll rvas

        !+ dll shall be loaded already

        TODO: complete bp types
    """
    mn_mod = None
    # mn_mod = xrkmona.MnModule(dll_name)
    assert mn_mod is not None
    base = mn_mod.moduleBase
    for rva in rvas:
        addr = base + rva
        comment = xrkdbg.getComment(addr)
        if len(comment) == 0:
            xrkdbg.setComment(addr, "bp by rva 0x%X" % rva)
        if bp_type == "int_3":
            xrkdbg.setBreakpoint(addr)
        elif bp_type == "hd_exec":
            xrkdbg.setHardwareBreakpoint(addr)
        else:
            xrkdbg.logLines("!" * 120, highlight=1)
            xrkdbg.logLines("invalid bp type: %s" % bp_type, highlight=1)
            xrkdbg.logLines("!" * 120, highlight=1)
        xrkdbg.logLines("setting breakpoint by rva at: 0x%X-%s" % (addr, dll_name), highlight=1)


# -------------------------------------------------------------------------
# knowledge
# -------------------------------------------------------------------------


def set_k(id_, value):
    assert id_ is not None and len(id_) != 0 and value is not None
    xrkdbg.forgetKnowledge(id_)
    xrkdbg.addKnowledge(id_, value, 1)


def get_k(id_):
    ret = xrkdbg.getKnowledge(id_)
    """
        this could be none. when caller detect this as none, caller should set it.
    """
    """assert ret is not None"""
    return ret


def may_init_update_k(cbk_get, cbk_set, pairs):
    """
        may init or update k

        1. get k
        2. if k is None, init k with pairs
        3. if k is not None, update k with pairs
    """
    k = cbk_get()
    if k is None:
        k = {}
        for (d, x) in pairs.items():
            k[d] = x
        cbk_set(k)
    else:
        is_changed = False
        for (d, x) in pairs.items():
            if d in k.keys():
                if k[d] != x:
                    k[d] = x
                    is_changed = True
            else:
                k[d] = x
                is_changed = True
        if is_changed:
            cbk_set(k)


# -------------------------------------------------------------------------
# serialize
# -------------------------------------------------------------------------


def serialize_set(id_, value):
    """
        this shall depend on __APP_NAME__
    """
    set_k(id_, value)


def serialize_get(id_, default=None):
    """
        this shall depend on __APP_NAME__
    """
    ret = get_k(id_)
    if ret is None:
        return default
    return ret


def serialize_update(cbk_get, cbk_set, pairs):
    return may_init_update_k(cbk_get, cbk_set, pairs)


# -------------------------------------------------------------------------
# api param parse
# -------------------------------------------------------------------------


def hook_id_to_str(id_):
    if id_ == 4:
        return "WH_CALLWNDPROC"
    if id_ == 12:
        return "WH_CALLWNDPROCRET"
    if id_ == 5:
        return "WH_CBT"
    if id_ == 9:
        return "WH_DEBUG"
    if id_ == 11:
        return "WH_FOREGROUNDIDLE"
    if id_ == 3:
        return "WH_GETMESSAGE"
    if id_ == 1:
        return "WH_JOURNALPLAYBACK"
    if id_ == 0:
        return "WH_JOURNALRECORD"
    if id_ == 2:
        return "WH_KEYBOARD"
    if id_ == 13:
        return "WH_KEYBOARD_LL"
    if id_ == 7:
        return "WH_MOUSE"
    if id_ == 14:
        return "WH_MOUSE_LL"
    if id_ == -1:
        return "WH_MSGFILTER"
    if id_ == 10:
        return "WH_SHELL"
    if id_ == 6:
        return "WH_SYSMSGFILTER"
    return "NULL"


def parse_p_file_time(p_file_time):
    """
        parse pointer of FILETIME structure

        @param: p_file_time: FILETIME *: pointer

        @return: obj of xrkwin32.SYSTEMTIME
    """
    """
    low = xrkdbg.readLong(p_file_time)
    high = xrkdbg.readLong(p_file_time + 4)
    ft = xrkwin32.FILETIME(low, high)
    st = xrkwin32.SYSTEMTIME(0)
    xrkwin32.FileTimeToSystemTime(ft, st)
    return st
    """
    return None


def parse_sockaddr(addr_ptr):
    """
        parse struct sockaddr by ptr to get ip string and ip value and port
    """
    p_ip_value = addr_ptr + 0x2 + 0x2
    p_port = addr_ptr + 0x2
    """original connect target"""
    port = socket.ntohs(xrkdbg.readShort(p_port))
    ip_value = xrkdbg.readLong(p_ip_value)
    # ip_str = socket.inet_ntoa(struct.pack('I', socket.htonl(ip_value)))
    # ip_value is big-idendian.
    ip_str = socket.inet_ntoa(struct.pack('I', ip_value))
    return ip_str, ip_value, port


def replace_sockaddr(addr_ptr, ip_str, port):
    """
        replace ip and port of struct sockaddr
    """
    ip_value = socket.ntohl(struct.unpack("I", socket.inet_aton(str(ip_str)))[0])
    p_ip_value = addr_ptr + 0x2 + 0x2
    xrkdbg.writeLong(p_ip_value, socket.htonl(ip_value))
    """
        p_port = addr_ptr + 0x2
        TODO: complete port update
    """


def get_reg_data(type_, pdata, data_size=0):
    if type_ == _winreg.REG_BINARY:
        assert data_size != 0
        return "REG_BINARY", addr_to_str(pdata, data_size)
    elif type_ == _winreg.REG_DWORD:
        return "REG_DWORD", "%d" % xrkdbg.readLong(pdata)
    elif type_ == _winreg.REG_DWORD_LITTLE_ENDIAN:
        return "REG_DWORD_LITTLE_ENDIAN", "NONE"
    elif type_ == _winreg.REG_DWORD_BIG_ENDIAN:
        return "REG_DWORD_BIG_ENDIAN", "NONE"
    elif type_ == _winreg.REG_EXPAND_SZ:
        return "REG_EXPAND_SZ", xrkdbg.readString(pdata)
    elif type_ == _winreg.REG_LINK:
        return "REG_LINK", "NONE"
    elif type_ == _winreg.REG_MULTI_SZ:
        return "REG_MULTI_SZ", xrkdbg.readString(pdata)
    elif type_ == _winreg.REG_NONE:
        return "REG_NONE", "NONE"
    elif type_ == _winreg.REG_SZ:
        return "REG_SZ", xrkdbg.readString(pdata)
    """
    elif type_ == _winreg.REG_QWORD:
        return "REG_QWORD", "NONE"
    elif type_ == _winreg.REG_QWORD_LITTLE_ENDIAN:
        return "REG_QWORD_LITTLE_ENDIAN", "NONE"
    """


def get_reg_data_w(type_, pdata, data_size=0):
    if type_ == _winreg.REG_BINARY:
        return "REG_BINARY", addr_to_str(pdata, data_size)
    elif type_ == _winreg.REG_DWORD:
        return "REG_DWORD", "%d" % xrkdbg.readLong(pdata)
    elif type_ == _winreg.REG_DWORD_LITTLE_ENDIAN:
        return "REG_DWORD_LITTLE_ENDIAN", "NONE"
    elif type_ == _winreg.REG_DWORD_BIG_ENDIAN:
        return "REG_DWORD_BIG_ENDIAN", "NONE"
    elif type_ == _winreg.REG_EXPAND_SZ:
        return "REG_EXPAND_SZ", dbg_read_wstring(pdata)
    elif type_ == _winreg.REG_LINK:
        return "REG_LINK", "NONE"
    elif type_ == _winreg.REG_MULTI_SZ:
        return "REG_MULTI_SZ", dbg_read_wstring(pdata)
    elif type_ == _winreg.REG_NONE:
        return "REG_NONE", "NONE"
    elif type_ == _winreg.REG_SZ:
        return "REG_SZ", dbg_read_wstring(pdata)


# -------------------------------------------------------------------------
# misc
# -------------------------------------------------------------------------


#
# from malware-analyses.py
#       ?auther tested this on MAX OS...
#       ?check file type: filetype = subprocess.check_output(["file", "-b", filePath])
#       ?check string: strings = subprocess.check_output(["strings", filePath])
#       get file size: os.path.getsize(file_name)
#       compilation file time: datetime.datetime.fromtimestamep(pe.FILE_HEADER.FILE_HEADER)
#       ?fileinfo: for fileinfo in pe.FileInfo:
#                     if fileinfo.key == "StringFileInfo":
#                         ...
#                     elif fileinfo.key == "VarFileInfo":
#                         ...
#       ep: pe.OPTIONAL_HEADER.AddressOfEntryPoint
#       base: pe.OPTIONAL_HEADER.ImageBase
#       ?sections: for section in pe.sections:
#                     e = getEntropy(section.get_data())
#                     if e < 6.0:
#                         # not packed
#                     elif e < 7.0:
#                         # maybe packed
#                     else:
#                         # packed
#                     section.Name/VirtualAddress/Misc_VirtualSize
#       ?data dirs: pe.parse_data_directories()
#       ?import: for entry in pe.DIRECTORY_ENTRY_IMPORT:
#                    entry.dll
#                    for imp in entry.imports:
#                        imp.name, imp.address
#       ?export: for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
#                    exp.name, exp.address
#       ?resource: for resc_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
#                      resc_type.name
#                      pefile.RESOURCE_TYPE.get(resc_type.struct.Id)
#                      for resc_id in resc_type.directory.entries:
#                          for resc_lang in resc_id.directory.entries:
#                              data = pe.get_data(resc_lang.data.struct.OffsetToData, resc_lang.data.struct.Size)
#                              lang = pefile.LANG.get(resc_lang.data.lang)
#                              sublang = pefile.get_sublang_name_for_lang(resc_lang....)
#


def get_file_hash_f(f):
    """
        get file md5 by handle

        @return: DICT: {"md5": xx, "sha1": xx, "sha256": xx, "sha512": xx}
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    while True:
        data = f.read(128)
        if not data:
            break
        md5.update(data)
        sha1.update(data)
        sha256.update(data)
        sha512.update(data)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest(), "sha512": sha512.hexdigest()}


def get_file_hash(file_name):
    """
        get file md5 by name

        @return: DICT: {"md5": xx, "sha1": xx, "sha256": xx, "sha512": xx}
    """
    assert os.path.exists(file_name)
    f = open(file_name)
    ret = get_file_hash_f(f)
    f.close()
    return ret


def query_vt(md5, vt_api_key):
    """
        query vt

        @return: ? JSON ?
    """
    params = {"resource": md5, "apikey": vt_api_key}
    response = urllib2.urlopen(urllib2.Request("https://www.virustotal.com/vtapi/v2/file/report",
                               urllib.urlencode(params)))
    # ?dict_.get("positives")/dict_.get("total")
    # dict_ = simplejson.loads(response.read())
    # return dict_
    return response

# -------------------------------------------------------------------------
# END OF FILE
# -------------------------------------------------------------------------
