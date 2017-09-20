# -*- coding: utf-8 -*-

"""
anything related with symbol
"""

import os
import sys
import string
import inspect
import datetime
import traceback
from ctypes import Structure, c_ulong, c_char, c_ulonglong, windll, sizeof, addressof
from _multiprocessing import win32


try:
    import xrklog
    import xrkdbg
    import xrkutil
    import xrkcloud
except:
    this_path = os.path.split(os.path.realpath(inspect.stack()[-1][1]))[0]
    sys.path.append(this_path)
    try:
        import xrklog
        import xrkdbg
        import xrkutil
        import xrkcloud
    except Exception, e:
        import immlib as dbglib
        dbg = dbglib.Debugger()
        dbg.log("xrksym import error: %s" % e, highlight=1)
        error = traceback.format_exc()
        while len(error) > 200:
            tmp = error[:200]
            dbg.log("  %s" % tmp, highlight=1)
            error = error[200:]
        dbg.log("  %s" % error, highlight=1)

        assert False


# -------------------------------------------------------------------------
# IDA FUNCTION NAMES
# -------------------------------------------------------------------------

"""
ida script to generate sym file:


import idc
import idautils

def get_non_sub_functions():
    ret = []
    for f in idautils.Functions():
        name = idc.GetFunctionName(f)
        if not name.startswith("sub_") and not name.startswith("unknown"):
            ret.append((idc.GetFunctionAttr(f, 0), idc.GetFunctionAttr(f, 4), name))
    return ret


def save_non_sub_function(file_name):
    f = open(file_name, "w")
    for func in get_non_sub_functions():
        f.write("%d %d %s\n" % (func[0], func[1], func[2]))

    print "save non sub functio to file finish: %s" % file_name


save_non_sub_function(r"e:\1111_ida_names.txt")


"""

#
# structure of func names:
#       [date,
#        (f1_start, f1_end, f1_name),
#        (f2_start, f2_end, f2_name),
#        (f3_start, f3_end, f3_name)]
#
v_id_ida_func_names = "ida_func_names"


def __check_update_ida_func_names():
    """
        if sym file exists and file time is "newer" than cloud, then update cloud by file
    """
    # sym file shall in the same directory with debugee and end with "_ida_names.txt"
    file = xrkutil.gen_debugeed_file_x_path("_ida_names.txt")
    if not os.path.exists(file):
        xrklog.error("file for ida func names not exist: %s" % file, verbose=True)

    else:
        timestamp = os.path.getmtime(file)
        date = datetime.datetime.fromtimestamp(timestamp)

        k = xrkcloud.cloud_get(v_id_ida_func_names)
        if k is None or k[0] != date:

            # set/udpate
            set_ida_func_names(file, date)


def set_ida_func_names(file_name, date):
    """
        read ida function borders and names from file, and store to cloud

        @param: file_name : STRING   : file name containing func infos
                                       each line shall be in this format: func_start func_end func_name
                                       func_start and func_end shall be DEC value
        @param: date      : datetime : datetime that file created
    """
    value = []
    # first element is date
    value.append(date)

    f = open(file_name)
    for line in f.readlines():

        splits = line.split(" ")
        assert len(splits) == 3

        # func_start/func_end: DEC, not HEX
        value.append((string.atoi(splits[0]), string.atoi(splits[1]), splits[2]))

    f.close()

    xrkcloud.cloud_set(v_id_ida_func_names, value)

    xrklog.high("parse ida func name success. name cnt: %d, file: %s" % (len(value) - 1, file_name))


def get_ida_func_name(addr):
    """
        get ida function name and offset by addr from cloud

        @param: addr : INT : address

        @return: TUPLE : (func_name, offset)
                         (None, None)
    """
    # check if we need set/update func names
    __check_update_ida_func_names()

    k = xrkcloud.cloud_get(v_id_ida_func_names)
    if k is not None and len(k) != 0:

        for f in k:
            if k.index(f) != 0 and f[0] <= addr and addr <= f[1]:
                return f[2], (f[1] - addr)

    return (None, None)


# -------------------------------------------------------------------------
# symbols
# -------------------------------------------------------------------------


class SYMBOL_INFO(Structure):
    _fields_ = [
        ('SizeOfStruct', c_ulong),
        ('TypeIndex', c_ulong),
        ('Reserved', c_ulonglong * 2),
        ('Index', c_ulong),
        ('Size', c_ulong),
        ('ModBase', c_ulonglong),
        ('Flags', c_ulong),
        ('Value', c_ulonglong),
        ('Address', c_ulonglong),
        ('Register', c_ulong),
        ('Scope', c_ulong),
        ('Tag', c_ulong),
        ('NameLen', c_ulong),
        ('MaxNameLen', c_ulong),
        ('Name', c_char * 2001)]


def get_dbgged_handle():
    """
        get debugged process handle by open process(by pid)

        @return: INT : process handle
                 None

        !+ don't forget to call windll.kernel32.CloseHandle(h_proc) after use
    """
    h_proc = windll.kernel32.OpenProcess(win32.PROCESS_ALL_ACCESS, False, xrkdbg.getDebuggedPid())

    if h_proc == 0:
        xrklog.error("OpenProcess error: %d" % windll.kernel32.GetLastError())
        return None

    return h_proc


#
# structure of sym cache:
#        {"h_proc": xxx,
#         "addr": (name, dis),
#         "addr": (name, dis)}
#
v_id_sym_cache = "sym_cache"


def __get_sym_from_cache(h_proc, addr):
    """
        get symbol from cache

        @param: h_proc : INT : process handle
        @param: addr   : INT : address

        @return: TUPLE : (func_name, offset)
                         (None, None), representing h_proc has changed or addr not in cache
    """
    k = xrkcloud.cloud_get(v_id_sym_cache)

    if k is None or k["h_proc"] != h_proc or addr not in k:
        return None, None

    return k[addr]


def __add_sym_to_cache(h_proc, addr, name, dis):
    """
        add symbol to cache

        @param: h_proc : INT    : process handle
        @param: addr   : INT    : address
        @param: name   : STRING : symbol name
        @param: dis    : INT    : symbol offset
    """
    k = xrkcloud.cloud_get(v_id_sym_cache, default={})

    if "h_proc" not in k or k["h_proc"] != h_proc:

        # clear all items, and set h_proc
        k = {}
        k["h_proc"] = h_proc

    # add symbol
    k[addr] = (name, dis)

    xrkcloud.cloud_set(v_id_sym_cache, k)


def __get_sym(h_proc, addr, use_cache=True):
    """
        get symbol of addr

        @param: h_proc    : INT  : process handle
        @param: addr      : INT  : address
        @param: use_cache : BOOL : is use cache

        @return: TUPLE : (func_name, offset)
                         (None, None)
    """
    # try get from cache
    if use_cache:
        name, dis = __get_sym_from_cache(h_proc, addr)
        if name is not None and dis is not None:
            return name, dis

    # resolve sym using dbghelp apis
    sinfo = SYMBOL_INFO()
    sinfo.SizeOfStruct = sizeof(SYMBOL_INFO) - 2000
    sinfo.MaxNameLen = 2000

    displacement = c_ulonglong()
    code = windll.dbghelp.SymFromAddr(h_proc, c_ulonglong(addr), addressof(displacement), addressof(sinfo))
    if code == 0:

        # win32 error
        last_error = windll.kernel32.GetLastError()
        # -------------------------------------------------------------------------
        # 487: try to access invalid address.
        # addr that can not resolve will return this
        # 126: no module found
        # TODO: when 126 happens, try to ?
        # -------------------------------------------------------------------------
        if last_error not in [487, 126]:
            xrklog.error("SymFromAddr error: %d, addr: 0x%X" % (last_error, addr))

        # xrklog.error("SymFromAddr error: %d, addr: 0x%X" % (last_error, addr), verbose=True)
        return None, None

    name = sinfo.Name.strip()
    dis = str(hex(displacement.value))

    # add to cache
    __add_sym_to_cache(h_proc, addr, name, dis)

    return name, dis


def __sym_initialize():
    """
        invoke dbghelp api: SymInitialize

        @return: TUPLE : (True, h_proc)
                         (False, None)
    """
    h_proc = get_dbgged_handle()
    if h_proc is not None:

        code = windll.dbghelp.SymInitialize(h_proc, None, 1)
        if code != 0:
            return True, h_proc

        xrklog.error("SymInitialize error: %d" % (windll.kernel32.GetLastError()))

    return False, None


#
# structure of sym init:
#       {"pid": 123, "h_proc: 456"}
#
v_id_sym_init = "sym_init"


def __gua_sym_initialized():
    """
        guarantee that dbghelp.SymInitialize is invoked for current process, so u don't have to init it again,

        @return: TUPLE : (True, h_proc)
                         (Flase, None)
        @raise: Exception

        !+ we do this, because each call to dbghelp.SymInitialize will alloc !+many !+many memory, even if SymCleanup() is called
        !+ for h_proc: CloseHandle() is never called
        !+ for sym: SymCleanUp() is never called
    """
    need_init = False
    pid = xrkdbg.getDebuggedPid()

    k = xrkcloud.cloud_get(v_id_sym_init)
    if k is None:
        need_init = True

    else:
        if k["pid"] == pid:
            return True, k["h_proc"]

        else:
            # maybe this is too late, and not necessary at all.
            windll.kernel32.CloseHandle(k["h_proc"])
            need_init = True

    if need_init:

        is_success, h_proc = __sym_initialize()
        if is_success:

            xrkcloud.cloud_set(v_id_sym_init, {"pid": pid, "h_proc": h_proc})
            return True, h_proc

        else:
            return False, None

    else:
        # if not need_init, shall already returned
        raise Exception("this shall never be invoked")


def get_sym(addr, use_cache=True):
    """
        get symbol of addr

        @param: addr      : INT  : address
        @param: use_cache : BOOL : is use cache

        @return: TUPLE : (name, dis)
                         (None, None)
    """
    is_init, h_proc = __gua_sym_initialized()
    if is_init:
        return __get_sym(h_proc, addr, use_cache=use_cache)

    else:
        xrklog.error("get sym, gua sym initialize failed", verbose=True)
        return None, None


def get_sym_str(addr, has__=True, has_at=True, has_dis=True, use_cache=True):
    """
        get symbol of addr, then format as string

        @param: addr      : INT  : address
        @param: has__     : BOOL : used to strip symbol name
        @param: has_at    : BOOL : used to strip symbol name
        @param: has_dis   : BOOL : is format offset
        @param: use_cache : BOOL : is use cache

        @return: STRING : formated symbol string
                 None

        steps:
            1. try from cache/dbghelp.SymFromAddr()  --> ?_GetProcAddress+0x4L
            2. try ida names                         --> __minit+0x5L
            3. try xrkdbg.decodeAddress()            --> 1111.00400000
            4. return None                           --> None

        TODO: has_q shall be param also.
    """
    # 1. try from cache/dbghelp.SymFromAddr()
    name, dis = get_sym(addr, use_cache=use_cache)
    if name is not None and dis is not None:

        # strip
        name = xrkutil.strip_str(name, has__=has__, has_at=has_at, has_q=False)
        if not has_at and "@" in name:
            name = name.split("@")[0]
            assert "@" not in name

        # format result
        return has_dis and (name + "+" + dis) or name

    if xrkutil.validate_addr(addr):

        # 2. try ida names
        name, dis = get_ida_func_name(addr)
        if name is not None and dis is not None:

            # strip
            name = xrkutil.strip_str(name, has__=has__, has_at=has_at, has_q=False)

            # simply looking at "@Sysutils@StrLen$qqrpxc" is really anonying...
            name = "%.8X_%s" % (addr, name)

            # format result
            return has_dis and (name + "+" + ("0x%XL" % dis)) or name

        else:
            # 3. try xrkdbg.decodeAddress() --> 1111.00400000
            ret = xrkdbg.decodeAddress(addr)
            if ret is not None and len(ret) != 0:
                return ret

            # 4. return None
            # this may happen when decode heap addrs
            # xrklog.error("decode valid addr fail: %X" % addr, verbose=True)
            return None
    else:
        # address invalid
        return None


def get_syms(addrs, use_cache=True):
    """
        get symbols of addrs.

        @param: addrs     : LIST : a list of address
        @param: use_cache : BOOL : is use cache

        @return: DICT : {addr: [name, dis],
                         addr: [name, dis]}
                         for addr that get sym fail, will not in result dict
                 None : meaning sym init fail

        !+ not resolved addrs, will not be in return dict
    """
    is_init, h_proc = __gua_sym_initialized()
    if is_init:

        ret = {}
        for addr in addrs:
            name, dis = __get_sym(h_proc, addr, use_cache=use_cache)
            if name is None:

                # get sym fail, do not add to result dict
                continue
            else:
                ret[addr] = name, dis

        return ret

    else:
        # sym init fail
        return None


def get_syms_strs(addrs, has__=True, has_at=True, has_dis=True, use_cache=True):
    """
        get symbols strings of addrs

        @param: addrs     : LIST : a list of address
        @param: has__     : BOOL : used to strip symbol name
        @param: has_at    : BOOL : used to strip symbol name
        @param: has_dis   : BOOL : is format offset
        @param: use_cache : BOOL : is use cache

        @return: LIST : a list of strings, like: [SuckThis+9L, 0xABC000, SuckThat+7L, ...]
                 None

        steps for each addr:
            1. try from cache/dbghelp.SymFromAddr()  --> ?_GetProcAddress+0x4L
            2. try ida names                         --> __minit+0x5L
            3. try xrkdbg.decodeAddress()               --> 1111.00400000
            4. direct format addr
    """
    # 1. try from cache/dbghelp.SymFromAddr()
    syms = get_syms(addrs, use_cache=use_cache)
    if syms is not None:

        ret = []
        for addr in addrs:
            if addr not in syms:

                # step 1 fail, try other approaches

                if xrkutil.validate_addr(addr):

                    # 2. try ida names
                    name, dis = get_ida_func_name(addr)
                    if name is not None and dis is not None:

                        # strip
                        name = xrkutil.strip_str(name, has__=False, has_at=False, has_q=False)

                        # simply looking at "@Sysutils@StrLen$qqrpxc" is really anonying...
                        name = "%.8X_%s" % (addr, name)

                        # format
                        ret.append(has_dis and (name + "+" + ("0x%XL" % dis)) or name)

                    else:
                        # 3. try xrkdbg.decodeAddress()
                        tmp = xrkdbg.decodeAddress(addr)
                        if tmp is not None and len(tmp) != 0:
                            ret.append(tmp)

                        else:
                            # 4. direct format addr
                            # this may happen when decode heap addrs
                            # xrklog.error("decode valid addr %X fail" % addr, verbose=True)
                            ret.append("%.8X" % addr)

                else:
                    # address invalid
                    ret.append("%.8X(INVALID)" % addr)
            else:
                # step 1 success, add to result list

                # strip
                name = xrkutil.strip_str(syms[addr][0], has__=has__, has_at=False, has_q=False)
                if not has_at and "@" in name:
                    name = name.split("@")[0]
                    assert "@" not in name

                # format
                dis = syms[addr][1]
                ret.append(has_dis and (name + " + " + dis) or name)

        return ret

    else:
        # sym init fail
        return None


# -------------------------------------------------------------------------
# END OF FILE
# -------------------------------------------------------------------------
