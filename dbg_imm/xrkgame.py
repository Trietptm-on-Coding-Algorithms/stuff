# -*- coding: utf-8 -*-

"""
hook def
"""

import os
import sys
import inspect
import traceback
from ctypes import c_uint32

try:
    import xrklog
    import xrkdbg
    import xrkdef
    import xrkhook
    import xrkutil
except:
    this_path = os.path.split(os.path.realpath(inspect.stack()[-1][1]))[0]
    sys.path.append(this_path)
    try:
        import xrklog
        import xrkdbg
        import xrkdef
        import xrkhook
        import xrkutil
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


# -------------------------------------------------------------------------
# model
# -------------------------------------------------------------------------


class sdg:
    def __init__(self, desc, str_):
        """
            @param: str_:
                has_x:          B9 x x x x E8 ? ? ? ? 8B 4C 24 04 F7 D8 1B C0 F7 D8 48 89 41 04 B0 01 C3
                has_nothing:    83 EC 08 56 8B 74 24 10 0F B7 06 57 8B F9 B9 96 00 00 00 66 3B C1 74 ? 66 83 F8 65 74 ? BA A8
        """
        # xrklog.info("init sdg %s" % desc, verbose=True)

        self.desc = desc
        self.str_ = str_
        desc_list, c_index_1, c_index_2 = xrkdef.game_str_to_desc_list(str_, splitter=" ", c1="x")
        self.desc_list = desc_list
        self.c_index = c_index_1

    def search(self):
        """
            default search method

            search self.desc_list in main module, and get result value
        """
        # xrklog.info("search main module for sdg: %s" % self.desc, verbose=True)
        addr_mm_dict = xrkutil.search_desc_list_in_main_module(self.desc_list)
        return self.calc_result(addr_mm_dict)

    def search_in_pages(self, pages):
        """
            search method

            search self.desc in pages

            @param: pages: DICT: {addr: MemoryPage, addr: MemoryPage,}
        """
        addr_mm_dict = xrkutil.search_desc_list_in_pages(self.desc_list, pages=pages)
        """
        for (d, x) in addr_mm_dict.items():
            xrklog.high("%.8X - %s" % (d, xrkutil.buf_to_str(x)), add_prefix=True)
        """
        return self.calc_result(addr_mm_dict)

    def calc_result(self, addr_mm_dict):
        """
            calc result
        """
        if self.c_index is not None:
            return xrkutil.get_v_from_mm_slice_list(addr_mm_dict.values(), self.c_index, v_len=4)
        else:
            if len(addr_mm_dict) == 0:
                # xrklog.info("sdg %s got no addr mm dict" % self.desc, verbose=True)
                return None
            elif len(addr_mm_dict) != 1:
                # xrklog.info("sdg %s got %d addr mm pairs" % (self.desc, len(addr_mm_dict)), verbose=True)
                # vs = sorted(addr_mm_dict.values())
                vs = sorted(addr_mm_dict.keys())
                ret = vs[0]
                for v in vs:
                    if ret != v:
                        # xrklog.warn("sdg %s got %d addr mm pairs, but result is different" % (self.desc, len(addr_mm_dict)), verbose=True)
                        # assert False
                        return None
                return ret
            else:
                return addr_mm_dict.keys()[0]


class sdg2:
    def __init__(self, desc, str_1, str_2):
        """
            @param: str_1:
                6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC AC 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 A8 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 C0 01 00 00 64 A3 00 00 00 00 8B F1 89 74 24
            @param: str_2:
                8B CE E8 z z z z A3 x x x x 8B 4C 24 10 64 89 0D 00 00 00 00 59 5E 83 C4 14 C3 33 C0 A3
        """
        # xrklog.info("init sdg2 %s" % desc, verbose=True)

        self.desc = desc
        desc_list, c_index, c_index = xrkdef.game_str_to_desc_list(str_1, splitter=" ")
        self.desc_list_1 = desc_list

        desc_list, c_index_1, c_index_2 = xrkdef.game_str_to_desc_list(str_2, splitter=" ", c1="z", c2="x")
        self.desc_list_2 = desc_list
        self.c_index_2_z = c_index_1
        self.c_index_2_x = c_index_2

    def search(self):
        """
            search self.desc_list_1 in main module, get result, and use result to work as a filter for self.desc_list_2 searched results
        """
        # xrklog.info("search main module for sdg2: %s" % self.desc, verbose=True)

        addr_mm_dict = xrkutil.search_desc_list_in_main_module(self.desc_list_1)
        assert len(addr_mm_dict) == 1
        v_check = addr_mm_dict.keys()[0]

        xrklog.info("sdg2 %s addr 1: %.8X" % (self.desc, v_check), verbose=True)

        addr_mm_dict = xrkutil.search_desc_list_in_main_module(self.desc_list_2)
        xrklog.log_table_binary(addr_mm_dict)
        tmp = []
        for (d, x) in addr_mm_dict.items():
            v_s = xrkutil.get_v_from_mm_slice(x, self.c_index_2_z)
            v = c_uint32(d + self.c_index_2_z + 4 + v_s).value
            # xrklog.info("%.8X + %.8X + 4 + %.8X = %.8X" % (d, self.c_index_2_z, v_s, v), verbose=True)
            if v_check == v:
                tmp.append(x)
        return xrkutil.get_v_from_mm_slice_list(tmp, self.c_index_2_x, v_len=4)

# -------------------------------------------------------------------------
# misc
# -------------------------------------------------------------------------


def search_sdg_list_in_main_module(sdg_list):
    """
        @param: sdg_list: a list of sdg objs

        @return: DICT: {sdg_1_desc: sdg_1_result, sdg_2_desc: sdg_2_result, ...}
    """
    sdg_dict = {}
    desc_list_dict = {}
    for sdg in sdg_list:
        sdg_dict[sdg.desc] = sdg
        desc_list_dict[sdg.desc] = sdg.desc_list

    # tmp: {"desc_1": addr_mm_dict_1, "desc_2": addr_mm_dict_2, ...}
    tmp = xrkutil.search_desc_list_dict_in_main_module(desc_list_dict)
    if tmp is not None:
        ret = {}
        for (d, x) in tmp.items():
            ret[d] = sdg_dict[d].calc_result(x)
        return ret
    return None


def gen_ida_script_by_sdg_list(sdg_list, file_name=r"e:\\ida_sdg_script.txt"):
    """
        generate ida script and save to file

        @param: sdg_list: a list of sdg objs
        @param: file_name: STRING: file to save to

        @return: LIST: a list of error messages

        each ida script item:
            "MakeNameEx(0x%X,\"%s_%X\",0);\n", m_addr, m_ida_name, m_addr
    """
    search_result = search_sdg_list_in_main_module(sdg_list)
    lines = []
    fails = []
    # {sdg_1_desc: sdg_1_result, sdg_2_desc: sdg_2_result, ...}
    for (d, x) in search_result.items():
        if x is not None:
            lines.append("MakeNameEx(0x%X, \"__%s_%.8X\", 0);" % (x, d, x))
        else:
            fails.append(d)

    file = open(file_name, "w")
    file.write("\n".join("%s" % line for line in lines))
    file.close()
    xrklog.info("write %d ida items to file %s" % (len(lines), file_name))
    """
    for sdg in sdg_list:
        if sdg.desc not in search_result or search_result[sdg.desc] is None:
            fails.append(sdg.desc)
    """
    return fails


def get_sdg_result(sdg):
    """
        the result of sdg never changes, so, get from k first, if not found, calc it, then store in k
    """
    k = xrkutil.serialize_get("sdg_results")
    if k is None:
        k = {}
    if sdg.desc not in k:
        k[sdg.desc] = sdg.search()
        xrkutil.serialize_set("sdg_results", k)
    return k[sdg.desc]


def gua_hook_installed_by_sdg(sdg, run_cbk, shall_pause=False):
    """
        gua that hook is installed by sdg

        @param: run_cbk: method
    """
    # addr = sdg.search()
    addr = get_sdg_result(sdg)
    if sdg.desc not in xrkdbg.listHooks():
        h = xrkhook.pausableInvokeRunCbkHook(xrkdef.cbkStructRun(run_cbk))
        h.add(sdg.desc, addr, shall_pause=shall_pause)
        xrklog.info("install hook for sdg %s at %.8X" % (sdg.desc, addr))
    xrkutil.set_bp_may_pause(addr, shall_pause)


# -------------------------------------------------------------------------
# hex feature
# -------------------------------------------------------------------------


def get_desc_from_addr(addr, max_len=100):
    """
        get desc string from addr

        code.result:        JE SHORT NYCSClie.00FC8CE4
        code.dump:          74 4C

        for each code:
            1. remove all middle ";"/" " in code.dump, as new_dump
            2. split new_dump by 2, format a string list
            3. replace part of string list itmes by "?"
            4. form a new string
        then, append result of each code, to get final string

        @return: string: a string, like the ones to init sdg
    """
    q_1 = ["?"]
    q_4 = ["?", "?", "?", "?"]
    ret = ""
    code_len = 0
    while code_len < max_len:
        code = xrkdbg.disasmCode(addr)
        code_size = code.getSize()
        new_dump = code.dump.replace(":", "").replace(" ", "")
        str_list = []
        for i in range(0, len(new_dump), 2):
            str_list.append(new_dump[i:i + 2])
        operand = code.result.split(" ")[0].lower()

        is_tripped = True
        if operand in ["jmp", "ja", "jb", "je", "jl", "jg", "jz", "jae", "jbe", "jge", "jle", "jna", "jnb", "jng", "jnl", "jnz", "jnae", "jnbe", "jnle", "jnge"]:
            if code_size == 2:
                # EB 03            JMP SHORT ntdll.KiFastSystemCallRet
                # 72 06            JB SHORT NYCSClie.011CA23C
                # 75 6F            JNZ SHORT NYCSClie.00FF79AD
                str_list = str_list[:1] + q_1
            elif code_size == 5:
                # E9 86CEFEFF      JMP ntdll.77575D93
                str_list = str_list[:1] + q_4
            elif code_size == 6:
                str_list = str_list[:2] + q_4
                # 0F86 AB080100    JBE NYCSClie.01008142
            else:
                is_tripped = False
                # xrklog.info("%s - %s" % (code.dump, code.result), verbose=True)

        elif operand in ["call"]:
            if code_size == 2:
                # FFD2             CALL EDX
                is_tripped = False
            elif code_size == 5 and str_list[0] == "E8":
                # E8 0F4B2100      CALL NYCSClie.0120C360
                str_list = str_list[:1] + q_4
            elif code_size == 6 and str_list[0] == "FF" and str_list[1] == "15":
                # FF15 286AA901    CALL DWORD PTR DS:[<&MSVCR90._invalid_pa>
                str_list = str_list[:2] + q_4
            else:
                is_tripped = False
                # xrklog.info("%s - %s" % (code.dump, code.result), verbose=True)

        elif operand in ["push"]:
            if code_size == 1 or code_size == 2:
                # 55               PUSH EBP
                # 6A FF            PUSH -1
                is_tripped = False
            elif code_size == 5:
                assert str_list[0] == "68"
                # 68 A96B4D01      PUSH NYCSClie.014D6BA9
                if "." in code.result:
                    str_list = str_list[:1] + q_4
                else:
                    # 68 F4000000      PUSH 0F4
                    # 68 43E648FB      PUSH FB48E643
                    # 68 60259A17      PUSH 179A2560 # this has no ".", because it's on heap, no on some module. and we don't have time to check module or heap.
                    # is_tripped = False
                    str_list = str_list[:1] + q_4
            else:
                is_tripped = False
                # xrklog.info("%s - %s" % (code.dump, code.result), verbose=True)

        elif operand in ["mov"]:
            if code_size == 2 or code_size == 3:
                # 8BEC - MOV EBP,ESP
                # 8B75 08          MOV ESI,DWORD PTR SS:[EBP+8]
                is_tripped = False
            elif code_size == 4:
                # 8B4424 18        MOV EAX,DWORD PTR SS:[ESP+18]
                # 894C24 40        MOV DWORD PTR SS:[ESP+40],ECX
                # str_list = str_list[:3] + q_1
                is_tripped = False
            elif code_size == 5:
                if str_list[0] in ["A1", "A2", "A3", "BA", "B9"]:
                    # A1 3808F001      MOV EAX,DWORD PTR DS:[1F00838]
                    # A3 F4593E02      MOV DWORD PTR DS:[23E59F4],EAX
                    # BA 4079C101      MOV EDX,NYCSClie.01C17940
                    # B9 30280A10      MOV ECX, g_100A2830
                    str_list = str_list[:1] + q_4
                elif str_list[0] in ["B8"]:
                    # B8 F43C0000      MOV EAX,3CF4
                    is_tripped = False
            elif code_size == 6:
                # 64:A1 00000000   MOV EAX,DWORD PTR FS:[0]
                if str_list[0] == "64" and str_list[2:] == ["00", "00", "00", "00"]:
                    is_tripped = False
                else:
                    str_list = str_list[:2] + q_4
            elif code_size == 7:
                # 64:8925 00000000 MOV DWORD PTR FS:[0],ESP
                # 898424 F03C0000  MOV DWORD PTR SS:[ESP+3CF0],EAX
                if str_list[0] in ["64", "89"]:
                    is_tripped = False
                elif str_list[0] in ["C6"]:
                    # C605 89279A17 7B MOV BYTE PTR DS:[179A2789],7B
                    str_list = str_list[:2] + q_4 + str_list[6:]
                elif str_list[0] in ["C7"]:
                    if str_list[2] in ["EC"]:
                        # C745 EC 00000000 MOV DWORD PTR SS:[EBP-14],0
                        is_tripped = False
                    elif str_list[2] in ["E8"]:
                        # C745 E8 5428CA02 MOV DWORD PTR SS:[EBP-18],2CA2854
                        str_list = str_list[:3] + q_4
                    else:
                        is_tripped = False
                else:
                    is_tripped = False
            elif code_size == 8:
                # C74424 58 00000000    MOV DWORD PTR SS:[ESP+58],0
                str_list = str_list[:3] + q_1 + q_4
            else:
                is_tripped = False
                # 895C24 08        MOV DWORD PTR SS:[ESP+8],EBX
                # xrklog.info("%s - %s" % (code.dump, code.result), verbose=True)

        elif operand in ["lea"]:
            if code_size == 3:
                # 8D49 00          LEA ECX,DWORD PTR DS:[ECX]
                is_tripped = False
            elif code_size == 4:
                # 8D4424 18        LEA EAX,DWORD PTR SS:[ESP+18]
                # 8D4C24 08        LEA ECX,DWORD PTR SS:[ESP+8]
                # str_list = str_list[:3] + q_1
                is_tripped = False
            elif code_size == 7:
                # 8D9424 00390000  LEA EDX,DWORD PTR SS:[ESP+3900]
                # str_list = str_list[:3] + q_4
                is_tripped = False
            else:
                is_tripped = False
                # xrklog.info("%s - %s" % (code.dump, code.result), verbose=True)

        elif operand in ["retn"]:
            for i in range(len(str_list)):
                ret = ret + " " + str_list[i]
            return ret
        elif operand in ["and", "sub", "xor"]:
            is_tripped = False
        elif operand in ["cmp"]:
            if code_size == 6:
                # 3935 FC27CA02      CMP DWORD PTR DS:[2CA27FC],ESI
                str_list = str_list[:2] + q_4
            elif code_size == 7:
                # 803D CF27D717 00 CMP BYTE PTR DS:[17D727CF],0
                str_list = str_list[:2] + q_4 + str_list[6:]
            else:
                is_tripped = False
        else:
            is_tripped = False
            # xrklog.info("%s - %s" % (code.dump, code.result), verbose=True)

        if is_tripped:
            xrklog.info("    tripped: %-20s | %-40s | --> |" % (code.dump, code.result), verbose=True)
        else:
            xrklog.info("not tripped: %-20s | %-40s | --> |" % (code.dump, code.result), verbose=True)

        for i in range(len(str_list)):
            if len(ret) == 0:
                ret = str_list[i]
            else:
                ret = ret + " " + str_list[i]
            code_len = code_len + 1
        addr = addr + code.getSize()
    return ret


def get_desc_dict_from_addr(addr, min_len=10, max_len=100):
    """
        get desc dict from addr

        @param: min_len: min bytes in desc_str, not "char" element, but "byte" element
        @param: max_len: max bytes in desc_str, not "char" element, but "byte" element

        @return: DICT: {desc_str_1: desc_list_1, desc_str_2: desc_list_2, ...}
    """
    desc_str_max = get_desc_from_addr(addr, max_len=max_len)
    # well, this is not good, actually...
    i = min(min_len * 3, len(desc_str_max) - 5)
    ret = {}
    while i < len(desc_str_max):
        if desc_str_max[i] == " " and desc_str_max[i + 1] != "?":
            desc_str_tmp = desc_str_max[:i].strip(" ").strip(" ? ? ? ?")
            ret[desc_str_tmp] = xrkdef.game_str_to_desc_list(desc_str_tmp)[0]
        i = i + 1
    return ret


def __desc_xx_dict_to_tuple_list(xx_dict):
    """
        @param: xx_dict: {"desc_1": addr_mm_dict_1, "desc_2": addr_mm_dict_2, ...}

        @return: LIST: [(desc_str_1, desc_str_1_size, search_cnt), (desc_str_2, desc_str_2_size, search_cnt), ...]
    """
    assert xx_dict is not None
    ret = []
    for (d, x) in xx_dict.items():
        ret.append((d, len(d), len(x)))
    return sorted(ret)


def get_desc_dict_from_addr_in_main_module(addr, min_len=10, max_len=100):
    """
        get desc dict from addr

        @param: min_len: min bytes in desc_str, not "char" element, but "byte" element
        @param: max_len: max bytes in desc_str, not "char" element, but "byte" element

        @return: LIST: [(desc_str_1, desc_str_1_size, search_cnt), (desc_str_2, desc_str_2_size, search_cnt), ...]
    """
    desc_list_dict = get_desc_dict_from_addr(addr, min_len=min_len, max_len=max_len)
    # tmp: {"desc_1": addr_mm_dict_1, "desc_2": addr_mm_dict_2, ...}
    tmp = xrkutil.search_desc_list_dict_in_main_module(desc_list_dict)
    if tmp is not None:
        return __desc_xx_dict_to_tuple_list(tmp)
    return None


def get_desc_dict_from_addr_in_mm_pages(addr, pages, min_len=10, max_len=100):
    """
        get desc dict from addr

        @param: min_len: min bytes in desc_str, not "char" element, but "byte" element
        @param: max_len: max bytes in desc_str, not "char" element, but "byte" element

        @return: LIST: [(desc_str_1, desc_str_1_size, search_cnt), (desc_str_2, desc_str_2_size, search_cnt), ...]
    """
    desc_list_dict = get_desc_dict_from_addr(addr, min_len=min_len, max_len=max_len)
    # tmp: {"desc_1": addr_mm_dict_1, "desc_2": addr_mm_dict_2, ...}
    tmp = xrkutil.search_desc_list_dict_in_pages(desc_list_dict, pages)
    if tmp is not None:
        return __desc_xx_dict_to_tuple_list(tmp)
    return None


def get_desc_dict_from_eip(regs=None, min_len=10, max_len=100):
    """
        get desc dict from eip

        @param: regs: can be None
        @param: min_len: min bytes in desc_str, not "char" element, but "byte" element
        @param: max_len: max bytes in desc_str, not "char" element, but "byte" element

        @return: LIST: [(desc_str_1, desc_str_1_size, search_cnt), (desc_str_2, desc_str_2_size, search_cnt), ...]
    """
    regs = regs is not None and regs or xrkdbg.getRegs()
    return get_desc_dict_from_addr(regs["EIP"], min_len=min_len, max_len=max_len)

# -------------------------------------------------------------------------
# END OF FILE
# -------------------------------------------------------------------------
