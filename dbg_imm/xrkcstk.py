# -*- coding: utf-8 -*-

"""
anything related with call stack

call stack filter:
1. this does not hook ntdll apis, like NtOpenFile, but CreateFileW. because ntdll apis hit too frequently, and not "filterable"
2. not hooking all apis. for example: we only hook SleepEx, no Sleep, because Sleep calls SleepEx internally
   but for some apis, like "process createtion" apis: CreateProcesssInternalW

"""

import os
import re
import sys
import inspect
import traceback


try:
    import xrkcst
    import xrklog
    import xrksym
    import xrkdbg
    import xrkutil
except:
    this_path = os.path.split(os.path.realpath(inspect.stack()[-1][1]))[0]
    sys.path.append(this_path)
    try:
        import xrkcst
        import xrklog
        import xrksym
        import xrkdbg
        import xrkutil
    except Exception, e:
        import immlib as dbglib
        dbg = dbglib.Debugger()
        dbg.log("xrkcstk import error: %s" % e, highlight=1)
        error = traceback.format_exc()
        while len(error) > 200:
            tmp = error[:200]
            dbg.log("  %s" % tmp, highlight=1)
            error = error[200:]
        dbg.log("  %s" % error, highlight=1)

        assert False


# ---------------------------------------------------------------------------
# get call stacks
# ---------------------------------------------------------------------------


class StackEx:
    # ---------------------------------------------------------------------------
    # normal debugtypes.Stack with symbol functionality:
    #       self.calledfrom_symbol
    #       self.calledfrom_symbol_ex
    #       self.procedure_symbol(not used anymore)
    #
    # !+ this is just on record of xrkdbg.callStack()
    # ---------------------------------------------------------------------------
    def __init__(self, stack):
        """
            set default symbols, and update it.

            @param: stack : obj : obj of debugtypes.Stack
        """
        self.stack = stack

        # set default symbols
        self.calledfrom_symbol = "%.8X" % self.stack.calledfrom
        self.calledfrom_symbol_ex = self.calledfrom_symbol

        # we don't use procedure_symbol any more. calledfrom_symbol is good to go.
        # self.procedure_symbol = self.stack.procedure

        self.__update_symbol()

    def __update_symbol(self):
        """
            update calledfrom_symbol by self.stack.calledfrom
        """
        if xrkutil.validate_addr(self.stack.calledfrom):

            # get symbol string
            sym_str = xrksym.get_sym_str(self.stack.calledfrom)

            # update self.calledfrom_symbol
            if sym_str is not None:
                self.calledfrom_symbol = sym_str

            # get module name
            md_name = xrkutil.get_md_name_by_addr(self.stack.calledfrom)

            # update self.calledfrom_symbol_ex
            if md_name is not None:
                self.calledfrom_symbol_ex = md_name + "." + self.calledfrom_symbol


def stacks_to_stacks_ex(stacks):
    """
        convert a list of debugtypes.Stack to list of StackEx

        @param: stacks : LIST : a list of debugtypes.Stack

        @return: LIST: a list of StackEx
    """
    if len(stacks) == 0:
        return []

    stacks_ex = []
    for stack in stacks:
        stacks_ex.append(StackEx(stack))
    return stacks_ex


def get_call_stacks_ex():
    """
        get current StackEx list

        @return: LIST : a list of StackEx
    """
    return stacks_to_stacks_ex(xrkdbg.callStack())


def get_calledfrom_stacks():
    """
        get debugtypes.Stack list, excluded arg items

        @return: LIST : a list of debugtypes.Stack, without arg items
    """
    stacks = xrkdbg.callStack()

    ret = []
    last_called_from = 0

    for i in range(len(stacks)):

        stack = stacks[i]
        if xrkutil.validate_addr(stack.calledfrom):

            # exclude arg items
            if last_called_from != stack.calledfrom:

                ret.append(stack)
                last_called_from = stack.calledfrom
    return ret


def get_calledfrom_stacks_ex():
    """
        get StackEx list, excluded arg items

        @return: LIST: a list of StackEx, without arg items
    """
    return stacks_to_stacks_ex(get_calledfrom_stacks())


def get_calledfrom_sym_strs(has__=True, has_at=True, has_dis=True):
    """
        get current calledfrom symbol strings

        @param: has__   : BOOL : pass to xrksym.get_sym_str as param
        @param: has_at  : BOOL : pass to xrksym.get_sym_str as param
        @param: has_dis : BOOL : pass to xrksym.get_sym_str as param

        @return: LIST : a list of calledfrom symbol strings
    """
    stacks = get_calledfrom_stacks()

    ret = []
    for i in range(len(stacks)):

        sym_str = xrksym.get_sym_str(stacks[i].calledfrom, has__=has__, has_at=has_at, has_dis=has_dis)
        if sym_str is None:
            sym_str = "%.8X" % stacks[i].calledfrom

        if "." in sym_str:

            # sym_str comes from xrkdbg.decodeAddress()
            ret.append(sym_str)

        else:
            # prefix sym_str with module name
            md_name = xrkutil.get_md_name_by_addr(stacks[i].calledfrom)
            ret.append(md_name is not None and (md_name + "." + sym_str) or sym_str)

    return ret


def get_calledfrom_sym_strs_as_str(all_cstk=True, has__=True, has_at=True, has_dis=True):
    """
        format current calledfrom symbols strings as string

        @param: all_cstk : BOOL : is force format all call stack items
        @param: has__    : BOOL : pass to get_calledfrom_sym_strs as param
        @param: has_at   : BOOL : pass to get_calledfrom_sym_strs as param
        @param: has_dis  : BOOL : pass to get_calledfrom_sym_strs as param

        @return: STRING : as below:
            A <-- B <-- C
            A <-- B <-- C <-- D
            A <-- B <-- C <-- D <-- E
            A <-- B <-- ... <-- X <-- Y
            or:
            !!EMPTY CALL STACK!!
    """
    strs = get_calledfrom_sym_strs(has__=has__, has_at=has_at, has_dis=has_dis)
    if len(strs) == 0:
        return "!!EMPTY CALL STACK!!"

    else:

        spliter = " <-- "
        ret = ""
        if all_cstk or len(strs) <= 4:

            # less than 4 items, or force all format items, append each other
            for i in range(len(strs)):

                if i != len(strs) - 1:
                    ret = ret + strs[i] + spliter
                else:
                    ret = ret + strs[i]
        else:
            # more than 4 items, use "..." in between
            ret = strs[0] + spliter + strs[1] + spliter + "..." + spliter + strs[-2] + spliter + strs[-1]

        return ret

# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


def check_is_same_stack(stacks1, stacks2):
    """
        check if two debugtypes.Stack list is same.
        compare each item with stack.calledfrom

        @param: stacks1 : LIST : a list of debugtypes.Stack
        @param: stacks2 : LIST : a list of debugtypes.Stack

        @return: BOOL :

        !+ calling this too much might freeze ui. so, only call this when you want output
    """
    if len(stacks1) != len(stacks2):
        return False

    for i in range(len(stacks1)):

        # compare with calledfrom
        if stacks1[i].calledfrom != stacks2[i].calledfrom:
            return False

    return True


def check_is_same_stack_ex(stacks_ex1, stacks_ex2):
    """
        check if two StackEx list is same.
        compare each StackEx with stack_ex.stack.calledfrom

        @param: stacks_ex1 : LIST : StackEx list
        @param: stacks_ex2 : LIST : StackEx list

        @return: BOOL

        !+ calling this too much will freeze ui. so, only call this when you want output
    """
    if len(stacks_ex1) != len(stacks_ex2):
        return False

    for i in range(len(stacks_ex1)):

        # compare with calledfrom
        if stacks_ex1[i].stack.calledfrom != stacks_ex2[i].stack.calledfrom:
            return False

    return True


def check_cstk_uppers_has_strs(strs, cstk_level=0):
    """
        check if call stack calledfrom symbol strings has specified strs

        @param: strs       : LIST : the list of strings to check
        @param: cstk_level : INT  : how many call stack levels to check. default 0 meaning all call stacks.

        @return: BOOL : True if has, Flase otherwise
    """
    stacks_sym_strs = get_calledfrom_sym_strs()

    # determine check_level
    check_level = 0
    if cstk_level == 0:
        check_level = len(stacks_sym_strs)
    else:
        check_level = min(cstk_level, len(stacks_sym_strs))

    if check_level > 0:

        # check each level
        for i in range(check_level):
            for str_ in strs:

                # check each str
                if str_ in stacks_sym_strs[i]:
                    return True
    return False


def check_cstk_uppers_in_md_names(api_name, md_names, is_no_stack_as_true=True, is_no_md_as_true=True):
    """
        check if top-most caller of api in md_names

        @param: api_name            : STRING : root api name to check
        @param: md_names            : LIST   : module name list to check
        @param: is_no_stack_as_true : BOOL   : is return True when no stack available
        @param: is_no_md_as_true    : BOOL   : is return True when no module available

        @return: BOOL
    """
    stacks_sym_strs = get_calledfrom_sym_strs(has__=False, has_at=False, has_dis=False)
    if len(stacks_sym_strs) == 0 or len(stacks_sym_strs) == 1:

        # no stack available
        # this might because imm get call stack fail, or really no call stack available
        return is_no_stack_as_true

    else:

        # get all pre-defined callers of api
        callers = xrkcst.api_name_to_api_callers(api_name)

        while len(stacks_sym_strs) != 0:

            cur_sym_str = stacks_sym_strs[0]

            if "." not in cur_sym_str:

                # called from not recognized module(might from stack or heap)
                return is_no_md_as_true

            proc_splits = cur_sym_str.split(".")
            if xrkutil.x_contains(md_names, proc_splits[0]):

                # module name of this call stack "in" md_names
                return True

            else:
                if callers is None:

                    # don't have pre-defiend caller anymore, but still no match found
                    return False

                else:
                    tmp_api_name = proc_splits[1]
                    if not xrkutil.x_contains(callers, tmp_api_name):

                        # "api name" of this call stack not "in" pre-defined callers
                        return False

                    else:
                        # get callers of "api name" of this call stack, then continue check
                        callers = xrkcst.api_name_to_api_callers(tmp_api_name)

                        # for some reason, this ret None
                        # stacks_sym_strs = stacks_sym_strs.remove(cur_sym_str)

                        stacks_sym_strs.pop(0)

        # we've finished comparing all call stack item.
        # here, we take it as no stack available
        return is_no_stack_as_true

# ---------------------------------------------------------------------------
# print
# ---------------------------------------------------------------------------


def __pt_cstk(stacks, pt_addr=False, pt_called_from=False, pt_frame=False):
    """
        print specified call stack

        @param: pt_addr        : BOOL : is print stack.address
        @param: pt_called_from : BOOL : is print stack.calledfrom
        @param: pt_frame       : BOOL : is print stack.frame
    """
    if len(stacks) == 0:
        xrkdbg.log("call stack empty!!", highlight=1)
        xrkutil.cstk()

    else:
        lines = ["__pt_cstk"]
        for stack in stacks:

            line = ""
            if pt_addr:
                line = line + ("%.8X" % stack.address) + "  "

            if pt_called_from:
                line = line + ("%.8X" % stack.calledfrom) + "  "

            if pt_frame:
                line = line + ("%.8X" % stack.frame) + "  "

            line = line.strip("  ")
            line = line + "  " + stack.procedure

            lines.append(line)

        # print
        xrklog.infos(lines)


def pt_cstk(pt_args=False, pt_addr=False, pt_called_from=False, pt_frame=False):
    """
        print current call stack

        @param: pt_args        : BOOL : is print arg items
        @param: pt_addr        : BOOL : param pass to __pt_cstk
        @param: pt_called_from : BOOL : param pass to __pt_cstk
        @param: pt_frame       : BOOL : param pass to __pt_cstk
    """
    # determine stacks
    stacks = []
    if pt_args:
        stacks = xrkdbg.callStack()
    else:
        stacks = get_calledfrom_stacks()

    __pt_cstk(stacks, pt_addr=pt_addr, pt_called_from=pt_called_from, pt_frame=pt_frame)


def pt_cstk_ex(pt_addr=False, pt_called_from=False, pt_frame=False):
    """
        print current call stack, with stack_ex.calledfrom_symbol_ex

        @param: pt_addr        : BOOL : is print stack_ex.stack.address
        @param: pt_called_from : BOOL : is print stack_ex.stack.calledfrom and stack_ex.calledfrom_symbol_ex
        @param: pt_frame       : BOOL : is print stack_ex.stack.frame
    """
    stacks_ex = get_call_stacks_ex()
    if len(stacks_ex) == 0:
        xrkdbg.log("call stack ex empty!!", highlight=1)

    else:
        lines = []
        for stack_ex in stacks_ex:

            line = ""
            if pt_addr:
                line = line + ("%.8X" % stack_ex.stack.address) + "  "

            if pt_called_from:
                line = line + ("%.8X" % stack_ex.stack.calledfrom) + "  " + stack_ex.calledfrom_symbol_ex + " "

            if pt_frame:
                line = line + ("%.8X" % stack_ex.stack.frame) + "  "

            line = line.strip("  ")
            line = line + "  " + stack_ex.stack.procedure

            lines.append(line)

    # print
    xrklog.infos(lines)


# ---------------------------------------------------------------------------
# dbgview
# ---------------------------------------------------------------------------


def dbgview_cstk_procedures(api_name, pt_addr=False, pt_called_from=False, pt_frame=False):
    """
        dbgview current call stack procedures
        this is for filtered out apis. we wannt know it, but not from imm log window.

        @param: api_name       : STRING : filtered out api name
        @param: pt_addr        : BOOL   : is print stack_ex.stack.address
        @param: pt_called_from : BOOL   : is print stack_ex.stack.calledfrom and stack_ex.calledfrom_symbol_ex
        @param: pt_frame       : BOOL   : is print stack_ex.stack.frame
    """
    lines = []
    stacks_ex = get_calledfrom_stacks_ex()
    if len(stacks_ex) == 0:
        lines.append("call stack procedures: empty")

    else:
        lines.append("filtered out api: %s" % api_name)
        for stack_ex in stacks_ex:

            line = ""
            if pt_addr:
                line = line + ("%.8X" % stack_ex.stack.address) + "  "

            if pt_called_from:
                line = line + ("%.8X" % stack_ex.stack.calledfrom) + "  " + stack_ex.calledfrom_symbol + " "

            if pt_frame:
                line = line + ("%.8X" % stack_ex.stack.frame) + "  "

            line = line.strip("  ")
            line = line + "  " + stack_ex.stack.procedure

            lines.append(line)

    # log to dbgview
    xrklog.dbgview_lines(lines)


# ---------------------------------------------------------------------------
# stack.procedure parsing
# ---------------------------------------------------------------------------
"""
    parsing value of stack.procedure is kind of difficult.
    it has 2 types of strings:
        as function call: ? kernel32.MoveFileWithProgressW
        as function args: Arg1 = xxx
    and we use this for only 1 purpose: logging.......

    format of stack.procedure is kind of complex, might contain many invalid chars, like: space/?/&/</>/Include/JMP/...
    so, for stack filter, we use stack.calledfrom.

    sometimes, cstk don't recognize some module that address belong to. dbg.getPage(stacks[i].calledfrom) can solve this, but we'd better use symbol.
    whatever, this is not important.
"""

#
# NOT USED ANYMORE!
#


def __exclude_stack_procedure(procedure):
    """
        1. apace
        2. ?
        3. include # can check space
        4. maybe # can check space
        5. &
        6. JMP # can check space and &
        7. <

        !+ ret may contains "."
    """
    invalid_str_list = [" ", "?", "&", "<", ">", "Include", "Maybe", "JMP"]
    # invalid_str = '|'.join("%s" % str_ for str_ in invalid_str_list)
    # !+: char '?' can't be in re.split(), because '?' represents any char
    invalid_str = " |&|<|>|Include|Maybe|JMP"
    while xrkutil.x_contains(invalid_str_list, procedure):
        splits = re.split(invalid_str, procedure)
        splits = sorted(splits, key=len)
        procedure = splits[-1]
    return procedure


def __exclude_stack_procedure_ex(procedure):
    """
        !+ if has ".", ret the later part
    """
    procedure = __exclude_stack_procedure(procedure)
    if "." in procedure:
        splits = procedure.split(".")
        assert len(splits) == 2
        assert "." not in splits[1]
        return splits[1]
    return procedure


def get_addr_from_procedure(procedure):
    """
        get addr from procedure

        @return: TUPLE: True/False, procedure_addr/None
    """
    procedure = __exclude_stack_procedure(procedure)
    if xrkutil.check_is_hex_num_str(procedure):
        return True, int(procedure, 16)
    else:
        return False, None

# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
