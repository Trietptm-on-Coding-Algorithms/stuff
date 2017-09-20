# -*- coding: utf-8 -*-

"""
    xrkdef
"""

import os
import sys
import string
import inspect
import traceback


try:
    import xrklog
    import xrkdbg
    import xrkutil
except:
    this_path = os.path.split(os.path.realpath(inspect.stack()[-1][1]))[0]
    sys.path.append(this_path)
    try:
        import xrklog
        import xrkdbg
        import xrkutil
    except Exception, e:
        import immlib as dbglib
        dbg = dbglib.Debugger()
        dbg.log("xrkdef import error: %s" % e, highlight=1)
        error = traceback.format_exc()
        while len(error) > 200:
            tmp = error[:200]
            dbg.log("  %s" % tmp, highlight=1)
            error = error[200:]
        dbg.log("  %s" % error, highlight=1)

        assert False


# ---------------------------------------------------------------------------
# addr_calcer
# ---------------------------------------------------------------------------


class addrCalcer:
    # ---------------------------------------------------------------------------
    # address cacler
    # ---------------------------------------------------------------------------
    def __init__(self, base, off_1=None, off_2=None, off_3=None, off_4=None):
        """
            @param: base            : INT : address base
            @param: off_1/.../off_4 : INT : address offsets
        """
        self.base = base
        self.off_1 = off_1
        self.off_2 = off_2
        self.off_3 = off_3
        self.off_4 = off_4

    def calc_addr(self):
        """
            calc addr by offsets
        """
        addr = self.base
        if self.off_1 is not None:

            addr = xrkdbg.readLong(addr + self.off_1)
            if self.off_2 is not None:

                addr = xrkdbg.readLong(addr + self.off_2)
                if self.off_3 is not None:

                    addr = xrkdbg.readLong(addr + self.off_3)
                    if self.off_4 is not None:

                        addr = xrkdbg.readLong(addr + self.off_4)

        return addr

    def __str__(self):
        """
            @return: STRING :
        """
        ret = ".8X" % self.base
        if self.off_1 is not None:

            ret = "[%s+%.8X]" % (ret, self.off_1)
            if self.off_2 is not None:

                ret = "[%s+%.8X]" % (ret, self.off_2)

                if self.off_3 is not None:

                    ret = "[%s+%.8X]" % (ret, self.off_3)
                    if self.off_4 is not None:

                        ret = "[%s+%.8X]" % (ret, self.off_4)

        return ret


# ---------------------------------------------------------------------------
# vSetter
# ---------------------------------------------------------------------------


def __invoke_v_set(addr_calcer, value, v_len):
    """
        set integer value

        @param: addr_calcer : obj : obj of addrCalcer
        @param: value       : INT : integer value to set
        @param: v_len       : INT : value width

        @return: BOOL :
    """
    addr = addr_calcer.calc_addr()
    if xrkutil.validate_addr(addr):
        xrkutil.write_v(addr, value, v_len)
        return True

    else:
        xrkdbg.error("calc invalid addr: %s - %.8X" % (addr_calcer, addr))
        return False


class vSetterBase:
    # ---------------------------------------------------------------------------
    # base class of all value setter classes
    #
    # !+ just to stay good style
    # ---------------------------------------------------------------------------
    def __init__(self):
        pass


class vSetterDirect(vSetterBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, addr, value, v_len=4, off_1=None, off_2=None, off_3=None, off_4=None):
        """
            @param: addr            : INT : address base
            @param: value           : INT : value to set
            @param: v_len           : INT : value width
            @param: off_1/.../off_4 : ... : address offsets
        """
        self.value = value
        self.v_len = v_len
        self.addr_calcer = addrCalcer(addr, off_1=off_1, off_2=off_2, off_3=off_3, off_4=off_4)

    def set(self, regs=None):
        """
            set value

            @param: regs : None : just to stay same with other two types of setters
            @return: BOOL :
        """
        return __invoke_v_set(self.addr_calcer, self.value, self.v_len)


class vSetterReg(vSetterBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, reg_name, value, v_len=4, off_1=None, off_2=None, off_3=None, off_4=None):
        """
            @param: reg_name        : STRING : reg name, use it's value as address base
            @param: value           : INT    : value to set
            @param: v_len           : INT    : value width
            @param: off_1/.../off_4 : ...    : address offsets
        """
        self.reg_name = reg_name
        self.value = value
        self.v_len = v_len
        self.off_1 = off_1
        self.off_2 = off_2
        self.off_3 = off_3
        self.off_4 = off_4

    def set(self, regs=None):
        """
            set value

            @param: regs : DICT : reg dict
            @return: BOOL :

            !+ in run_cbk, xrkdbg.getRegs() ret wrong regs, caller provide regs instead
        """
        if regs is None:
            regs = xrkdbg.getRegs()
        addr_calcer = addrCalcer(regs[self.reg_name], off_1=self.off_1, off_2=self.off_2, off_3=self.off_3, off_4=self.off_4)
        return __invoke_v_set(addr_calcer, self.value, self.v_len)


class vSetterRegOnly(vSetterBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, reg_name, value):
        """
            @param: reg_name        : STRING : reg name, target reg to set
            @param: value           : INT    : value to set
        """
        self.reg_name = reg_name
        self.value = value

    def set(self, regs=None):
        """
            set value

            @param: regs : DICT : reg dict
            @return: True

            !+ in run_cbk, xrkdbg.getRegs() ret wrong regs, caller provide regs instead
        """
        if regs is None:
            regs = xrkdbg.getRegs()
        xrkdbg.setReg(self.reg_name, self.value)
        return True


class vSetterStack(vSetterBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, stack_offset, value, v_len=4, off_1=None, off_2=None, off_3=None, off_4=None):
        """
            @param: stack_offset    : INT : stack offset, use ("ESP" + stack_offset) as address base
            @param: value           : INT : value to set
            @param: v_len           : INT : value width
            @param: off_1/.../off_4 : ... : address offsets
        """
        self.stack_offset = stack_offset
        self.value = value
        self.v_len = v_len
        self.off_1 = off_1
        self.off_2 = off_2
        self.off_3 = off_3
        self.off_4 = off_4

    def set(self, regs=None):
        """
            set value

            @param: regs : DICT : reg dict
            @return: BOOL :

            !+ in run_cbk, xrkdbg.getRegs() ret wrong regs, caller provide regs instead
        """
        if regs is None:
            regs = xrkdbg.getRegs()
        addr_calcer = addrCalcer(regs["ESP"] + self.stack_offset, off_1=self.off_1, off_2=self.off_2, off_3=self.off_3, off_4=self.off_4)
        return __invoke_v_set(addr_calcer, self.value, self.v_len)


def __invoke_mm_set(addr_calcer, buf):
    """
        set mm

        @param: addr_calcer : obj : obj of addrCalcer
        @param: buf         : str : buf to write

        @return: BOOL :
    """
    addr = addr_calcer.calc_addr()
    if xrkutil.validate_addr(addr):
        xrkdbg.writeMemory(addr, buf, len(buf))
        return True

    else:
        xrklog.error("addr calcer get invalid addr: %s - %.8X" % (addr_calcer, addr))
        return False


class mmSetterBase:
    # ---------------------------------------------------------------------------
    # base class of all mm setter classes
    #
    # !+ just to stay good style
    # ---------------------------------------------------------------------------
    def __init__(self):
        pass


class mmSetterDirect(mmSetterBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, addr, buf, off_1=None, off_2=None, off_3=None, off_4=None):
        """
            @param: addr            : INT : address base
            @param: buf             : str : mm buf to set
            @param: off_1/.../off_4 : ... : address offsets
        """
        self.buf = buf
        self.addr_calcer = addrCalcer(addr, off_1=off_1, off_2=off_2, off_3=off_3, off_4=off_4)

    def set(self, regs=None):
        """
            set buf

            @param: regs : None : just to stay same with other two types of setters

            @return: BOOL :
        """
        return __invoke_mm_set(self.addr_calcer, self.buf)


class mmSetterReg(mmSetterBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, reg_name, buf, off_1=None, off_2=None, off_3=None, off_4=None):
        """
            @param: reg_name        : STRING : reg name, use it's value as address base
            @param: buf             : str    : mm buf to set
            @param: off_1/.../off_4 : ...    : address offsets
        """
        self.reg_name = reg_name
        self.buf = buf
        self.off_1 = off_1
        self.off_2 = off_2
        self.off_3 = off_3
        self.off_4 = off_4

    def set(self, regs=None):
        """
            set buf

            @param: regs : DICT : reg dict

            @return: BOOL :

            !+ in run_cbk, xrkdbg.getRegs() ret wrong regs, caller provide regs instead
        """
        if regs is None:
            regs = xrkdbg.getRegs()
        addr_calcer = addrCalcer(regs[self.reg_name], off_1=self.off_1, off_2=self.off_2, off_3=self.off_3, off_4=self.off_4)
        return __invoke_mm_set(addr_calcer, self.buf)


class mmSetterStack(mmSetterBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, stack_offset, buf, off_1=None, off_2=None, off_3=None, off_4=None):
        """
            @param: stack_offset    : INT : stack offset, use ("ESP" + stack_offset) as address base
            @param: buf             : str : mm buf to set
            @param: off_1/.../off_4 : ... : address offsets
        """
        self.stack_offset = stack_offset
        self.buf = buf
        self.off_1 = off_1
        self.off_2 = off_2
        self.off_3 = off_3
        self.off_4 = off_4

    def set(self, regs=None):
        """
            set buf

            @param: regs : DICT : reg dict
            @return: BOOL :

            !+ in run_cbk, xrkdbg.getRegs() ret wrong regs, caller provide regs instead
        """
        if regs is None:
            regs = xrkdbg.getRegs()
        addr_calcer = addrCalcer(regs["ESP"] + self.stack_offset, off_1=self.off_1, off_2=self.off_2, off_3=self.off_3, off_4=self.off_4)
        return __invoke_mm_set(addr_calcer, self.buf)


# ---------------------------------------------------------------------------
# debugeeModifies
# ---------------------------------------------------------------------------


class debugeeModifies:
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, modifies):
        """
            @param: modifies : obj or LIST : a vSetterXX obj or list of vSetterXX objs

            !+ TODO: should be able to modify byte/short/memory/ect...
        """
        self.modifies = xrkutil.obj_inst_or_list_to_list(modifies)

    def invoke(self, regs=None, stop_when_fail=False):
        """
            invoke

            @param: regs           : DICT : reg dict
            @param: stop_when_fail : BOOL : shall stop when any of "modifier" fails

            @return: BOOL :
        """
        for modify in self.modifies:
            if not modify.set(regs):
                xrklog.error("modify fail..")
                if stop_when_fail:
                    return False
        return True


# ---------------------------------------------------------------------------
# vGetter/mmGetter
# ---------------------------------------------------------------------------


def invoke_v_get(addr_calcer, v_len=4):
    """
        get integer value

        @param: addr_calcer : obj : obj of addrCacler
        @param: v_len       : INT : value width, default 4, means __int32

        @return: INT :

        !+ can't be private
    """
    addr = addr_calcer.calc()
    if v_len == 4:
        return xrkdbg.readLong(addr)
    elif v_len == 2:
        return xrkdbg.readShort(addr)
    elif v_len == 1:
        return xrkdbg.readByte(addr)
    else:
        assert False


class vGetterBase:
    # ---------------------------------------------------------------------------
    # base class of value getter classes
    #
    # !+ just to stay good style
    # ---------------------------------------------------------------------------
    def __init__(self):
        pass


class vGetterSolid(vGetterBase):
    # ---------------------------------------------------------------------------
    # just to work as vGetterBase
    # ---------------------------------------------------------------------------
    def __init__(self, value):
        """
            @param: value : INT : value to get.
        """
        self.value = value

    def get(self, regs=None):
        """
            @param: regs : None

            @return: INT : value to get
        """
        return self.value


class vGetterDirect(vGetterBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, addr, v_len=4, off_1=None, off_2=None, off_3=None, off_4=None):
        """
            @param: addr            : INT : address base
            @param: v_len           : INT : value width
            @param: off_1/.../off_4 : ... : address offsets
        """
        self.v_len = v_len
        self.addr_calcer = addrCalcer(addr, off_1=off_1, off_2=off_2, off_3=off_3, off_4=off_4)

    def get(self, regs=None):
        """
            get value

            @param: regs: None, just to stay same with other two types of gettrs
            @return: INT :
        """
        return invoke_v_get(self.addr_calcer, self.v_len)


class vGetterReg(vGetterBase):
    # ---------------------------------------------------------------------------
    # !+ read value that reg_value point to, not reg itself
    # ---------------------------------------------------------------------------
    def __init__(self, reg_name, v_len=4, off_1=None, off_2=None, off_3=None, off_4=None):
        """
            @param: reg_name        : STRING : reg name, use it's value as address base
            @param: v_len           : INT    : value width
            @param: off_1/.../off_4 : ...    : address offsets
        """
        self.reg_name = reg_name
        self.v_len = v_len
        self.off_1 = off_1
        self.off_2 = off_2
        self.off_3 = off_3
        self.off_4 = off_4

    def get(self, regs=None):
        """
            value get

            @param: regs : DICT : reg dict

            @return: INT :

            !+ in run_cbk, xrkdbg.getRegs() ret wrong regs, caller provide regs instead
        """
        if regs is None:
            regs = xrkdbg.getRegs()
        addr_calcer = addrCalcer(regs[self.reg_name], off_1=self.off_1, off_2=self.off_2, off_3=self.off_3, off_4=self.off_4)
        return invoke_v_get(addr_calcer, self.v_len)


class vGetterRegOnly(vGetterBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, reg_name):
        """
            @param: reg_name : STRING : reg name, get it's value
        """
        self.reg_name = reg_name

    def get(self, regs=None):
        """
            get value

            @param: regs : DICT :
            @return: INT :

            !+ in run_cbk, xrkdbg.getRegs() ret wrong regs, caller provide regs instead
        """
        if regs is None:
            regs = xrkdbg.getRegs()
        return regs[self.reg_name]


class vGetterRegOnlyPageBase(vGetterBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, reg_name):
        self.reg_name = reg_name

    def get(self, regs=None):
        if regs is None:
            regs = xrkdbg.getRegs()
        page = xrkdbg.getMemoryPageByAddress(regs[self.reg_name])
        assert page is not None
        return page.getBaseAddress()


class vGetterRegOnlyPageSize(vGetterBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, reg_name):
        self.reg_name = reg_name

    def get(self, regs=None):
        if regs is None:
            regs = xrkdbg.getRegs()
        page = xrkdbg.getMemoryPageByAddress(regs[self.reg_name])
        assert page is not None
        return page.getSize()


class vGetterStack(vGetterBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, stack_offset, is_negative=False, v_len=4, off_1=None, off_2=None, off_3=None, off_4=None):
        """
            @param: is_negative: default False, when set True, we get something just "abandoned" by previous function
        """
        self.stack_offset = stack_offset
        self.is_negative = is_negative
        self.v_len = v_len
        self.off_1 = off_1
        self.off_2 = off_2
        self.off_3 = off_3
        self.off_4 = off_4

    def get(self, regs=None):
        """
            in run_cbk, xrkdbg.getRegs() ret wrong regs, caller provide regs instead
        """
        if regs is None:
            regs = xrkdbg.getRegs()
        stack_addr = self.is_negative and regs["ESP"] - self.stack_offset or regs["ESP"] + self.stack_offset
        addr_calcer = addrCalcer(stack_addr, off_1=self.off_1, off_2=self.off_2, off_3=self.off_3, off_4=self.off_4)
        return invoke_v_get(addr_calcer, self.v_len)


class vGetterMmSlice(vGetterBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    pass


def __invoke_mm_get(addr, mm_size, off_1=None, off_2=None, off_3=None, off_4=None):
    """
        get a range of memory
    """
    pass


class mmGetterBase:
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self):
        pass


class mmGetterSolid(mmGetterBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, buf):
        self.buf = buf

    def get(self, regs=None):
        return self.buf


class mmGetterDirect(mmGetterBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, addr, mm_size=4, off_1=None, off_2=None, off_3=None, off_4=None):
        self.mm_size = mm_size
        self.addr_calcer = addrCalcer(addr, off_1=off_1, off_2=off_2, off_3=off_3, off_4=off_4)

    def get(self, regs=None):
        """
            @param: regs: None, just to stay same with other two types of gettrs
        """
        return __invoke_mm_get(self.addr_calcer, self.mm_size)


class mmGetterReg(mmGetterBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, reg_name, mm_size=4, off_1=None, off_2=None, off_3=None, off_4=None):
        self.reg_name = reg_name
        self.mm_size = mm_size
        self.off_1 = off_1
        self.off_2 = off_2
        self.off_3 = off_3
        self.off_4 = off_4

    def get(self, regs=None):
        """
            in run_cbk, xrkdbg.getRegs() ret wrong regs, caller provide regs instead
        """
        if regs is None:
            regs = xrkdbg.getRegs()
        addr_calcer = addrCalcer(regs[self.reg_name], off_1=self.off_1, off_2=self.off_2, off_3=self.off_3, off_4=self.off_4)
        return __invoke_mm_get(addr_calcer, self.mm_size)


class mmGetterStack(mmGetterBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, stack_offset, is_negative=False, mm_size=4, off_1=None, off_2=None, off_3=None, off_4=None):
        self.stack_offset = stack_offset
        self.is_negative = is_negative
        self.mm_size = mm_size
        self.off_1 = off_1
        self.off_2 = off_2
        self.off_3 = off_3
        self.off_4 = off_4

    def get(self, regs=None):
        """
            in run_cbk, xrkdbg.getRegs() ret wrong regs, caller provide regs instead
        """
        if regs is None:
            regs = xrkdbg.getRegs()
        stack_addr = self.is_negative and regs["ESP"] - self.stack_offset or regs["ESP"] + self.stack_offset
        addr_calcer = addrCalcer(stack_addr, off_1=self.off_1, off_2=self.off_2, off_3=self.off_3, off_4=self.off_4)
        return __invoke_mm_get(addr_calcer, self.mm_size)


# ---------------------------------------------------------------------------
# vComparer/mmComparer
# ---------------------------------------------------------------------------

#
# !+ all compare() return True/Flase. for interger comparsions, if u wanna get bigger/smaller result, do it with vGetterXX yourself.
#


class comparerBase:
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def compare(self, cmp_thing):
        """
            @return: BOOL
        """
        assert False


class vComparerDirect(comparerBase):
    # ---------------------------------------------------------------------------
    # save the trouble of "compare", than vGetterDirect
    # ---------------------------------------------------------------------------
    def __init__(self, cmp_value, addr, v_len=4, off_1=None, off_2=None, off_3=None, off_4=None):
        pass

    def compare(self, value):
        pass


class vComparerReg(comparerBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    pass


class vComparerStack(comparerBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    pass


class vComparerMmSlice(comparerBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, cmp_value, slice_offset, v_len=4, off_1=None, off_2=None, off_3=None, off_4=None):
        self.cmp_value = cmp_value
        self.slice_offset = slice_offset
        self.v_len = v_len
        self.off_1 = off_1
        self.off_2 = off_2
        self.off_3 = off_3
        self.off_4 = off_4

    def compare(self, mm_slice):
        v = xrkutil.get_v_from_mm_slice(mm_slice, self.slice_offset, self.v_len)
        v = vGetterDirect(addr=v, v_len=self.v_len, off_1=self.off_1, off_2=self.off_2, off_3=self.off_3, off_4=self.off_4).get()
        return v == self.cmp_value


class mmComparerDirect(comparerBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    pass


class mmComparerReg(comparerBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    pass


class mmComparerStack(comparerBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    pass


class mmCompareMmSlice(comparerBase):
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, cmp_buf, is_exact, slice_offset, off_1=None, off_2=None, off_3=None, off_4=None):
        self.cmp_buf = cmp_buf
        self.is_exact = is_exact
        self.slice_offset = slice_offset
        self.off_1 = off_1
        self.off_2 = off_2
        self.off_3 = off_3
        self.off_4 = off_4

    def compare(self, mm_slice):
        if self.off_1 is not None:
            v = xrkutil.get_v_from_mm_slice(mm_slice, self.slice_offset, v_len=4)
            if self.off_2 is not None:
                v = xrkdbg.readLong(v + self.off_2)
                if self.off_3 is not None:
                    v = xrkdbg.readLong(v + self.off_3)
                    if self.off_4 is not None:
                        v = xrkdbg.readLong(v + self.off_4)
            buf = xrkdbg.readMemory(v, len(self.cmp_buf))
            if self.is_exact:
                return buf == self.cmp_buf
            else:
                return self.cmp_buf in buf or buf in self.cmp_buf
        if self.is_exact:
            return buf == mm_slice[self.offset:self.offset + len(self.cmp_buf)]
        else:
            return buf in mm_slice[self.offset:]


# -------------------------------------------------------------------------
# callback
# -------------------------------------------------------------------------


def invoke_cbk(cbk, param1=None, param2=None, param3=None, param4=None):
    """
        !+ might be called by other modules, so can't be private
    """
    if param1 is None:
        cbk()
    elif param2 is None:
        cbk(param1)
    elif param3 is None:
        cbk(param1, param2)
    elif param4 is None:
        cbk(param1, param2, param3)
    else:
        cbk(param1, param2, param3, param4)


class cbkStructBase:
    # -------------------------------------------------------------------------
    #  class with method name: invoke(self, xxx)
    # -------------------------------------------------------------------------
    def __init__(self):
        pass


class cbkStruct(cbkStructBase):
    # -------------------------------------------------------------------------
    # cbk with no dynamic params
    # -------------------------------------------------------------------------
    def __init__(self, cbk, param1=None, param2=None, param3=None, param4=None):
        self.cbk = cbk
        self.param1 = param1
        self.param2 = param2
        self.param3 = param3
        self.param4 = param4

    def invoke(self):
        """
            invoke cbk
        """
        invoke_cbk(self.cbk, self.param1, self.param2, self.param3, self.param4)


def invoke_cbk_run(cbk, regs, param1=None, param2=None, param3=None, param4=None):
    """
        !+ might be called by other modules, so can't be private
    """
    if param1 is None:
        cbk(regs=regs)
    elif param2 is None:
        cbk(param1, regs=regs)
    elif param3 is None:
        cbk(param1, param2, regs=regs)
    elif param4 is None:
        cbk(param1, param2, param3, regs=regs)
    else:
        cbk(param1, param2, param3, param4, regs=regs)


class cbkStructRun(cbkStructBase):
    # -------------------------------------------------------------------------
    # cbk with regs as dynamic params, for hooking, invoke when hook hit, in hook.run()
    # -------------------------------------------------------------------------
    def __init__(self, cbk, param1=None, param2=None, param3=None, param4=None):
        """
            @param: cbk: method, prototype: cbk(regs, param1=None, param2=None, param3=None, param4=None)
        """
        self.cbk = cbk
        self.param1 = param1
        self.param2 = param2
        self.param3 = param3
        self.param4 = param4

    def invoke(self, regs):
        """
            invoke cbk, but set regs as one param
        """
        invoke_cbk_run(self.cbk, regs, self.param1, self.param2, self.param3, self.param4)


class cbkStructApiValid(cbkStructBase):
    # -------------------------------------------------------------------------
    # cbk with api address as dynamic param, invoke when new dll loaded, in run_LoadDllEvent, to install api hook at dynamic address
    # -------------------------------------------------------------------------
    def __init__(self, dll_name, api_name, cbk):
        """
            cbk to call when dll load, and api become valid

            @param: dll_name: STRING: newly loaded dll name
            @param: api_name: STRING: newly api that become valid
            @param: cbk: method with prototype: cbk_xx(dll_name, api_name, api_addr)
        """
        self.dll_name = dll_name
        self.api_name = api_name
        self.cbk = cbk

    def invoke(self, api_addr):
        """
            @param: api_addr: INT: address of api
        """
        self.cbk(self.dll_name, self.api_name, api_addr)


class cbkStructDllLoaded(cbkStructBase):
    # -------------------------------------------------------------------------
    # cbk with (evt, image_name, image_path) as dynamic param, invoke when new dll loaded, in run_LoadDllEvent, can do many things, like to install all api hooks for this dll
    # -------------------------------------------------------------------------
    def __init__(self, cbk):
        """
            cbk to call when dll load

            @param: cbk: method with prototype: cbk_xx(evt, image_name, image_path)
        """
        self.cbk = cbk

    def invoke(self, evt, image_name, image_path):
        """
            invoke cbk
        """
        self.cbk(evt, image_name, image_path)


class loadDllCbkStruct:
    # -------------------------------------------------------------------------
    # cbks to call for one single dll
    #
    # there is no self.invoke_all_cbks() method, because we don't have all api address for each cbk
    # -------------------------------------------------------------------------
    def __init__(self, dll_name):
        """
            @param: dll_name : STRING : newly loaded dll name
        """
        self.dll_name = dll_name

        # a list of cbkStructApiValid
        self.cbks = []

    def add_cbk(self, api_name, cbk_proxy):
        """
            add cbk to self.cbks, if api_name not added

            @param: api_name  : STRING : api name
            @param: cbk_proxy : method : a proxy function. actually, this: proxy_install_api_hook_by_name

            @return: BOOL : True  : api not exist, add success
                            False : api already exist, add fail
        """
        for c in self.cbks:
            if c.api_name == api_name:
                xrkdbg.log("cbk_proxy already added. dll_name: %s, api_name: %s" % (self.dll_name, api_name), highlight=1)
                return False

        cbk_ = cbkStructApiValid(self.dll_name, api_name, cbk_proxy)
        self.cbks.append(cbk_)

        return True

    def remove_cbk(self, api_name):
        """
            remove cbk from self.cbks, if cbk is added

            @param: api_name : STRING : api name
        """
        for c in self.cbks:
            if c.api_name == api_name:
                self.cbks.remove(c)
                return

    def remove_cbks(self, api_names):
        """
            remove cbks from self.cbks

            @param: api_names : LIST : a list of api names
        """
        for c in self.cbks:
            if c.api_name in api_names:
                self.cbks.remove(c)

    def check_has_cbk(self):
        """
            check has cbk available
        """
        return len(self.cbks) == 0


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------


class mmSearchDescriptor:
    # ---------------------------------------------------------------------------
    #
    # ---------------------------------------------------------------------------
    def __init__(self, desc, desc_list, v_getter_mm, cbks_cmparers=None):
        """
            @param: desc          : STRING : obj description, for log
            @param: desc_list     : LIST   : a list of mm slices and integers(representing lenght of any mm)
            @param: v_getter_mm   : obj    : obj of class vGetterMmSlice
            @param: cbks_cmparers : LIST   : a list of cbkFilterByXX objs, like: cbkFilterByValue/cbkFilterByString
        """
        self.desc = desc
        self.desc_list = desc_list
        self.v_getter_mm = v_getter_mm
        self.cbks_cmparers = cbks_cmparers
        self.addr_mm_dict = None

    def get_len(self):
        """
            get total len of desc_list
        """
        return xrkutil.get_desc_list_len(self.desc_list)

    def set_addrs(self, addrs):
        """
            set searched addrs, for filter and calc final address

            @param: addrs : LIST : a list of address
        """
        self.addr_mm_dict = addrs

    def apply_filter_v(self, offset, value, v_len=4):
        """
            @param: offset :
            @param: value  :
            @param: v_len  :
        """
        assert self.addr_mm_dict is not None
        if len(self.addr_mm_dict) == 0:
            xrklog.error("can not apply custom v filter to none addrs. desc: %s" % self.desc)
            assert False
        v_comparer = vComparerMmSlice(value, offset, v_len=v_len)
        tmp = {}
        for (d, x) in self.addr_mm_dict.items():
            if v_comparer.compare(x):
                tmp[d] = x
        self.addr_mm_dict = tmp

    def apply_filters(self):
        """
            apply filters to searched addrs, and remove addrs that doesn't pass all filters
        """
        assert self.addr_mm_dict is not None
        if len(self.addr_mm_dict) == 0:
            xrklog.error("can not apply filters to none addrs. desc: %s" % self.desc)
            assert False
        if self.cbks_cmparers is not None and len(self.cbks_cmparers) != 0:
            tmp = {}
            for (d, x) in self.addr_mm_dict.items():
                is_ok = True
                for cbk_filter in self.cbks_cmparers:
                    if not cbk_filter.compare(x):
                        is_ok = False
                        break
                if is_ok:
                    tmp[d] = x
            self.addr_mm_dict = tmp

    def calc(self):
        """
            calc final value
        """
        assert self.addr_mm_dict is not None
        assert self.v_getter_mm is not None
        if len(self.addr_mm_dict) == 0:
            xrklog.error("can not calc to none addrs. desc: %s" % self.desc)
            assert False
        elif len(self.addr_mm_dict) != 1:
            xrklog.error("calc more than 1 addrs. desc: %s, addrs: %s" % (self.desc, self.addr_mm_dict.keys()), verbose=True)
            ret = 0
            for (d, x) in self.addr_mm_dict.items():
                if ret == 0:
                    ret = self.v_getter_mm.get(x)
                    assert ret != 0
                else:
                    assert ret == self.v_getter_mm.get(x)
            return ret
        else:
            return self.v_getter_mm.get(self.addr_mm_dict.values()[0])


def game_str_to_desc_list(game_str, splitter=" ", c1=None, c2=None):
    """
        convert game string to desc list, and get c start index

        @param: game_str:
                         only "x":          B9 x x x x E8 ? ? ? ? 8B 4C 24 04 F7 D8 1B C0 F7 D8 48 89 41 04 B0 01 C3
                         both "x" and "z":  8B CE E8 z z z z A3 x x x x 8B 4C 24 10 64 89 0D 00 00 00 00 59 5E 83 C4 14 C3 33 C0 A3
                         none:              6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC AC 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 A8 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 C0 01 00 00 64 A3 00 00 00 00 8B F1 89 74 24

        @param: splitter: " " as default. might be "\\x"

        @param: c1: default is None
        @param: c2: default is None

        @return: TUPLE: (desc_list, c_index_1, c_index_2), c_index_x can be None, if no "x/z" found in game_str or param c1/c2 is None
    """
    strs = game_str.split(splitter)
    desc_list = []
    c_index_1 = None
    c_index_2 = None
    i = 0
    while i < len(strs):
        # "B9" or "x"
        assert len(strs[i]) <= 2
        if c1 is not None and strs[i] == c1:
            # only a pair of c1
            assert c_index_1 is None and i != 0
            c_index_1 = i

        if c2 is not None and strs[i] == c2:
            assert c_index_2 is None and i != 0
            c_index_2 = i

        if strs[i] in ["x", "z"]:
            assert len(desc_list) != 0
            if type(desc_list[-1]) is str:
                desc_list.append(4)
            else:
                desc_list[-1] = desc_list[-1] + 4
            i = i + 4

        elif strs[i] == "?":
            assert len(desc_list) != 0
            if type(desc_list[-1]) is str:
                desc_list.append(1)
            else:
                desc_list[-1] = desc_list[-1] + 1
            i = i + 1

        else:
            assert len(strs[i]) == 2
            tmp_chr = chr(string.atoi(strs[i], 16))
            if len(desc_list) == 0 or type(desc_list[-1]) is not str:
                desc_list.append(tmp_chr)
            else:
                desc_list[-1] = desc_list[-1] + tmp_chr
            i = i + 1

    return desc_list, c_index_1, c_index_2


def game_str_to_desc_list_only_q(game_str):
    """
        convert game string to desc list.

        @param: game_str : STRING : with none "x" nor "z", only has "?", like:
                                    6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC AC 01 00 00 A1 ? ? ? ? 33

        @return: STRING :
    """
    ret, c_index_1, c_index_2 = game_str_to_desc_list(game_str)
    return ret


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
