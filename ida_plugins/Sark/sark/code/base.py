# -*- coding: utf-8 -*-

"""
"""

import collections
import string

import idaapi
import idc
import idautils

from ..core import get_func, get_native_size
from .. import exceptions

NAME_VALID_CHARS = string.ascii_letters + string.digits + "?_:"


# ---------------------------------------------------------------------------
DTYP_TO_SIZE = {
    idaapi.dt_byte: 1,
    idaapi.dt_word: 2,
    idaapi.dt_dword: 4,
    idaapi.dt_float: 4,
    idaapi.dt_double: 8,
    idaapi.dt_qword: 8,
    idaapi.dt_byte16: 16,
    idaapi.dt_fword: 6,
    idaapi.dt_3byte: 3,
    idaapi.dt_byte32: 32,
    idaapi.dt_byte64: 64,
}


def dtyp_to_size(dtyp):
    """
        operand type to operand size

        @param: dtyp : char : idaapi.op_t.dtyp
                              type of the operand itself, not the size of the addressing mode
        @return: int :
    """
    return DTYP_TO_SIZE[dtyp]


def is_ea_call(ea):
    """
        check if insn that ea points to is CALL instruction

        @param: ea : int : address

        @return: bool :
        @raise:
    """
    insn = idautils.DecodeInstruction(ea)
    if insn is None:
        raise exceptions.SarkException("invalid ea: %.8X" % ea)

    feature = insn.get_canon_feature()
    return feature & idaapi.CF_CALL


# ---------------------------------------------------------------------------
def get_register_info(reg_name):
    """
        is this done during debug session?
    """
    ri = idaapi.reg_info_t()
    success = idaapi.parse_reg_name(reg_name, ri)
    if not success:
        raise exceptions.SarkInvalidRegisterName("No register named {!r}".format(reg_name))
    return ri


def get_register_id(reg_name):
    return get_register_info(reg_name).reg


def get_register_size(reg_name):
    return get_register_info(reg_name).size


def get_register_name(reg_id, size=None):
    if size is None:
        size = get_native_size()
    return idaapi.get_reg_name(reg_id, size)


# ---------------------------------------------------------------------------
def operand_has_displacement(operand):
    """
        check if operand has displacement

        @param: operand : obj : idaapi.op_t()
    """
    # idaapi.o_phrase : Memory Ref [Base Reg + Index Reg]
    # idaapi.o_idspl  : Memory Reg [Base Reg + Index Reg + Displacement].
    return operand.type in (idaapi.o_phrase, idaapi.o_displ)


def operand_get_displacement(operand):
    """
        return virtual address used by the operand.

        @param: operand : obj : idaapi.op_t()
    """
    return operand.addr


# ---------------------------------------------------------------------------
def is_same_function(ea1, ea2):
    """
        check if 2 ea in the scope of same function

        @param: ea1 : int :
        @param: ea2 : int :

        @return: bool :
    """
    try:
        return get_func(ea1).startEA == get_func(ea2).startEA
    except:
        pass

    return False


Selection = collections.namedtuple("Selection", "start end")


def get_selection(always=True):
    """
        get selection that user selected

        @param: always : bool : (optional, dft=True)is forced return some selection.
                                if Flase and BADADDR selected, will raise Exception

        @return: named tuple : ["start", "end"]
        @raise:
    """
    start = idc.SelStart()
    end = idc.SelEnd()

    if idaapi.BADADDR in (start, end):
        if not always:
            raise exceptions.SarkNoSelection()

        ea = idc.here()
        start = idaapi.get_item_head(ea)
        end = idaapi.get_item_end(ea)

    return Selection(start, end)


def format_name(name):
    try:
        return "".join(char if char in NAME_VALID_CHARS else "_" for char in name)
    except:
        return ""


def demangle(name, disable_mask=0):
    try:
        demangled_name = idaapi.demangle_name2(name, disable_mask)
    except AttributeError:
        # Backwards compatibility with IDA 6.6
        demangled_name = idaapi.demangle_name(name, disable_mask)

    if demangled_name:
        return demangled_name

    return name


def get_offset_name(ea):
    # Try and get the function name
    try:
        func = get_func(ea)
        name = idc.GetTrueName(func.startEA)
        name = demangle(name, 0x60)  # MNG_NOTYPE | MNG_NORETTYPE
        if name:
            offset = ea - func.startEA
            if offset:
                return '{}+{:X}'.format(name, offset)
            return name
    except exceptions.SarkNoFunction:
        pass

    # If that failed, use the segment name instead.
    segment = idaapi.getseg(ea)
    name = idaapi.get_true_segm_name(segment)
    offset_format = '{{:0{}X}}'.format(get_native_size() * 2)
    ea_text = offset_format.format(ea)
    if name:
        return '{}:{}'.format(name, ea_text)

    # Nothing found, simply return the address
    return ea_text
