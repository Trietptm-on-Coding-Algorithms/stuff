# -*- coding: utf-8 -*-

"""
"""

import os
import idc
import time

import idaapi


# ---------------------------------------------------------------------------
def time_str():
    """
        time string in this format: xx

        @return: STRING :
    """
    return time.strftime('%Y%m%d_%H_%M_%S', time.localtime(time.time()))


# ---------------------------------------------------------------------------
def get_idb_file_path():
    """
        TODO: there should be another better approach
    """
    # idaapi.get_input_file_path(): this return original path of idb file, even if file is copied to another directory
    file_path = idc.GetIdbPath()
    if file_path is None or len(file_path) == 0:
        return None
    return os.path.dirname(file_path)


def gen_path_in_idb_dir(tail, add_time_prefix=True):
    """
    """
    idb_file_path = get_idb_file_path()
    if idb_file_path is None or len(idb_file_path) == 0:
        return None

    if add_time_prefix:
        return os.path.join(idb_file_path, time_str() + "_" + tail)
    return os.path.join(idb_file_path, tail)


# ---------------------------------------------------------------------------

def _patch_bytes(addr, value, size):
    """
        patch a range of bytes to specificed value
    """
    for i in range(size):
        idaapi.patch_byte(addr + i, value)


def _clear_bytes(addr, size):
    """
        patch a range of bytes to 0
    """
    _patch_bytes(addr, 0, size)


def _nope_bytes(addr, size):
    """
        patch a range of bytes to 0x90
    """
    _patch_bytes(addr, 0x90, size)


def _get_len_till_0(addr):
    """
        iter addrs, till 0 is get
    """
    len_ = 0
    while idaapi.get_byte(addr + len_) != 0:
        len_ = len_ + 1
    return len_


def _patch_str(addr, str_):
    """
        patch str bytes, one by one
    """
    print "patch str, addr: 0x%X, str: %s" % (addr, str_)
    for i in range(len(str_)):
        idaapi.patch_byte(addr + i, ord(str_[i]))


def _replace_str(addr, str_, is_force=False):
    """
        replace str, check size first. if is_forst is specified, will patch whatever
    """
    len_ = _get_len_till_0(addr)
    if len_ < len(str_):
        if not is_force:
            print "!!!! replace str, this one is invalid. addr: 0x%X, str: %s" % (addr, str_)
            print "!!!! will not patch"
            return
        print "!!!! replace str, this one is invalid. addr: 0x%X, str: %s" % (addr, str_)
        print "!!!! will patch anyway, since is_force is specified as True"
    _clear_bytes(addr, len_)
    _patch_str(addr, str_)
    idaapi.make_ascii_string(addr, len(str_), idc.ASCSTR_C)


def _replace_str_rva(addr, base, str_, is_force=False):
    """
        replace str, by addr and base
    """
    _replace_str(addr - base, str_, is_force)
