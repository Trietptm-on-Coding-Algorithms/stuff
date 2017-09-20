# -*- coding: utf-8 -*-


"""
anything else
"""

import os
import wmi
import time
import random
import inspect
import chardet

import pefile

from my_ctypes import *
from defines import *
from windows_h import *

file_path = os.path.abspath(inspect.getsourcefile(lambda: 0))
file_dir = os.path.dirname(inspect.getsourcefile(lambda: 0))


# ---------------------------------------------------------------------------
# global main debugee name, set by xrkpydbg.py
global v_tmp_debugee_name
v_tmp_debugee_name = None

# global main debugee dir
global v_tmp_debugee_dir
v_tmp_debugee_dir = None


def debugee_name(has_ext=True):
    global v_tmp_debugee_name
    assert v_tmp_debugee_name is not None and len(v_tmp_debugee_name) != 0

    return has_ext and v_tmp_debugee_name or v_tmp_debugee_name.strip(".exe")


def debugee_dir():
    global v_tmp_debugee_dir
    return v_tmp_debugee_dir


def debugee_path():
    global v_tmp_debugee_name
    return os.path.abspath(v_tmp_debugee_name)


def gen_path_tail_debugee(tail, has_ext=True):
    """
        generate a path under debugee direcotry
    """
    global v_tmp_debugee_name
    assert v_tmp_debugee_name is not None and len(v_tmp_debugee_name) != 0
    global v_tmp_debugee_dir
    assert v_tmp_debugee_dir is not None and len(v_tmp_debugee_dir) != 0
    assert os.path.exists(v_tmp_debugee_dir)

    if has_ext:
        return os.path.join(v_tmp_debugee_dir, v_tmp_debugee_name + tail)
    else:
        return os.path.join(v_tmp_debugee_dir, v_tmp_debugee_name.strip(".exe") + tail)


def gen_path_prefix_time_tail_debugee(tail, has_ext=True):
    """
        generate a path under debugee directory, with time_str() as prefix
    """
    global v_tmp_debugee_name
    assert v_tmp_debugee_name is not None and len(v_tmp_debugee_name) != 0
    global v_tmp_debugee_dir
    assert v_tmp_debugee_dir is not None and len(v_tmp_debugee_dir) != 0
    assert os.path.exists(v_tmp_debugee_dir)

    if has_ext:
        return os.path.join(v_tmp_debugee_dir, time_str() + "_" + v_tmp_debugee_name + tail)
    else:
        return os.path.join(v_tmp_debugee_dir, time_str() + "_" + v_tmp_debugee_name.strip(".exe") + tail)


# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
class XPE(pefile.PE):
    # ---------------------------------------------------------------------------
    # wrapper of pefile.PE
    # ---------------------------------------------------------------------------
    def __init__(self, name):
        """
            @param: name : STRING : pe full path
        """
        pefile.PE.__init__(self, name)

    def get_export_table(self):
        """
            get parsed export table

            @return: obj : obj of ExportDirData
                     None
        """
        return hasattr(self, "DIRECTORY_ENTRY_EXPORT") and self.DIRECTORY_ENTRY_EXPORT or None

    def get_export_dict(self):
        """
            get parsed export table as dict

            @return: DICT: {export_name_1: export_addr_1, export_name_2: export_addr_2}
                     None
        """
        try:
            exports = self.get_export_table()
            if exports is not None and len(exports.symbols) != 0:
                ret = {}
                for export_item in exports.symbols:
                    ret[export_item.name] = export_item.address
                return ret
            return None
        except:
            return None

    def get_export_item_rva(self, export_name):
        """
            get export item rva by export name

            @param: INT
                    None
        """
        exports = self.get_export_table()
        if exports is not None:
            for export_item in exports.symbols:
                if export_item.name == export_name:
                    return export_item.address
        return None

    def get_ep_offset(self):
        return self.OPTIONAL_HEADER.AddressOfEntryPoint


# ---------------------------------------------------------------------------


def file_handle_to_name(handle):
    """
        this handle does't belong to debuger, we need to duplicate the handle first
    """
    assert False
    # create a file mapping from the dll handle.
    file_map = kernel32.CreateFileMappingA(handle, 0, PAGE_READONLY, 0, 1, 0)

    if file_map:
        # map a single byte of the dll into memory so we can query for the file name.
        kernel32.MapViewOfFile.restype = POINTER(c_char)
        file_ptr = kernel32.MapViewOfFile(file_map, FILE_MAP_READ, 0, 0, 1)

        if file_ptr:
            # query for the filename of the mapped file.
            filename = create_string_buffer(2048)
            psapi.GetMappedFileNameA(kernel32.GetCurrentProcess(), file_ptr, byref(filename), 2048)

            # store the full path. this is kind of ghetto, but i didn't want to mess with QueryDosDevice() etc ...
            path = os.sep + filename.value.split(os.sep, 3)[3]
            kernel32.UnmapViewOfFile(file_ptr)

        kernel32.CloseHandle(file_map)
        return path


# ---------------------------------------------------------------------------


def save_buf_to_file(tail, data):
    """
        generate a file under debugee direcotry, with time_str() as prefix, and write binary data to file
    """
    file_path = gen_path_prefix_time_tail_debugee(tail, has_ext=False)
    assert not os.path.exists(file_path)
    try:
        file = open(file_path, "bw")
    except:
        print "open file exception: %s" % file_path
    else:
        file.write(data)
        file.close()


def pid_to_proc_path(pid):
    """
    """
    proc_path = "[Invalid]"

    c = wmi.WMI()
    for proc in c.Win32_Process():
        if pid == proc.ProcessId:
            proc_path = str(proc.Name)
            break

    return proc_path


# ---------------------------------------------------------------------------


def data_to_unicode_str_ori(data, max_len):
    """
        @param: data    : raw :
        @param: max_len : int :

        @return: string :
    """
    discovered = ""
    every_other = True
    for char in data:
        if every_other:
            # if we've hit a non printable char, break
            if ord(char) < 32 or ord(char) > 126:
                break
            discovered += char
        every_other = not every_other

    if len(discovered) < max_len:
        return ""

    return discovered


def retrive_unicode_data(data, max_len):
    """
        @param: data    : raw :
        @param: max_len : int :

        @return: tuple : (string, int)
    """
    data_x = ""
    i = 0
    while i < len(data) and i < max_len:
        s = data[i:i + 2]
        if s[0] == "\x00" and s[1] == "\x00":
            break
        data_x = data_x + s
        i = i + 2
    return data_x, i


def data_to_unicode_str_encoding_ascii(data, max_len):
    """
        @param: data    : raw :
        @param: max_len : int :

        @return: string :
    """
    i = 0
    ret = ""
    while i < len(data) - 1 and i < max_len:
        s = data[i:i + 2]
        i = i + 2
        ret = ret + unicode(s).strip("\0")
    return ret


def data_to_unicode_str_my(data, max_len):
    """
        try to resolve unicode string from data

        @param: data    : raw :
        @param: max_len : int :

        @return: string :
    """
    encoding = chardet.detect(data)["encoding"]

    if encoding == "GB2312":
        return data.decode("GB2312")

    elif encoding == "ascii":
        return data_to_unicode_str_encoding_ascii(data, max_len)

    elif encoding == "windows-1252":
        return data.decode("windows-1252")

    elif encoding == "utf-8":
        return data.decode("utf-8")

    else:
        if encoding is not None:
            print "." * 100
            print "invalid decode: %s" % chardet.detect(data)
            print "." * 100

        # try multiple encodings
        try:
            return data_to_unicode_str_encoding_ascii(data, max_len)
        except:
            try:
                return data.decode("GB2312")
            except:
                return ""


def data_to_unicode_str(data, max_len):
    """
        todo: for invalid chars, we get "" here

        @param: data    : raw :
        @param: max_len : int :

        @return: unicode : unicode, not string
    """
    data, max_len = retrive_unicode_data(data, max_len)

    ret = data_to_unicode_str_my(data, max_len)
    if len(ret) == 0:
        ret = data_to_unicode_str_ori(data, max_len)

    return ret


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
