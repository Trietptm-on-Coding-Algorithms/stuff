# -*- coding: utf-8 -*-

"""
log utils:
    format: add prefix, split into lines, format table, etc
    log: format, then call xrkutil.log_lines()

    !+ this py calls function provided by xrkutil, because this py don't know where to log to.
"""

import os
import sys
import chardet
import inspect
import win32api
import traceback

try:
    import xrkutil
    import xrkdbg
except:
    this_path = os.path.split(os.path.realpath(inspect.stack()[-1][1]))[0]
    sys.path.append(this_path)
    try:
        import xrkutil
        import xrkdbg
    except Exception, e:
        lines = ["xrklog import error: %s" % e]
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
                dbg.log(line, highlight=1)
        except:
            for line in lines:
                print line

        assert False

# ---------------------------------------------------------------------------
# global const
# ---------------------------------------------------------------------------


v_log_prefix = "[*][*][*]"
v_log_prefix_empty = " " * len(v_log_prefix)
"""
v_log_prefix - tid - msg:
    [*][*][*] [      123] msg
    [*][*][*] [   (M)123] msg
"""
v_len_row = 200
v_len_row_max = v_len_row - len(v_log_prefix) - 10 - 1


# ---------------------------------------------------------------------------
# util
# ---------------------------------------------------------------------------


def highlight(notice="come on baby!"):
    """
        print notice red, with header and tail

        @param: notice : STRING : msg to print
    """
    lines = []
    lines.append("*" * 100)
    sub_lines = split_into_lines(notice, 200)
    for sub_line in sub_lines:
        lines.append("****** %s" % sub_line)
    lines.append("*" * 100)

    xrkutil.log_lines(lines, highlight=True)


def list_to_lines(list_):
    """
        value desc

        @param: list_ : LIST : a list of something

        @return: LIST : a list of strings
    """
    lines = []
    for l in list_:
        lines.append(xrkutil.value_desc(l))
    return lines


# ---------------------------------------------------------------------------
# log: info/warn/error/high, as table/lines, to dbgview/immlog
# ---------------------------------------------------------------------------


def dbgview(str_):
    """
        log to dbgView

        @param: str_ : STRING : string to dbgview

        !+ native Win32 API has xxA and xxW, but python only has xx.
    """
    """
    if chardet.detect(str_)["encoding"] != "ascii":
        str_ = str_.encode("UTF-8")
    """
    if len(str_) == 0:
        # empty str encoding is None
        str_ = " "

    assert chardet.detect(str_)["encoding"] == "ascii"
    win32api.OutputDebugString(str_)


def dbgview_lines(strs):
    """
        @param: strs : LIST : a list of strings to dbgview
    """
    for str_ in strs:
        dbgview(str_)


def __log_lines(lines, addr=0xbadf00d, highlight=False, gray=False, verbose=False):
    """
        proxy to xrkutil.log_lines()

        @param: lines     : LIST : a list of strings to print
        @param: addr      : INT  : address
        @param: highlight : BOOL : is print red
        @param: gray      : BOOL : is print white
        @param: verbose   : BOOL : is verbose log
    """
    xrkutil.log_lines(lines=lines, addr=addr, highlight=highlight, gray=gray, verbose=verbose)


# -------------------------------------------------------------------------
# table log
# -------------------------------------------------------------------------


extra_len = 7
table_len_max = 200


def __format_table_header(table_len, header):
    """
        |                            header                             |
    """
    sp1 = (table_len - len(header) / 2 - extra_len) / 2
    sp2 = table_len - len(header) - sp1 - extra_len + 3
    return "| " + " " * sp1 + header + " " * sp2 + " |"


def __format_table_line(table_len, table_len_half, d_line, x_line):
    """
        | key3333333333333333333333     | value3                        |
    """
    return "| " + d_line + " " * (table_len_half - len(d_line)) + " | " + x_line + " " * (table_len_half - len(x_line)) + " |"


def __format_table_line_x(table_len, table_len_left, d_line, x_line):
    """
        need to check, because might be errors
    """
    if type(d_line) != str:
        highlight("format table line x, d not str: %s" % d_line)
    if type(x_line) != str:
        highlight("format table line x, x not str: %s" % x_line)
    table_len_right = table_len - table_len_left
    return "| " + d_line + " " * (table_len_left - len(d_line)) + " | " + x_line + " " * (table_len_right - len(x_line) - extra_len) + " |"


def __format_table_lines(table_len, d, x):
    """
        | key3333333333333333333333     | value3                        |

        | key33333333333333333333333333 | value3                        |
        | 3333333333333333333333        |                               |

        | key3                          | value333333333333333333333333 |
        |                               | 3333333333                    |

        | key33333333333333333333333333 | value333333333333333333333333 |
        | 3333333333333333333333        | 3333333333                    |
    """
    table_len_half = table_len / 2
    lines = []
    d_lines = split_into_lines(d, table_len_half)
    x_lines = split_into_lines(x, table_len_half)
    for i in range(max(len(d_lines), len(x_lines))):
        d_line = i < len(d_lines) and d_lines[i] or ""
        x_line = i < len(x_lines) and x_lines[i] or ""
        lines.append(__format_table_line(table_len, table_len_half, d_line, x_line))
    return lines


def __format_table_lines_x(table_len, left_len, d, x):
    lines = []
    d_lines = split_into_lines(d, left_len)
    x_lines = split_into_lines(x, table_len - left_len - extra_len)
    for i in range(max(len(d_lines), len(x_lines))):
        d_line = i < len(d_lines) and d_lines[i] or ""
        x_line = i < len(x_lines) and x_lines[i] or ""
        lines.append(__format_table_line_x(table_len, left_len, d_line, x_line))
    return lines


def __get_empty_table_lines(header=""):
    lines = []
    lines.append("-----------------------------------------------------------------")
    if len(header) == 0:
        lines.append("---------------------- no       header --------------------------")
    else:
        sp1 = (65 - len(header)) / 2 - 1
        sp2 = 65 - len(header) - sp1 - 2
        lines.append("%s %s %s" % ("-" * sp1, header, "-" * sp2))
    lines.append("-----------------------------------------------------------------")
    return lines


def get_dict_str_as_table(dict_, header="", line_spliter=False):
    """
        -----------------------------------------------------------------
        |                            header                             |
        | key1                          | value11111111                 |
        | key222222222                  | vaue2                         |
        | key3333333333333333333333     | value3                        |
        | ke4                           | value44444444444444444        |
        -----------------------------------------------------------------

        extra_len: |  | |: 7
    """
    assert dict_ is not None
    if len(dict_) == 0:
        return __get_empty_table_lines(header=header)

    # calc table len
    table_len = 75
    for (d, x) in dict_.items():
        len_ = len(d) + len(x)
        if table_len < len_:
            if len_ <= (table_len_max - extra_len):
                table_len = len_
            else:
                table_len = (table_len_max - extra_len)
                break
    table_len = table_len + extra_len
    spliter = "-" * table_len
    lines = []
    lines.append(spliter)
    # header
    if len(header) != 0:
        lines.append(__format_table_header(table_len, header))
        if line_spliter:
            lines.append(spliter)
    # lines
    left_len = table_len / 2
    left_len_max = len(sorted(dict_.keys(), key=len)[-1]) + 1
    right_len_max = len(sorted(dict_.values(), key=len)[-1]) + 1
    if left_len_max + right_len_max < table_len:
        # both too short, split by half. pass because it's set as default
        # left_len = table_len / 2
        pass
    else:
        # left too short, move towards left
        left_len = min(left_len_max, table_len / 2)
    for (d, x) in dict_.items():
        for sub_line in __format_table_lines_x(table_len, left_len, d, x):
            lines.append(sub_line)
        if line_spliter:
            lines.append(spliter)
    """
    # lines
    for (d, x) in dict_.items():
        for sub_line in __format_table_lines(table_len, d, x):
            lines.append(sub_line)
        if line_spliter:
            lines.append(spliter)
    """
    # tail
    if not line_spliter:
        lines.append(spliter)
    return lines


def get_dict_as_table(dict_, header="", exclude_keys=[], line_spliter=False):
    """
        1. convert k and value to string
        2. get dict str as table
    """
    dict_ = xrkutil.exclude_keys_dict(dict_, exclude_keys=exclude_keys)[0]
    dict_str = {}
    for (d, x) in dict_.items():
        dict_str[xrkutil.value_desc(d)] = xrkutil.value_desc(x)
    return get_dict_str_as_table(dict_str, header=header, line_spliter=line_spliter)


def get_binary_dict_as_table(dict_, header="", exclude_keys=[], line_spliter=False, max_bin_len=0x30):
    dict_ = xrkutil.exclude_keys_dict(dict_, exclude_keys=exclude_keys)[0]
    dict_str = {}
    for (d, x) in dict_.items():
        assert type(x) == str
        dict_str[xrkutil.value_desc(d)] = xrkutil.buf_to_str(x[:max_bin_len])
    return get_dict_str_as_table(dict_str, header=header, line_spliter=line_spliter)


def log_table_str(dict_, header="", line_spliter=False, addr=0xbadf00d, highlight=False, gray=False):
    """
        log as table

        @param: dict_: a dict of string
    """
    lines = get_dict_str_as_table(dict_, header=header, line_spliter=line_spliter)
    __log_lines(lines, addr=addr, highlight=highlight, gray=gray)


def log_table(dict_, header="", exclude_keys=[], line_spliter=False, addr=0xbadf00d, highlight=False, gray=False):
    """
        log as table

        @param: dict_: a dict of anything
    """
    lines = get_dict_as_table(dict_, header=header, exclude_keys=exclude_keys, line_spliter=line_spliter)
    __log_lines(lines, addr=addr, highlight=highlight, gray=gray)


def log_table_binary(dict_, header="", exclude_keys=[], line_spliter=False, addr=0xbadf00d, highlight=False, gray=False, max_bin_len=0x30):
    """
        log as table, but second colume is binary
    """
    lines = get_binary_dict_as_table(dict_, header=header, exclude_keys=exclude_keys, line_spliter=line_spliter, max_bin_len=max_bin_len)
    __log_lines(lines, addr=addr, highlight=highlight, gray=gray)


def get_dict_attrs_descriptions(dict_, header="", exclude_keys=[]):
    """
        key1: key1, type: type1
        key2: key2, type: type2
    """
    dict_ = xrkutil.exclude_keys_dict(dict_, exclude_keys)[0]
    ret = []
    spa = ""
    if len(header) != 0:
        ret.append(header)
        spa = " " * len(header)
    for (d, x) in dict_.items():
        ret.append("%skey: %s, type: %s" % (spa, d, type(x)))
    return ret


def get_dict_attrs_descriptions_as_table(dict_, header="", exclude_keys=[], line_spliter=False):
    """
        -----------------------------
        | key1        | type1       |
        | key22222222 | type2       |
        -----------------------------
    """
    dict_ = xrkutil.exclude_keys_dict(dict_, exclude_keys)[0]
    ret = {}
    for (d, x) in dict_.items():
        ret[xrkutil.value_desc(d)] = xrkutil.value_type_desc(x)
    return get_dict_as_table(ret, header=header, line_spliter=line_spliter)


def get_dict_details_descriptions(dict_, header="", exclude_keys=[]):
    """
        header:
        key1: key1, value: value1
        key2: key2, value: value2
    """
    dict_ = xrkutil.exclude_keys_dict(dict_, exclude_keys)[0]
    ret = []
    spa = ""
    if len(header) != 0:
        ret.append(header)
        spa = " " * len(header)
    for (d, x) in dict_.items():
        ret.append("%skey: %s, value: %s" % (spa, xrkutil.value_desc(d), xrkutil.value_desc(x)))
    return ret


def get_dict_details_descriptions_as_table(dict_, header="", exclude_keys=[], line_spliter=False):
    """
        -----------------------------
        | key1        | value1      |
        | key22222222 | value2      |
        -----------------------------
    """
    dict_ = xrkutil.exclude_keys_dict(dict_, exclude_keys)[0]
    return get_dict_as_table(dict_, header=header, line_spliter=line_spliter)


# -------------------------------------------------------------------------
# prefix log
# -------------------------------------------------------------------------


def split_into_lines(msg, col_len=v_len_row):
    """
        msg -->
            msg_1
            msg_2
    """
    len_ = len(msg)
    if len_ <= col_len:
        return [msg]
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
            msg_ = msg[start:end]
            ret.append(msg_)
        return ret


def __split_into_lines_by_prefix(msg, add_prefix=False):
    """
        split into lines by add prefix or not
    """
    msgs = []
    if add_prefix:
        msgs = split_into_lines(msg, col_len=v_len_row_max)
    else:
        msgs = split_into_lines(msg, col_len=v_len_row)
    return msgs


def __prefix_tid_msg(msg):
    """
        msg: 1 line

        msg -->
            prefix - tid - msg
    """
    """
    # thread got in this method is always MainThread, because py script in executed in MainThread
    cur_t = threading.current_thread()
    if cur_t.name == "MainThread":
        tid = "(M)%X" % cur_t.ident
        spa = " " * (8 - len(tid))
        return "%s[%s%s] %s" % (v_log_prefix, spa, tid, msg)
    else:
        return "%s[%.8d] %s" % (v_log_prefix, cur_t.ident, msg)
    """
    return "%s[%.8d] %s" % (v_log_prefix, xrkdbg.getThreadId(), msg)


def __prefix_tid_empty_msg(msg):
    """
        msg: 1 line

        msg -->
            prefix - [tid] - msg
    """
    spa = " " * (8 + 2)
    return "%s%s %s" % (v_log_prefix, spa, msg)


def __prefix_empty_tid_empty_msg(msg):
    """
        msg: 1 line

        msg -->
            [prefix] - [tid] - msg
    """
    spa = " " * (8 + 2)
    return "%s%s %s" % (v_log_prefix_empty, spa, msg)


def __format_lines_ex(msgs, add_prefix=False):
    """
        format lines

        msgs:
            prefix - tid - msgs[0]
                                  msgs[1]
                                  msgs[2]
    """
    assert type(msgs) is list
    assert len(msgs) > 0
    lines = []
    spa = " " * len(msgs[0])
    if add_prefix:
        for i in range(len(msgs)):
            if i == 0:
                lines.append(__prefix_tid_msg(msgs[i]))
            else:
                lines.append(__prefix_empty_tid_empty_msg("%s%s" % (spa, msgs[i])))
    else:
        for i in range(len(msgs)):
            if i == 0:
                lines.append(msgs[i])
            else:
                lines.append("%s%s" % (spa, msgs[i]))
    return lines


def __format_lines(msgs, add_prefix=False):
    """
        format lines

        msgs:
            prefix - tid - msgs[0]
                           msgs[1]
                           msgs[2]
    """
    assert type(msgs) is list
    lines = []
    if add_prefix:
        for i in range(len(msgs)):
            if i == 0:
                lines.append(__prefix_tid_msg(msgs[i]))
            else:
                lines.append(__prefix_empty_tid_empty_msg(msgs[i]))
    else:
        lines = msgs
    return lines


def infos_ex(msgs, addr=0xbadf00d, add_prefix=False, verbose=False):
    """
        log infos

        msgs:
            prefix - tid - msgs[0]
                                  msgs[1]
                                  msgs[2]
    """
    __log_lines(__format_lines_ex(msgs, add_prefix=add_prefix), addr=addr, verbose=verbose)


def infos(msgs, addr=0xbadf00d, add_prefix=False, verbose=False):
    """
        log infos

        msgs:
            prefix - tid - msgs[0]
                           msgs[1]
                           msgs[2]

        !+ each line start at same index: 0
    """
    __log_lines(__format_lines(msgs, add_prefix=add_prefix), addr=addr, verbose=verbose)


def info(msg, addr=0xbadf00d, add_prefix=False, verbose=False):
    """
        @param: msg: len might more than 255

        msg:
            prefix - tid - msg_1
                           msg_2
                           msg_3

        !+ color: default color
    """
    if msg is None:
        infos(["info msg: None"], addr=addr, add_prefix=add_prefix, verbose=verbose)
        return

    if type(msg) != str:
        assert type(msg) == list
        assert len(msg) != 0
        assert type(msg[0]) == str
        infos(msgs=msg, addr=addr, add_prefix=add_prefix, verbose=verbose)
        return
    infos(__split_into_lines_by_prefix(msg, add_prefix=add_prefix), addr=addr, add_prefix=add_prefix, verbose=verbose)


def warns_ex(msgs, addr=0xbadf00d, add_prefix=False, verbose=False):
    """
        log warns

        msgs:
            prefix - tid - msgs[0]
                                  msgs[1]
                                  msgs[2]
    """
    __log_lines(__format_lines_ex(msgs, add_prefix=add_prefix), addr=addr, gray=True, verbose=verbose)


def warns(msgs, addr=0xbadf00d, add_prefix=False, verbose=False):
    """
        log warns

        msgs:
            prefix - tid - msgs[0]
                           msgs[1]
                           msgs[2]

        !+ each line start at same index: 0
    """
    __log_lines(__format_lines(msgs, add_prefix=add_prefix), addr=addr, gray=True, verbose=verbose)


def warn(msg, addr=0xbadf00d, add_prefix=False, verbose=False):
    """
        @param: msg: len might more than 255

        msg:
            prefix - tid - msg_1
                           msg_2
                           msg_3

        !+ color: gray color
    """
    if msg is None:
        warns(["warn msg: None"], addr=addr, add_prefix=add_prefix, verbose=verbose)
        return

    if type(msg) != str:
        assert type(msg) == list
        assert len(msg) != 0
        assert type(msg[0]) == str
        warns(msgs=msg, addr=addr, add_prefix=add_prefix, verbose=verbose)
        return
    warns(__split_into_lines_by_prefix(msg, add_prefix=add_prefix), addr=addr, add_prefix=add_prefix, verbose=verbose)


def errors_ex(msgs, addr=0xbadf00d, add_prefix=False, verbose=False):
    """
        log errors

        msgs:
            prefix - tid - msgs[0]
                                  msgs[1]
                                  msgs[2]
    """
    __log_lines(__format_lines_ex(msgs, add_prefix=add_prefix), addr=addr, highlight=1, verbose=verbose)


def errors(msgs, addr=0xbadf00d, add_prefix=False, verbose=False):
    """
        log errors

        msgs:
            prefix - tid - msgs[0]
                           msgs[1]
                           msgs[2]

        !+ each line start at same index: 0
    """
    __log_lines(__format_lines(msgs, add_prefix=add_prefix), addr=addr, highlight=1, verbose=verbose)


def error(msg, addr=0xbadf00d, add_prefix=False, verbose=False):
    """
        @param: msg: len might more than 255

        msg:
            prefix - tid - msg_1
                           msg_2
                           msg_3

        !+ color: highlight color
    """
    if msg is None:
        errors(["error msg: None"], addr=addr, add_prefix=add_prefix, verbose=verbose)
        return

    if type(msg) != str:
        assert type(msg) == list
        assert len(msg) != 0
        assert type(msg[0]) == str
        errors(msgs=msg, addr=addr, add_prefix=add_prefix, verbose=verbose)
        return
    errors(__split_into_lines_by_prefix(msg, add_prefix=add_prefix), addr=addr, add_prefix=add_prefix, verbose=verbose)


def highs_ex(msgs, addr=0xbadf00d, add_prefix=False, verbose=False):
    """
        log highs

        msgs:
            prefix - tid - msgs[0]
                                  msgs[1]
                                  msgs[2]
    """
    errors_ex(msgs, addr=addr, add_prefix=add_prefix, verbose=verbose)


def highs(msgs, addr=0xbadf00d, add_prefix=False, verbose=False):
    """
        log errors

        msgs:
            prefix - tid - msgs[0]
                           msgs[1]
                           msgs[2]

        !+ each line start at same index: 0
    """
    errors(msgs, addr=addr, add_prefix=add_prefix, verbose=verbose)


def high(msg, addr=0xbadf00d, add_prefix=False, verbose=False):
    """
        @param: msg: len might more than 255

        msg:
            prefix - tid - msg_1
                           msg_2
                           msg_3

        !+ color: highlight color
    """
    error(msg, addr=addr, add_prefix=add_prefix, verbose=verbose)


# ---------------------------------------------------------------------------
# misc
# ---------------------------------------------------------------------------


def format_params(v1, v2=None, v3=None, v4=None):
    if v2 is None:
        return xrkutil.value_desc(v1)
    if v3 is None:
        return "%s, %s" % (xrkutil.value_desc(v1), xrkutil.value_desc(v2))
    if v4 is None:
        return "%s, %s, %s" % (xrkutil.value_desc(v1), xrkutil.value_desc(v2), xrkutil.value_desc(v3))
    return "%s, %s, %s, %s" % (xrkutil.value_desc(v1), xrkutil.value_desc(v2), xrkutil.value_desc(v3), xrkutil.value_desc(v4))


# ---------------------------------------------------------------------------
# end of file
# ---------------------------------------------------------------------------
