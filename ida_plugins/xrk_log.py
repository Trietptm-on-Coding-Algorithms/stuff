# -*- coding: utf-8 -*

"""
"""

import idaapi


def msg(prefix, str_):
    idaapi.msg("[INFO]%-20s%s\n" % (prefix, str_))


def msgs(prefix, strs):
    for str_ in strs:
        msg(prefix, str_)


def warn(prefix, str_):
    idaapi.msg("[WARN]%-20s%s\n" % (prefix, str_))
