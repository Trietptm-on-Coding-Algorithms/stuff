# -*- coding: utf-8 -*-

"""
    cloud thing
    if running as PyCommands, use xrkutil.serialize_set/serialize_get()
"""

import os
import sys
import inspect
import traceback

try:
    import xrkutil
except:
    this_path = os.path.split(os.path.realpath(inspect.stack()[-1][1]))[0]
    sys.path.append(this_path)
    try:
        import xrkutil
    except Exception, e:
        import immlib as dbglib
        dbg = dbglib.Debugger()
        dbg.log("xrk cloud import error: %s" % e, highlight=1)
        error = traceback.format_exc()
        while len(error) > 200:
            tmp = error[:200]
            dbg.log("  %s" % tmp, highlight=1)
            error = error[200:]
        dbg.log("  %s" % error, highlight=1)

        assert False


# -------------------------------------------------------------------------
# globals
# -------------------------------------------------------------------------


__IS_AS_PYCOMMANDS__ = True


# -------------------------------------------------------------------------
# misc
# -------------------------------------------------------------------------


v_misc_dict = {}


def cloud_misc_get(id_):
    """
        get value by id_ from cloud_dict/v_misc_dict

        @param: id_ : anyting that can be key of dict, STRING is suggested

        @return: value, or None
    """
    k_misc = __IS_AS_PYCOMMANDS__ and xrkutil.serialize_get("cloud_misc_dict") or v_misc_dict

    if k_misc is not None and id_ in k_misc:
        return k_misc[id_]
    return None


def cloud_misc_set(id_, value):
    """
        set somthing to cloud_dict/v_misc_dict

        @param: id_   : anything that can be key of dict
        @param: value : anything that can be value of dict
    """
    k_misc = __IS_AS_PYCOMMANDS__ and xrkutil.serialize_get("cloud_misc_dict", default={}) or v_misc_dict

    k_misc[id_] = value

    if __IS_AS_PYCOMMANDS__:
        xrkutil.serialize_set("cloud_misc_dict", k_misc)


# -------------------------------------------------------------------------
# xx
# -------------------------------------------------------------------------


def cloud_get(id_, default=None):
    if __IS_AS_PYCOMMANDS__:
        if default is None:
            return xrkutil.serialize_get(id_)
        else:
            return xrkutil.serialize_get(id_, default=default)
    else:
        assert False


def cloud_set(id_, value):
    if __IS_AS_PYCOMMANDS__:
        xrkutil.serialize_set(id_, value)
    else:
        assert False


# -------------------------------------------------------------------------
# END OF FILE
# -------------------------------------------------------------------------
