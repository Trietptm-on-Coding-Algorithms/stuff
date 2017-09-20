# -*- coding: utf-8 -*

"""
test in plugin
"""

import idaapi
import xrk_log


# ---------------------------------------------------------------------------
# log, proxy to xrklog.py

v_log_header = "[XRK-TEST] >> "


def msg(str_):
    xrk_log.msg(v_log_header, str_)


def msgs(strs):
    xrk_log.msgs(v_log_header, strs)


def warn(str_):
    xrk_log.warn(v_log_header, str)


# ---------------------------------------------------------------------------
class hexrays_callback_info(object):

    def __init__(self):
        return

    def event_callback(self, event, *args):
        import traceback
        traceback.print_exc()

        try:
            print "evt: %s" % str(event)

        except:
            pass

        return 0


def callback(event, *args):
    import traceback
    traceback.print_exc()

    try:
        msg("evt: %s" % str(event))

    except:
        msg("exception")

    return 0


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if idaapi.init_hexrays_plugin():
        # x = hexrays_callback_info()
        # if idaapi.install_hexrays_callback(x.event_callback):
        if idaapi.install_hexrays_callback(callback):
            print "install callback success"
        else:
            print "install callback fail"
    else:
        print "hexrays not inited...."


# ---------------------------------------------------------------------------
class xrktest(idaapi.plugin_t):

    flags = idaapi.PLUGIN_FIX
    comment = "This is test script"

    help = "This is test script"
    wanted_name = "xrktest"
    wanted_hotkey = ""

    def init(self):
        # msg("init()")
        self.is_cbk_registered = False
        if idaapi.init_hexrays_plugin():
            msg("true........")
        else:
            msg("false..........")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        msg("run()")
        if idaapi.init_hexrays_plugin():
            msg("true........")
        else:
            msg("false..........")
        # self.is_cbk_registered = idaapi.install_hexrays_callback()
        msg("run() -- finish")

    def term(self):
        msg("term()")


# ---------------------------------------------------------------------------
def PLUGIN_ENTRY():
    return xrktest()

"""
if __name__ == "__main__":
    msg(idaapi.init_hexrays_plugin())
"""
