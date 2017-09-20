# -*- coding: utf-8 -*-

"""
x
"""

import os
import sys
import datetime
import traceback
from immlib import BpHook
from immlib import LogBpHook

try:
    import xrkmd
    import xrkmon
    import xrkdef
    import xrklog
    import xrkdbg
    import xrkhook
    import xrkutil
    import xrkcstk
    import xrkmonctrl
except:
    this_path = os.path.split(os.path.realpath(__file__))[0]
    sys.path.append(this_path)
    try:
        import xrkmd
        import xrkmon
        import xrkdef
        import xrklog
        import xrkdbg
        import xrkhook
        import xrkutil
        import xrkcstk
        import xrkmonctrl
    except Exception, e:
        import immlib as dbglib
        dbg = dbglib.Debugger()
        dbg.log("xxx import error: %s" % e, highlight=1)
        error = traceback.format_exc()
        while len(error) > 200:
            tmp = error[:200]
            dbg.log("  %s" % tmp, highlight=1)
            error = error[200:]
        dbg.log("  %s" % error, highlight=1)

        assert False


class testHook(BpHook):
    def __init__(self):
        BpHook.__init__(self)

    def run(self, regs):
        xrklog.high("running....", add_prefix=True)


def main(args):

    start = datetime.datetime.now()

    # xrkmonctrl.fake_main_md_name(r"C:\DOCUME~1\ADMINI~1\LOCALS~1\Temp\bijaweed.exe")

    # xrkmon.exec_args_str("--config --key test")

    # xrkhook.install_all_exception_hook("xxxxxx", xrkmonctrl.run_AllExceptHookPtDetails)
    # xrkmon.exec_args_str("--config --key test")

    h = testHook()
    h.add("xxxx", 0x0120F738)

    end = datetime.datetime.now()
    xrklog.highlight("main: %s" % ((end - start)))

    return "hello"
