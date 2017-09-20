# -*- coding: utf-8 -*-

"""
    test
"""

import datetime
import xrkdbg
import xrklog

start = datetime.datetime.now()


end = datetime.datetime.now()
print "time elapsed: %d" % ((end - start).microseconds)


# ---------------------------------------------------------------------------
# all exceptions
# ---------------------------------------------------------------------------


def run_AllExceptHookPtDetails(regs):
    """
        print all exception details
    """
    evt = xrkdbg.getEvent()
    if evt.isCreateProcess():
        xrklog.high("evt: create process", add_prefix=True)
    elif evt.isCreateThread():
        xrklog.high("evt: create thread", add_prefix=True)
    elif evt.isException():
        xrklog.high("evt: exception", add_prefix=True)
    elif evt.isExitProcess():
        xrklog.high("evt: exit process", add_prefix=True)
    elif evt.isExitThread():
        xrklog.high("evt: exit thread", add_prefix=True)
    elif evt.isLoadDll():
        xrklog.high("evt: load dll", add_prefix=True)
    elif evt.isOutputDebugString():
        xrklog.high("evt: output debug string", add_prefix=True)
    elif evt.isUnloadDll():
        xrklog.high("evt: unload dll", add_prefix=True)
    elif evt.isRipEvent():
        xrklog.high("evt: rip...", add_prefix=True)
    else:
        xrklog.highlight("invalid event")
