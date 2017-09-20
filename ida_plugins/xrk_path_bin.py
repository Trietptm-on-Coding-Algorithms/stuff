# -*- coding: utf-8 -*

"""
test module
"""

import os
import inspect


import idaapi
import xrk_log


file_path = os.path.abspath(inspect.getsourcefile(lambda: 0))
file_dir = os.path.dirname(inspect.getsourcefile(lambda: 0))

# ---------------------------------------------------------------------------
v_log_header = "[XRK-PATCH-BIN] >>"


def msg(str_):
    xrk_log.msg(v_log_header, str_)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    msg("from patch binary")

    # put py file under same directory of this script
    patch_file_path = os.path.abspath("_patch.bin")
    try:
        file = open(patch_file_path, "rb")
    except:
        msg("open patch file fail...: %s" % patch_file_path)
    else:
        patch_bytes = file.read()
        file.close()

        idaapi.patch_many_bytes(0x00F10000, patch_bytes)
        msg("patch finish")
