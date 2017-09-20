# -*- coding: utf-8 -*

"""
test module
"""

import os
import inspect


# import idaapi
import xrk_log


file_path = os.path.abspath(inspect.getsourcefile(lambda: 0))
file_dir = os.path.dirname(inspect.getsourcefile(lambda: 0))

# ---------------------------------------------------------------------------
v_log_header = "[XRK-PATCH-STR] >>"


def msg(str_):
    xrk_log.msg(v_log_header, str_)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    msg("from patch string")

    # put py file under same directory of this script
    import xrk_util
    import z_ida_patch
    reload(z_ida_patch)
    from z_ida_patch import z_tmp_patch_strings
    for (addr, str_) in z_tmp_patch_strings.items():
        xrk_util._replace_str(addr, str_, is_force=True)
