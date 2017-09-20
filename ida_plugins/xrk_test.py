# -*- coding: utf-8 -*

"""
test module
"""

import os
import pickle
import inspect


# import idaapi
import xrk_log
import _share_this


file_path = os.path.abspath(inspect.getsourcefile(lambda: 0))
file_dir = os.path.dirname(inspect.getsourcefile(lambda: 0))

# ---------------------------------------------------------------------------
v_log_header = "[XRK-TEST] >>"


def msg(str_):
    xrk_log.msg(v_log_header, str_)


def load_api_summary(file_path):
    """
        load api summary exported by pydbg

        @param: file_path : string :
    """
    assert os.path.exists(file_path)

    try:
        # file_path = r"E:\SVN\repo-pydbg\1111_api_summary.dat"
        file = open(file_path, "r")
    except:
        print "export api summary to file cause exception: %s" % file_path
    else:
        api_summaries_with_stacks, api_summaries_no_stacks = pickle.load(file)
        file.close()

        msg("%d - %d" % (len(api_summaries_with_stacks), len(api_summaries_no_stacks)))

        # print way borrowed from output.py

        if len(api_summaries_with_stacks) == 0:
            print "!" * 5 + " no api call with stacks " + "!" * 5
        else:
            print "!" * 5 + " api call with stacks count: %d " % len(api_summaries_with_stacks) + "!" * 5
            for record in api_summaries_with_stacks:

                lines = record.lines()
                for line in lines:
                    print "    %s" % line

                none_md_stacks_cnt = 0
                for stacks in record.stacks_list:
                    # todo: this checker is incorrent
                    if _share_this.is_stacks_has_None_md(stacks):
                        # none_md_stacks_cnt = none_md_stacks_cnt + 1
                        pass
                if none_md_stacks_cnt != 0:
                    print "    ******************************************************************"
                    print "    >>> %d stacks has None module, u should pay attention to this" % none_md_stacks_cnt
                    print "    ******************************************************************"

            print ""

        if len(api_summaries_no_stacks) == 0:
            print "!" * 5 + " no api call with none stacks " + "!" * 5
        else:
            print "!" * 5 + " api call with none stacks count: %d " % len(api_summaries_no_stacks) + "!" * 5
            for record in api_summaries_no_stacks:
                lines = record.lines()
                for line in lines:
                    print "    %s" % line
            print ""


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    msg("from hello")

    # # load api summary exported by pydbg
    # import idaapi
    # file_path = idaapi.askfile_c(0, "_api_summary.dat", "plese select api summary file")
    # if os.path.exists(file_path):
    #     load_api_summary(file_path)

    # patch string
    # put py file under same directory of this script
    import xrk_util
    from z_ida_patch import z_tmp_patch_strings
    for (addr, str_) in z_tmp_patch_strings.items():
        xrk_util._replace_str(addr, str_, is_force=True)
