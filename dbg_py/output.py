# -*- coding: utf-8 -*-

"""
all output stuff for ida
"""

# import os
import pickle

import log
import util
import _share_this


# ---------------------------------------------------------------------------
# global item to be set by xrkpydbg

# is pt stacks before parsing api
# global v_tmp_is_pt_stacks_before_api_parse
v_tmp_is_pt_stacks_before_api_parse = False

# is pt api summary collision when parsing api record
# global v_tmp_is_pt_parse_api_summary_collision
v_tmp_is_pt_parse_api_summary_collision = False


# ---------------------------------------------------------------------------

def _pt_log(line):
    """
        proxy to log.pt_log()
    """
    log.pt_log(line)


# ---------------------------------------------------------------------------
def export(file_path, pickle_obj, usage=""):
    """
    """
    try:
        file = open(file_path, "w")
    except:
        _pt_log("export %s to file cause exception: %s" % (usage, file_path))
    else:
        pickle.dump(pickle_obj, file)
        file.close()

        _pt_log("export %s to file: %s" % (usage, file_path))


# ---------------------------------------------------------------------------

# a list of tuple, each item: (api_name, stacks, param_str)
global v_tmp_api_record_list
v_tmp_api_record_list = []


def add_api_call_record(api_name, stacks, param_str=None):
    """
        @param: api_name  : string : api name
        @param: stacks    : list   : list of call_stack() object
        @param: param_str : string : (optional, dft=None)param string
    """
    global v_tmp_api_record_list
    v_tmp_api_record_list.append((api_name, stacks, param_str))


def api_summary_with_stacks__add_record(summary, api_name, from_func_name, stacks, param_str=None):
    """
        @param: summary        : obj    : obj of _share_this.api_summary_with_stacks()
        @param: api_name       : string : api name that truely hit breakpoint
        @param: from_func_name : string :
        @param: stacks         : list   : list of call_stack() object
        @param: param_str      : string : (optional, dft=None)param string
    """
    # todo: special samples, different api may return to same to_addr, because sample invoke api in this way: call eax...
    if summary.api_name != api_name:

        global v_tmp_is_pt_parse_api_summary_collision
        if v_tmp_is_pt_parse_api_summary_collision:
            _pt_log("-" * 100)
            _pt_log("existing summary details: ")
            for line in summary.lines():
                _pt_log("    %s" % line)
            _pt_log("")
            _pt_log("record to add details:")
            _pt_log("    api_name: %s" % api_name)
            _pt_log("    from_func_name: %s" % from_func_name)
            _pt_log("    stacks details(depth: %d): " % len(stacks))
            for stack in stacks:
                _pt_log("        %s" % stack)
            _pt_log("-" * 100)
        # assert False
        return summary

    assert summary.api_name == api_name
    if summary.from_func_name != from_func_name:
        _pt_log("-" * 100)
        _pt_log(">>> not equal from_func_name: %s vs %s" % (summary.from_func_name, from_func_name))
        _pt_log("-" * 100)
        # assert False
        return summary
    assert len(stacks) != 0

    if not _share_this.has_stacks(summary.stacks_list, stacks):
        summary.stacks_list.append(stacks)

    if param_str is not None and param_str not in summary.param_str_list:
        summary.param_str_list.append(param_str)

    summary.call_count = summary.call_count + 1

    return summary


def api_summary_no_stacks__add_record(summary, param_str):
    """
        @param: summary   : obj    : obj of _share_this.api_summary_no_stacks()
        @param: param_str : string : api call param description
    """
    if param_str is not None and param_str not in summary.param_str_list:
        summary.param_str_list.append(param_str)

    summary.call_count = summary.call_count + 1

    return summary


def _parse_api_records():
    """
        parse global v_tmp_api_record_list, then return parsed results

        @return: tuple : (api_summaries_with_stacks, api_summaries_no_stacks)
                          api_summaries_with_stacks : list : a list of api_summary_with_stacks() object
                          api_summaries_no_stacks   : list : a list of api_summary_no_stacks() object
    """
    # convert to a new list of tuple, each item : (to_addr, api_name, from_func_name, stacks, param_str)
    #                                        or : (0, api_name, "", [], param_str)
    api_record_list = []
    for i in range(len(v_tmp_api_record_list)):

        tmp_record = v_tmp_api_record_list[i]

        api_name = tmp_record[0]
        from_func_name = tmp_record[0]
        stacks = tmp_record[1]
        to_addr = 0

        if len(stacks) != 0:

            # ---------------------------------------------------------------------------
            global v_tmp_is_pt_stacks_before_api_parse
            if v_tmp_is_pt_stacks_before_api_parse:
                _pt_log("before parsing stacks of api record...")
                _pt_log("api name: %s" % api_name)
                _pt_log("stack depth: %d" % len(stacks))
                for stack in stacks:
                    _pt_log("    %s" % stack)
                _pt_log("")
            # ---------------------------------------------------------------------------

            while len(stacks) > 1:

                to_addr = stacks[0].to_addr
                assert to_addr != 0

                # for most apis, from_func_name is valid.
                # but because we use self-parsed symbols, there are some "address" can't be "resolved", so we ignore this here.
                from_func_name = stacks[0].from_func_name
                # assert from_func_name is not None and len(from_func_name) != 0

                if stacks[0].to_md_name is None or stacks[0].to_md_name == "":
                    # special call stacks like this:
                    # (0000B465)kernel32.dll._GetModuleFileNameW@12+00000000 | (016F0145)None.016F0145
                    # (016F0145)None.016F0145 | (0020AB1E)1111.exe.0060AB1E
                    # (0020AB1E)1111.exe.0060AB1E | (00002E78)1111.exe.00402E78
                    # (00002E78)1111.exe.00402E78 | (002129CF)1111.exe.006129CF
                    break

                # actually, we don't need to check from_md_name: stacks[0].from_md_name == util.debugee_name() or
                if stacks[0].to_md_name == util.debugee_name():
                    break

                stacks.pop(0)

            # if only 1 stack left, we ignore this whole record, but print details as remainder.
            if len(stacks) == 1:

                # print "*" * 100
                # print "parsing api record, ignore this one because it has only 1 stack: to_addr: %.8X, api_name: %s" % (to_addr, api_name)
                # print "    %s" % stacks[0]
                # print "*" * 100
                continue

        api_record_list.append((to_addr, api_name, from_func_name, stacks, tmp_record[2]))

    # make summary
    api_summaries_with_stacks = []
    api_summaries_no_stacks = []
    for api_record in api_record_list:

        api_name = api_record[1]
        stacks = api_record[3]
        param_str = api_record[4]

        if len(stacks) != 0:

            # with call stack, summary by to_addr
            # todo: special samples, different api may return to same to_addr, because sample invoke api in this way: call eax...
            # so for now, we just print it out...
            to_addr = api_record[0]
            assert to_addr != 0
            from_func_name = api_record[2]
            # this is possible
            # assert from_func_name is not None and len(from_func_name) != 0

            is_exist = False
            for summary in api_summaries_with_stacks:
                if to_addr == summary.to_addr:
                    is_exist = True
                    summary = api_summary_with_stacks__add_record(summary, api_name, from_func_name, stacks, param_str)
                    break

            if not is_exist:
                summary = _share_this.api_summary_with_stacks(to_addr, api_name, from_func_name)
                summary = api_summary_with_stacks__add_record(summary, api_name, from_func_name, stacks, param_str)
                api_summaries_with_stacks.append(summary)

        else:
            # no call stack, summary by api_name
            is_exist = False
            for summary in api_summaries_no_stacks:
                if summary.api_name == api_name:
                    is_exist = True
                    summary = api_summary_no_stacks__add_record(summary, param_str)
                    break

            if not is_exist:
                summary = _share_this.api_summary_no_stacks(api_name)
                summary = api_summary_no_stacks__add_record(summary, param_str)
                api_summaries_no_stacks.append(summary)

    return (api_summaries_with_stacks, api_summaries_no_stacks)


def pt_api_summary():
    """
        print api summary
    """
    api_summaries_with_stacks, api_summaries_no_stacks = _parse_api_records()
    if len(api_summaries_with_stacks) == 0:
        _pt_log("!" * 5 + " no api call with stacks " + "!" * 5)

    else:
        _pt_log("!" * 5 + " api call with stacks count: %d " % len(api_summaries_with_stacks) + "!" * 5)
        for record in api_summaries_with_stacks:
            lines = record.lines()
            for line in lines:
                _pt_log("    %s" % line)
        _pt_log("")

    if len(api_summaries_no_stacks) == 0:
        _pt_log("!" * 5 + " no api call with none stacks " + "!" * 5)

    else:
        _pt_log("!" * 5 + " api call with none stacks count: %d " % len(api_summaries_no_stacks) + "!" * 5)
        for record in api_summaries_no_stacks:
            lines = record.lines()
            for line in lines:
                _pt_log("    %s" % line)
        _pt_log("")


def export_api_summary(file_path=None):
    """
        parse then export api summary to file

        @param: file_path : string : (optional, dft=None)output file path
    """
    if file_path is None:
        file_path = util.gen_path_prefix_time_tail_debugee("_api_summary.dat", has_ext=False)

    export(file_path, _parse_api_records(), "api summary")


# ---------------------------------------------------------------------------
# function call summary
class func_summary:
    def __init__(self):
        pass


global v_tmp_func_summary_list
v_tmp_func_summary_list = []


def add_func_summary():
    pass


def export_func_summary():
    pass


# ---------------------------------------------------------------------------
# function call stream
class func_stream:
    def __init__(self):
        pass


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
