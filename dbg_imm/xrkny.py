# -*- coding: utf-8 -*-

"""
ny thing
"""

import os
import sys
import inspect
import traceback
import datetime

try:
    import xrkmd
    import xrkdef
    import xrkdbg
    import xrklog
    # import xrkhook
    import xrkgame
    import xrkutil
    import xrknycst
except:
    this_path = os.path.split(os.path.realpath(inspect.stack()[-1][1]))[0]
    sys.path.append(this_path)
    try:
        import xrkmd
        import xrkdef
        import xrkdbg
        import xrklog
        # import xrkhook
        import xrkgame
        import xrkutil
        import xrknycst
    except Exception, e:
        import immlib as dbglib
        dbg = dbglib.Debugger()
        dbg.log("xrk ny import error: %s" % e, highlight=1)
        error = traceback.format_exc()
        while len(error) > 200:
            tmp = error[:200]
            dbg.log("  %s" % tmp, highlight=1)
            error = error[200:]
        dbg.log("  %s" % error, highlight=1)

        assert False


# ---------------------------------------------------------------------------
# cloud - xrkmd cstk
# ---------------------------------------------------------------------------


def get_cloud_xrkmd_cstk():
    """
        structure: a LIST of TUPLE
            [(time, cstks), (time, cstks), ...]
    """
    return xrkutil.serialize_get("xrkmd_cstk", default=[])


def set_cloud_xrkmd_cstk(value):
    """
        set
    """
    xrkutil.serialize_set("xrkmd_cstk", value)


def add_cloud_xrkmd_cstk(regs):
    """
        add to cstk sum
    """
    k = get_cloud_xrkmd_cstk()
    k.append((datetime.datetime.now(), xrkmd.get_xrkmd_cstks()))
    set_cloud_xrkmd_cstk(k)


def pt_cloud_xrkmd_cstk():
    """
        get from cloud, sum, print
    """
    k_old = get_cloud_xrkmd_cstk()
    if k_old is not None and len(k_old) != 0:
        # structure of k_new:
        # {"1": (cstks, 23, time_base, [time_gap_1, time_gap_2, ...]), "2": (cstks, 12, time_base, [time_gap_1, time_gap_2, ...]), ...}
        k_new = {}
        for i in range(len(k_old)):

            tuple_ = k_old[i]
            time_ = tuple_[0]
            cstk = tuple_[1]
            is_exist = False
            for (d, x) in k_new.items():
                if xrkmd.is_same_cstks(cstk, x[0]):

                    assert x[3] is not None
                    x[3].append(((time_ - x[2]).microseconds))
                    k_new[d] = (x[0], x[1] + 1, x[2], x[3])
                    is_exist = True
                    break

            if not is_exist:
                key_ = "%d" % len(k_new)
                k_new[key_] = (cstk, 1, time_, [])

        lines = []
        for (d, x) in k_new.items():
            sublines = ["apex send, count: %d" % (x[1])]
            time_gaps = sorted(x[3])
            sublines.append("apex send, time gaps: %s" % (time_gaps))
            for i in range(len(x[0])):
                sublines.append("%s" % x[0][i])
            lines = lines + sublines

        xrklog.infos(lines)
    else:
        xrklog.high("no apex send call stack")


# ---------------------------------------------------------------------------
# cloud - ny cstk
# ---------------------------------------------------------------------------

def get_cloud_ny_cstk():
    """
        structure: a LIST of TUPLE
            [(time, cstks), (time, cstks), ...]
    """
    return xrkutil.serialize_get("ny_cstk", default=[])


def set_cloud_ny_cstk(value):
    """
        set
    """
    xrkutil.serialize_set("ny_cstk", value)


def add_cloud_ny_cstk(regs):
    """
        add to cstk sum
    """
    k = get_cloud_ny_cstk()
    k.append((datetime.datetime.now(), xrkdbg.callStack()))
    set_cloud_ny_cstk(k)


def pt_cloud_ny_cstk():
    """
        get from cloud, sum, print
    """
    pass


# ---------------------------------------------------------------------------
# send/recv
# ---------------------------------------------------------------------------


def run_game_send(regs):
    """
        buf, code
    """
    esp = regs["ESP"]
    pbuf = xrkdbg.readLong(esp + 4)
    len_ = xrkdbg.readLong(esp + 8)
    buf = xrkdbg.readMemory(pbuf, len_)
    code = xrkutil.get_v_from_mm_slice(buf, 0, v_len=2)

    known_codes = {0x3E9: "info",
                   0x96: "route"}

    ignore_codes = [0x3E9, 0x96]

    lines = []
    if code in known_codes:
        lines.append("sending... %.8X %.4X %.4X %s" % (pbuf, code, len_, known_codes[code]))
    else:
        lines.append("sending... %.8X %.4X %.4X" % (pbuf, code, len_))

    if code not in ignore_codes:
        lines = lines + xrkutil.buf_to_str_rows(buf, col_len=48)

    xrklog.infos_ex(lines, addr=pbuf, add_prefix=True)


def run_game_recv(regs):
    pass


def run_apex_send_by_game(regs):
    """
        in NYCSClient.exe, proto:
            int __cdecl _apex_send_by_game_00FABBB0(void *Src, size_t Size)
    """
    esp = regs["ESP"]
    size = xrkdbg.readLong(esp + 8)
    xrklog.high("apex send (ny): size: %X" % size, add_prefix=True)
    """
    p_buf = xrkdbg.readLong(esp + 4)
    buf = xrkdbg.readMemory(p_buf, size)
    lines = ["apex send: %d" % size]
    lines = lines + xrkutil.buf_to_str_rows(buf)
    # xrklog.highs_ex(lines)
    """


def decrypt_apex_send_data(data):
    """
        decrypt apex send data, and print

        @param: data: range of memory

        structure:
            off_0   BYTE    b_0_from_s0_i_1E38
            off_1   BYTE    b_1_check_byte_of_below_data
            off_2   BYTE    b_2_code
            off_3   BYTE    b_3_from_g_100A26D4_ps2_b_84_or_0xFF
            off_4   WORD    w_4_packet_index
            off_6   BYTE[]  a_6_data
    """
    if len(data) >= 6:

        b_0_from_s0_i_1E38 = xrkutil.get_v_from_mm_slice(data, 0, v_len=1)
        b_1_check_byte = xrkutil.get_v_from_mm_slice(data, 1, v_len=1)
        b_2_code = xrkutil.get_v_from_mm_slice(data, 2, v_len=1)
        b_3_from_gps2_xx = xrkutil.get_v_from_mm_slice(data, 3, v_len=1)
        w_4_packet_index = xrkutil.get_v_from_mm_slice(data, 4, v_len=2)
        a_6_data = data[6:]

        xrklog.high("%.2X - %.2X(check) - %.2X(code) - %.2X - %.4X(index) - %.2X(len) - %s" %
                    (b_0_from_s0_i_1E38, b_1_check_byte, b_2_code, b_3_from_gps2_xx, w_4_packet_index, len(data), xrkutil.buf_to_str(a_6_data)), add_prefix=True)
        xrklog.info("")

    else:
        xrklog.error("apex send, invalid len: %d - %s" % (len(data), xrkutil.buf_to_str(data)))


def run_pe_1_send(regs):
    """
        xx
    """
    # log call stacks
    # xrklog.high("apex sending(pe 1): %s" % datetime.datetime.now(), add_prefix=True)

    esp = regs["ESP"]
    p_buf = xrkdbg.readLong(esp + 0)
    size = xrkdbg.readLong(esp + 4)
    buf = xrkdbg.readMemory(p_buf, size)
    decrypt_apex_send_data(buf)

    """
    k = get_cloud_xrkmd_cstk()
    k.append((datetime.datetime.now(), xrkmd.get_xrkmd_cstks()))
    set_cloud_xrkmd_cstk(k)
    """


def run_pe_1_apex_send_proxy_root(regs):
    """
        apex send proxy root
    """
    esp = regs["ESP"]
    # p_buf = xrkdbg.readLong(esp + 4)
    size = xrkdbg.readLong(esp + 8)
    index = xrkdbg.readShort(esp + 0xC)
    code = xrkdbg.readShort(esp + 0xE)
    # xrklog.high("apex send root: %.8X - %.8X - %.4X - %.2X" % (p_buf, size, index, code), add_prefix=True)
    xrklog.high("apex send root: size: %X - index: %X - code: %X" % (size, index, code), add_prefix=True)
    # add_cloud_xrkmd_cstk(regs)


def run_cbk_of_pe_1_for_pe_2_to_send(regs):
    """
        pe 2 send data by cbk provided by pe 1
    """
    esp = regs["ESP"]
    p_buf = xrkdbg.readLong(esp + 4)
    size = xrkdbg.readLong(esp + 8)
    buf = xrkdbg.readMemory(p_buf, size)
    xrklog.high("pe 2 send through pe 1: %d - %s" % (size, xrkutil.buf_to_str(buf)), add_prefix=True)


def run_cbk_of_pe_1_for_pe_2_to_oper_on_code(regs):
    """
        pe 2 call cbk of pe 1
    """
    esp = regs["ESP"]
    code = xrkdbg.readLong(esp + 4)
    if code == 0x3E9:
        p_buf = xrkdbg.readLong(esp + 8)
        size = xrkdbg.readLong(esp + 0xC)
        buf = xrkdbg.readMemory(p_buf, size)
        xrklog.high("pe 2 oper through pe 1 by code: 000003E9 - %s - %s" % (size, xrkutil.buf_to_str(buf)), add_prefix=True)
    else:
        xrklog.high("pe 2 oper through pe 1 by code: %.8X" % (code), add_prefix=True)


def run_pe_1_call_pe_2_buf_size(regs):
    """
        record buf and size
    """
    # esp = regs["ESP"]
    pass


def run_pe_1_call_pe_2_code_xx_xx(regs):
    """
        this is a little complicated
    """
    esp = regs["ESP"]
    code = xrkdbg.readLong(esp + 4)
    ret_1 = xrkdbg.readLong(esp + 8)
    ret_2 = xrkdbg.readLong(esp + 0xC)
    ret_2_v = xrkdbg.readLong(ret_2)
    xrklog.high("pe 1 call pe 2 to code xx xx: %.8X - %.8X - %.8X" % (code, ret_1, ret_2_v), add_prefix=True)


# ---------------------------------------------------------------------------
# msg box
# ---------------------------------------------------------------------------


def run_msg_box_1(regs):
    esp = regs["ESP"]
    str_ = xrkutil.dbg_read_pstring(esp + 8)
    xrklog.info("show msg box 1: %s" % str_, add_prefix=True)


def run_msg_box_2(regs):
    esp = regs["ESP"]
    str_ = xrkutil.dbg_read_pstring(esp + 8)
    xrklog.info("show msg box 2: %s" % str_, add_prefix=True)


# ---------------------------------------------------------------------------
# get string
# ---------------------------------------------------------------------------


def run_get_string_end(regs):
    """
        iter string table to get string

        !+ 在游戏中，应该是有个什么东西，一直获取诺亚的URL，来显示到标题上
    """
    esp = regs["ESP"]
    tag = xrkdbg.readLong(esp + 4)
    if tag == 1:
        src = xrkutil.dbg_read_pstring(esp + 0x14)
        dst = xrkdbg.readString(regs["EAX"])
        xrklog.info("get string: %-40s --> %s" % (src, dst), add_prefix=True)


def gua_install_get_string_end_hook(is_pause=False):
    """
        gua that end of get string function is hooked
    """
    addr_start = xrkgame.get_sdg_result(xrknycst.get_ny_sdg("func_iter_string_table"))
    addr_end = xrkutil.get_first_retn_addr(addr_start)
    if "ny_get_string_end" not in xrkdbg.listHooks():
        h = xrkdef.pausableInvokeRunCbkHook(xrkdef.cbkStructRun(run_get_string_end))
        h.add("ny_get_string_end", addr_end, shall_pause=is_pause)
        xrklog.info("install hook for get string end at %.8X" % (addr_end))
    xrkutil.set_bp_may_pause(addr_end, is_pause)


# ---------------------------------------------------------------------------
# pe-2 device io ctrl
# ---------------------------------------------------------------------------


def run_pe_2_device_io_ctrl_whatever(regs):
    """
        log code, sub_code, and in_buf
    """
    esp = regs["ESP"]
    code = xrkdbg.readLong(esp + 8)
    sub_code = xrkdbg.readLong(esp + 0xC)
    p_in_buf = xrkdbg.readLong(esp + 0x10)
    in_buf_len = xrkdbg.readLong(esp + 0x14)
    in_buf = xrkdbg.readMemory(p_in_buf, in_buf_len)

    xrklog.info("device io ctrl whatever prams: %.8X - %.8X - %X --> %s" % (code, sub_code, in_buf_len, xrkutil.buf_to_str(in_buf)))


def run_pe_2_device_io_ctrl_whatever_RETN(regs):
    pass


def run_pe_2_device_io_ctrl_0x222008(regs):
    """
        log code, sub_code, and in_buf

        !+ this hits too frequently...
    """
    esp = regs["ESP"]
    sub_code = xrkdbg.readLong(esp + 0x8)
    p_in_buf = xrkdbg.readLong(esp + 0xC)
    in_buf_len = xrkdbg.readLong(esp + 0x10)
    in_buf = xrkdbg.readMemory(p_in_buf, in_buf_len)

    xrklog.info("device io ctrl 00222008 prams: 00222008 - %.8X - %X --> %s" % (sub_code, in_buf_len, xrkutil.buf_to_str(in_buf)))


def run_pe_2_device_io_ctrl_0x222008_RETN(regs):
    pass


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def run_invoke(p1, regs):
    xrklog.high("invoking....%s" % p1, add_prefix=True)


def run_add_xrkmd_cstk(regs):
    add_cloud_xrkmd_cstk(regs)


def run_add_ny_cstk(regs):
    add_cloud_ny_cstk(regs)


def run_test(p1, regs):
    """
        test purpose
    """
    esp = regs["ESP"]
    # p_buf = xrkdbg.readLong(esp + 4)
    size = xrkdbg.readLong(esp + 8)
    # xrklog.high("test: %.8X - %.8X" % (p_buf, size), add_prefix=True)
    xrklog.high("%s: size: %X" % (p1, size), add_prefix=True)


def test():
    pt_cloud_xrkmd_cstk()
    """
    import win32

    pid = xrkdbg.getDebuggedPid()
    h_proc = win32.OpenProcess(win32.PROCESS_ALL_ACCESS, win32.FALSE, pid)
    assert h_proc is not None

    tid = xrkdbg.getThreadId()
    h_thread = win32.OpenThread(win32.THREAD_ALL_ACCESS, win32.FALSE, tid)
    ctx_raw = win32.GetThreadContext(h_thread, raw=True)

    stack_frame = win32.STACKFRAME64()
    ctx = win32.GetThreadContext(h_thread)
    stack_frame.AddrPC = win32.ADDRESS64(ctx.pc)
    stack_frame.AddrFrame = win32.ADDRESS64(ctx.fp)
    stack_frame.AddrStack = win32.ADDRESS64(ctx.sp)

    # trace = []
    while win32.StackWalk64(win32.IMAGE_FILE_MACHINE_I386, h_proc, h_thread, stack_frame, ctx_raw):
        # stack_frame.AddrPC.Offset     --> EIP
        # stack_frame.AddrStack.Offset  --> ESP
        if stack_frame.AddrPC.Offset != 0:
            xrklog.high("%.8X - %.8X - %.8X" % (stack_frame.AddrPC.Offset, stack_frame.AddrFrame.Offset, stack_frame.AddrStack.Offset))

        if stack_frame.AddrReturn.Offset == 0:
            break

        if xrkutil.validate_addr(stack_frame.AddrFrame.Offset):
            stack_frame.AddrFrame.Offset = xrkdbg.readLong(stack_frame.AddrFrame.Offset)

        # fp = stack_frame.AddrFrame.Offset
        if fp == 0:
            break
        xrklog.high("%.8X - %.8X - %.8X" % (fp, stack_frame.))
        #
    """

#
# 1. for mds, don't init with sdg, because it takes time to search sdg address.
#


def xrkmd_thing():
    """
        xrkmd thing
    """
    ny_call_pe_1_entry = xrkgame.get_sdg_result(xrknycst.get_ny_sdg("apex_load_pe_1_call_eop"))
    ny_pe_1_unload = xrkgame.get_sdg_result(xrknycst.get_ny_sdg("apex_stop"))
    pe_1 = xrkmd.get_md_root("pe_1_root", "first pe, oep", ny_call_pe_1_entry, ny_pe_1_unload, xrkdef.vGetterRegOnlyPageBase("ECX"), xrkdef.vGetterRegOnlyPageSize("ECX"))
    pe_1.feat_add_many([("as_init", 0x47390, "55 8B EC 5D E9 D7 FE FF FF"),
                        ("as_done", 0x44DC0, "55 8B EC 83 EC 28 A1 ? ? ? ? 33 C5 89 45 FC 33 C0 56 8B 75 08 68"),
                        ("as_set_base", 0x39720, "55 8B EC B9 ? ? ? ? 5D E9"),
                        ("as_set_func", 0x39730, "55 8B EC 8B 45 0C 05 16 FC FF FF 83 F8 06 77"),
                        ("as_set_info", 0x3F030, "55 8B EC 56 8B 75 0C 89 35"),
                        ("as_set_db_buf", 0x397C0, "C2 08 00 CC CC CC CC CC CC CC CC CC CC CC CC CC 8B 51 04 2B 11 B8 AB AA AA 2A F7 EA D1 FA 8B"),
                        ("xor_get", 0x11C40, "A1 ? ? ? ? 33 05 ? ? ? ? 03 01 C3"),
                        ("pe_1_mm_load_custom_pe_by_shlzip", 0x31260, "55 8B EC 83 EC 40 A1 ? ? ? ? 33 C5 89 45 FC A1 ? ? ? ? 8B 0D"),
                        ("pe_1_load_shlzip_call_shlplain", 0x6EE0, "55 8B EC 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 0C 53 56 57 A1 ? ? ? ? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 8B 45 08 8B 7D 0C 33"),
                        ("pe_1_apex_load_shlzip", 0x1C660, "55 8B EC 83 EC 30 53 8B 5D 08 85 DB 75"),
                        ("pe_1_memory_load_pe_core", 0x1C9F0, "55 8B EC 83 EC 34 53 8B 5D 08 56 57 33"),
                        ("pe_1_decrypt_string", 0x1C9B0, "55 8B EC 8B 4D 08 33 D2 B8 07 00 00 00 38 11 74"),
                        ("pe_1_memory_load_pe_core_call_entry", 0x1CCA6, "FF D1 5F 5E 33 C0 5B 8B E5 5D C3 C7"),
                        ("pe_1_memory_load_pe_call_pe_2_export", 0x31386, "FF 15 ? ? ? ? 8B 45 D0 83 C4 10 8B 4D C8 8B 51 0E 89 15"),
                        ("pe_1_apex_call_ny_send", 0x473A0, "55 8B EC 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 0C 53 56 57 A1 ? ? ? ? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 65 F0 8B F9 83 BF 74 01 00 00 00 0F 84"),
                        ("pe_1_apex_call_ny_send_call", 0x47437, "FF D2 83 C4 08 89 45 0C A2"),
                        ("pe_1_apex_send_proxy_root", 0x32310, "55 8B EC 81 EC DC 07 00 00 A1"),
                        ("pe_1_apex_recv_root", 0x3A780, "55 8B EC 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 51 56 A1 ? ? ? ? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 80 3D"),
                        ("pe_1_cbk_for_pe_2_to_send", 0x3CB70, "55 8B EC B9 ? ? ? ? E8 ? ? ? ? 8B 4D 0C 8B 55 08 51 52 68"),
                        ("pe_1_cbk_for_pe_2_to_oper_on_code", 0x39AE0, "55 8B EC 81 EC EC 03 00 00 A1 ? ? ? ? 33 C5 89 45 FC 8B 45 08 56"),
                        ("pe_1_call_pe_2_code_xx_xx", 0x398F0, "55 8B EC 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 0C 53 56 57 A1 ? ? ? ? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 65 F0 C7 45 E8"),
                        ("pe_1_call_pe_2_buf_size", 0x3C590, "55 8B EC A1 ? ? ? ? 56 8B 75 0C 85 C0 75 ? 80 3D")])

    pe_1.set_sym_file("E:\\SVN\\idbs\\pe_1_root_20161224_09_37_37.txt", force_update=True)

    # pe_1.bp_add_by_feat("as_set_info", is_enabled=True)
    # pe_1.bp_add_by_feat("pe_1_memory_load_pe_core_call_entry", is_enabled=True)

    # pe_1.hook_add_by_desc_str("pe_1_apex_call_ny_send_call", run_pe_1_send, shall_pause=False)
    pe_1.hook_add_by_desc_str("pe_1_apex_send_proxy_root", run_pe_1_apex_send_proxy_root, shall_pause=True)
    # pe_1.hook_add_by_desc_str("pe_1_cbk_for_pe_2_to_send", run_cbk_of_pe_1_for_pe_2_to_send, shall_pause=True)
    # pe_1.hook_add_by_desc_str("pe_1_cbk_for_pe_2_to_oper_on_code", run_cbk_of_pe_1_for_pe_2_to_oper_on_code, shall_pause=True)
    # pe_1.hook_add_by_desc_str("pe_1_call_pe_2_buf_size", run_pe_1_call_pe_2_buf_size)
    # pe_1.hook_add_by_desc_str("pe_1_call_pe_2_code_xx_xx", run_pe_1_call_pe_2_code_xx_xx)

    # pe_1.hook_add("sum cstk", 0x4D7C0, run_add_xrkmd_cstk)
    # pe_1.hook_add("invokeing", 0x382C9, run_invoke, param1="1")
    # pe_1.hook_add("invokeing2", 0x3790F, run_invoke, param1="2")
    # pe_1.hook_add("invokeing4", 0x54F55, run_invoke, param1="4")

    pe_1.hook_add("copy to s0 src", 0x388E0, run_test, param1="copy ..")

    # pe_1.bp_add("xx", 0x3C590)
    # pe_1.bp_add("pf 2", 0x39AE0)

    # pe_1.bp_tmp(0x32310)

    """
    pe_1.bp_add_many_by_feat_dict({"pe_1_mm_load_custom_pe_by_shlzip": True,
                                   "pe_1_load_shlzip_call_shlplain": True,
                                   "pe_1_apex_load_shlzip": True,
                                   "pe_1_memory_load_pe_core": True,
                                   "pe_1_decrypt_string": True,
                                   "pe_1_memory_load_pe_core_call_entry": True,
                                   "pe_1_memory_load_pe_call_pe_2_export": True})
    """

    # pe_2 = pe_1.sub_md_get_feat("pe_2_sub", "sub md of pe 1", "pe_1_memory_load_pe_core_call_entry", "as_done", xrkdef.vGetterRegOnlyPageBase("ECX"), xrkdef.vGetterRegOnlyPageSize("ECX"))
    # pe_2.feat_add_many([("device_io_ctrl_whatever", 0x4C7F8, "55 8B EC 81 EC 00 04 00 00 56 57 E8 ? ? ? ? 8B 75 18 89 85"),
    #                     ("device_io_ctrl_0x222008", 0x4C78C, "55 8B EC 81 EC 00 04 00 00 56 57 E8 ? ? ? ? 8B 75 14 89 85")])
    # pe_2.bp_add_by_feat("", is_enabled=True)

    # pe_2.hook_add_by_desc_str("device_io_ctrl_whatever", run_pe_2_device_io_ctrl_whatever)
    # this hits too requently
    # pe_2.hook_add_by_desc_str("device_io_ctrl_0x222008", run_pe_2_device_io_ctrl_0x222008)

    # pe_1.bp_disable_all()
    xrkmd.update_md_root("pe_1_root", pe_1)


def game_thing():

    # xrkgame.gua_hook_installed_by_sdg(xrknycst.get_ny_sdg("call_game_send"), run_game_send)
    xrkgame.gua_hook_installed_by_sdg(xrknycst.get_ny_sdg("call_game_send"), run_add_ny_cstk)
    # xrkgame.gua_hook_installed_by_sdg(xrknycst.get_ny_sdg("call_show_msg_box_1"), run_msg_box_1)
    # xrkgame.gua_hook_installed_by_sdg(xrknycst.get_ny_sdg("call_show_msg_box_2"), run_msg_box_2)
    # xrkgame.gua_hook_installed_by_sdg(xrknycst.get_ny_sdg("apex_send_by_game"), run_apex_send_by_game)

    # addr_apex_send_by_game = xrkgame.get_sdg_result(xrknycst.get_ny_sdg("apex_send_by_game"))
    # xrkhook.install_pausable_hook("apex_send_by_game", addr_apex_send_by_game, run_apex_send_by_game, shall_pause=False)


def main(args):

    if len(args) != 0:
        # args
        if "test" in args:
            test()
        return "xrkny with params exec finish"

    start = datetime.datetime.now()

    # xrkmd_thing()
    game_thing()

    end = datetime.datetime.now()
    xrklog.info("xrkny exec time: %d msecs" % ((end - start).microseconds / 1000))
    return "ny finish"

"""
需求明确：
1. 通过命令行，对预定义的各种hook进行管理。
    client_send
        non_itd_code: 不感兴趣的，这些code都会被过滤掉
        itd_code：感兴趣的，这些code都会显示
        enable()/disable()
    client_recv
    show_msg_middle
    show_msg_bottom
    show_msg_talk
    create_window
    update_ui_element(direct)
    iter_string_table
    iter_xx_info

    a. 只Hook某1个
"""


"""
function _verifyLinkedList(address)
    local nextItem = readInteger(address) or 0
    local previousItem = readInteger(address + 4) or 0
    local nextItemBack = readInteger(nextItem + 4)
    local previousItemForward = readInteger(previousItem)
    return (address == nextItemBack and address == previousItemForward)
end

function isValueInLinkedList(valueAddress)
    for address = valueAddress - 8, valueAddress - 48, -4 do
        if (_verifyLinkedList(address)) then
            return address
        end
    end
    return 0
end

local node = isValueInLinkedList(addressOfSomeValue)
if (node > 0) then
    print(string.format("Value in LL, top of node at 0x0%x", node))
end

# Listing 5-8: Determining whether data is in a std::list using a Cheat Engine Lua script
"""
