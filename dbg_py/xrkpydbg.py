# -*- coding: utf-8 -*-

"""
known bugs:
1. when debugee exit, dbg.read_stack_int32() may fail:
   fix_to_addr = self.read_stack_int32(0)
   todo: a better way to check if address is valid.
2. bp at some api(or api combination) may cause debugee terminate unexpectedly.
   and it takes time to find out.


分析思路：
1. 退出调用栈是否正确(是否invoke了ExitProcess，而不是最末的调用栈)
    a. IMM/LCG是否正确(shorten_sleep、下断ExitProcess)
    b. pydbg_ori是否正确
    c. pydbg_my: 去掉loaddllcbk是否正确
    d. pydbg_my: 把api类型设置为n是否正确
    e. pydbg_my: 按照last api减少几个api试一下
    f. pydbg_my: 减少几个cat
2. 是否是本PE的代码
3. 是否执行了主要分支(互斥体、反调试、反虚拟机之类)
4. 没了


functionality:

1. 调试时对进程内存、API返回结果等进行修改，使程序执行我们预定的代码分支

2. 记录xrkpydbg指定API参数及调用栈，进行汇总。
   汇总结果：
       每一条对应被调试模块对外的"接口"
       每一条的内容包含由此"接口"引发的所有API调用，用户可以对导出文件修改，只剩下感兴趣的API调用
       汇总结果可以通过IDA脚本进行导入，导入为汇编模式、F5模式下的注释。(此处有多种情况，可能需要界面由用户来选择导入哪些，以及导入方式为覆盖or追加)

3. 记录IDA指定API参数及调用栈，进行汇总。
   IDA导出所有调用API的地址，此程序对其中部分地址下断，记录参数，汇总，再导入IDA

4. 间接调用地址记录。
   由IDA导出所有IDA无法解析的间接调用地址，此程序中对所有地址下断，记录实际调用地址，再导入到IDA

5. 函数调用顺序记录。
   IDA导出所有函数地址，此程序对所有地址下断，每次中断，根据线程将中断地址加入队列，汇总后导入IDA

6. 记录调用参数。
   IDA导出某些函数原型，此程序中下断，记录参数，再导入IDA

7. 对于特定API/API组的监测。
   内存分配、文件创建等，打印调用栈

8. IDA导出所有指令，此程序对所有这些指令下断点。
   如果是目标模块的指令，则单步。否则运行。
   如此，可以记录所有属于该模块的指令运行过程，
   再搞一搞，就可以实现回访？

9. IDA导出所有跳转，此程序对所有跳转下断，记录执行时采用的分支

10. IDA可以方便的标注"感兴趣的"函数、地址，导出，到Imm程序中下断

11. 多个样本，批处理

12. 进程退出的时候，检测到如果有None的调用栈，找到Memory Page，dump出来

13. python版的pdbparser

14. 代码覆盖率:在所有basic_block的头下断统计代码覆盖率

PS:
1. IDA的导入、导出可能需要界面

5. 监控新分配的内存

6. 如果代码是解密之后的，要设置trigger，在trigger之后再次添加断点

7. 取消文件的隐藏属性
   import win32file
   import win32con
   file = r"C:\Documents and Settings\Administrator\Desktop\explorer.exe_"
   win32file.SetFileAttributes(file, win32con.FILE_ATTRIBUTE_NORMAL)

8. 在代码被覆盖的某一个契机，再执行某些动作，比如加载patch、下函数头断点等。

9. 那些buf，如果是PE，用pefile.py搞一下，看是不是可以搞出来

10. printf, 内联的

11. 哪些大规模移动、复制内存的函数，检查是否为PE

14. delphi的很多内容都不对：System::BeginThread

15. 导出符号时，要连带导出函数一起，因为icmp.dll没有function，但是有导出函数

17. hint.py

19. VirtualAlloc的各个内存页，在VirtualFree或者进程退出时，都dump出来
    每一段内存页，用IDA分析一遍，也弄出符号来。对比的时候，可以根据长度+前面几个字节来匹配。

20. 把__api_sum.txt统一放到某个地方，方便搜索.

21. 感兴趣的DLL加载时，要提示

22. 调试时，新分配的内存，一般在头部下写入断，此时可以不写入头部

23. 行为的相似性

24. advapi32.ChangeServiceConfig/ChangeServiceConfig2

25. 设置的注册表内容超大时....

26. 创建子进程，然后无法结束。最好有一个线程，当进程无法结束时，脚本自己结束，把输出打印出来，不管进程了。

27. 第1个出现None调用栈的地方。最终汇总时，来自于None调用的比例

28. MapViewOfFileEx的参数和结果

29. ZwQueueApcThread, APC注入

30. 时间什么的，换算成可读的

31. HttpSendRequestxxx的结果

32. 大长block，还不带F5的那种，做工具监控

33. COM之类的，其实是可以跟踪到系统模块里面的。找那些常用的COM, 以及里面常用的函数。当然，这个函数就不一定是导出函数了
    当然，函数不一定有有意义的名称

34. 退出时写入一个文件，包含按顺序的API调用，带堆栈的

35. 解析PE文件，对于每个返回到debugee的调用，判断内存的hex和解析的hex是否相同。

36. 某些api的参数，作为"特征"字符串，比如CreateMutex

37. IDA脚本，查找函数中"手动"未命名的函数

38. IDA脚本，寻找所有的SleepEx，将值改为1，patch到二进制中

39. 只对某些Sleep Patch

40. InternetConnectA等连接地址的汇总

41. 通过修改host文件实现流量(http)重定向

42. floss的字符串，跟ida的对比，单独创建1个section，来放多余的字符串

43. IDA脚本，创建的结构如果是api指针，要记得改变结构

44. 解析HttpSendRequest的参数opt，最后打印

45. IDA脚本，隐藏cast的时候，按函数/结构体/xxx来自动hide

46. IDA脚本，所有被引用到的字符串

"""

import os
import shutil
import inspect

import log
import sym
import util
import apis
import msdn
import pydbg
import output
import defines
import debugee


file_path = os.path.abspath(inspect.getsourcefile(lambda: 0))
file_dir = os.path.dirname(inspect.getsourcefile(lambda: 0))


# ---------------------------------------------------------------------------
# global - to set manually

# is hide debugger when debugee load
# global v_tmp_is_hide_debugger
v_tmp_is_hide_debugger = False

# is debugee first load
# global v_tmp_is_debugee_first_load
v_tmp_is_debugee_first_load = False

# is install api hook only when debugee ep hit
# global v_tmp_is_bp_apis_only_when_debugee_ep_hit
v_tmp_is_bp_apis_only_when_debugee_ep_hit = False

# is always check if we have sys dll symbol
v_tmp_is_always_check_sys_dll_sym = False


# ---------------------------------------------------------------------------
# global - pt

# is pt when new dll load
v_tmp_is_pt_new_dll_load = False

# is pt when any exception
v_tmp_is_pt_all_exceptions = False

# is pt any unnormal exceptions
v_tmp_is_pt_unnormal_exceptions = False


# ---------------------------------------------------------------------------
# global - to set automatically

# is debugee ep hit
# global v_tmp_is_debugee_ep_been_hit
v_tmp_is_debugee_ep_been_hit = False


# ---------------------------------------------------------------------------

def _pt_log(line):
    """
        proxy to log.pt_log()
    """
    log.pt_log(line)


# ---------------------------------------------------------------------------
# handler

def handler_debugee_ep_hit(dbg):
    """
        when this thing hit, we know we shall install api hooks now.
    """
    global v_tmp_is_bp_apis_only_when_debugee_ep_hit
    assert v_tmp_is_bp_apis_only_when_debugee_ep_hit

    global v_tmp_is_debugee_ep_been_hit
    assert not v_tmp_is_debugee_ep_been_hit

    print ">>> debugee ep hit, delete ep bp"

    # del this bp, so it will not invoke again
    dbg.bp_del(dbg.context.Eip)

    v_tmp_is_debugee_ep_been_hit = True

    apis.check_install_api_hooks(dbg)

    return defines.DBG_CONTINUE


# ---------------------------------------------------------------------------
# callback

def callback_load_sys_dll(dbg):
    """
        load dll order:

        1.
            >>> all dlls: ['ntdll.dll']
            >>> all mds : []
        2.
            >>> all dlls: ['ntdll.dll', 'kernel32.dll']
            >>> all mds : ['1111.exe', 'ntdll.dll']
    """
    new_dll_name = dbg.system_dlls[-1].name

    global v_tmp_is_pt_new_dll_load
    if v_tmp_is_pt_new_dll_load:
        print ">>> new dll loaded: %s" % new_dll_name

    global v_tmp_is_debugee_first_load
    if not v_tmp_is_debugee_first_load and dbg.check_has_module(util.debugee_name()):

        print ">>> debugee %s just loaded...." % util.debugee_name()

        # hide debugger
        global v_tmp_is_hide_debugger
        if v_tmp_is_hide_debugger:
            dbg.hide_debugger()

        # pe info
        md = dbg.get_md(util.debugee_name())
        pe = util.XPE(name=md.szExePath)
        ep = md.modBaseAddr + pe.get_ep_offset()

        # bp apis
        global v_tmp_is_bp_apis_only_when_debugee_ep_hit
        if v_tmp_is_bp_apis_only_when_debugee_ep_hit:

            global v_tmp_is_debugee_ep_been_hit
            assert not v_tmp_is_debugee_ep_been_hit

            # set bp at ep
            dbg.bp_set(address=ep, handler=handler_debugee_ep_hit)

            print ">>> set bp at debugee ep at: %.8X" % ep

        # install patches/hooks/func_starts
        debugee.install_debugee_patches(dbg, md.modBaseAddr)
        debugee.install_debugee_hooks(dbg, md.modBaseAddr)
        debugee.install_debugee_func_starts(dbg, md.modBaseAddr)

        # set flag, so not to invoke again
        v_tmp_is_debugee_first_load = True

    # looks like, we don't need "global" stuff?
    # global v_tmp_is_bp_apis_only_when_debugee_ep_hit
    # global v_tmp_is_debugee_ep_been_hit
    if v_tmp_is_bp_apis_only_when_debugee_ep_hit and not v_tmp_is_debugee_ep_been_hit:

        # debugee ep not hit, so doing nothing....
        pass

    else:
        global v_tmp_is_always_check_sys_dll_sym
        if v_tmp_is_always_check_sys_dll_sym:
            if not sym.check_has_sys_dll_sym(new_dll_name):
                print ">>> first loaded dll but no symbol: %s" % new_dll_name
                # print ">>> %s" % sym.get_sym_sys_dll_names()
                # assert False

        apis.check_install_api_hooks(dbg)

    return defines.DBG_CONTINUE


def callback_process_exit(dbg):
    """
        pt line spliter and other things
    """
    _pt_log("-" * 100)
    _pt_log(">>> debugee exit, infos...")
    apis.callback_process_exit_pt_exit_call_stacks(dbg)
    apis.callback_process_exit_pt_api_details_summary(dbg)
    apis.callback_process_exit_pt_api_invoke_summary(dbg)
    apis.callback_process_exit_pt_last_api(dbg)
    apis.callback_process_exit_pt_bp_hit_count(dbg)
    apis.callback_process_exit_pt_file_reg_proc_summary(dbg)
    apis.callback_process_exit_pt_manual_resolved_funcs(dbg)
    debugee.callback_process_exit_pt_func_tree(dbg)
    debugee.callback_process_exit_pt_func_cnt(dbg)

    try:
        # exit callback
        from z_1111 import z_tmp_debugee_exit_cbk
        if z_tmp_debugee_exit_cbk is not None:
            z_tmp_debugee_exit_cbk(dbg)
    except:
        pass

    _pt_log("-" * 100)
    # call this last
    log.callback_process_exit_save_api_to_file(dbg)

    return defines.DBG_CONTINUE


def callback_any_exception(dbg, ec):
    """
        @param: ec : int : exception code
    """
    if v_tmp_is_pt_all_exceptions:
        print "exception code: %.8X - %s" % (ec, msdn.resolve_code_exception(ec))

    elif v_tmp_is_pt_unnormal_exceptions and ec not in []:
        print "exception code: %.8X - %s" % (ec, msdn.resolve_code_exception(ec))

    else:
        pass

# ---------------------------------------------------------------------------
# main
if __name__ == "__main__":

    target_dll = None
    target_entry = None

    if target_dll is None:

        # ? by default, this script is running as x86 ark.
        # src_file = r"D:\SoftWare\processhacker-2.39-bin\x86\ProcessHacker.exe"
        # src_file = r"C:\Windows\System32\calc.exe"
        # src_file = r"C:\Documents and Settings\Administrator\Desktop\1111.exe"
        src_file = r"1111.exe"
        cmd_line = None

        # this shall be some absolute path
        target_file = r""
        try:
            # load nope ranges
            from z_1111 import z_tmp_target_file
            # must be .lower()
            target_file = z_tmp_target_file.lower()
            from z_1111 import z_tmp_target_cmd_line
            cmd_line = z_tmp_target_cmd_line.lower()
        except:
            pass

        if len(target_file) != 0:

            # create tar dir
            tar_dir = os.path.dirname(target_file)
            if not os.path.exists(tar_dir):
                os.makedirs(tar_dir)

            # copy sample file
            shutil.copyfile(src_file, target_file)
            print ">>> file sample moved to: %s" % target_file

            # copy script file
            script_file_src = "z_1111.py"
            script_file_tar = "z_1111.py"
            if os.path.exists(script_file_src):
                shutil.copyfile(script_file_src, os.path.join(tar_dir, script_file_tar))

            # copy sym file
            sym_file_src = "1111_ida_names.txt"
            sym_file_dst = os.path.basename(target_file) + "_ida_names.txt"
            if os.path.exists(sym_file_src):
                shutil.copyfile(sym_file_src, os.path.join(tar_dir, sym_file_dst))

            # copy func file
            func_file_src = "1111_ida_funcs.txt"
            func_file_dst = os.path.basename(target_file) + "_ida_funcs.txt"
            if os.path.exists(func_file_src):
                shutil.copyfile(func_file_src, os.path.join(tar_dir, func_file_dst))

            # todo: might need to copy other files
        else:
            target_file = os.path.abspath(src_file)

        # make it absolute path, so other files don't need to absolute again.
        util.v_tmp_debugee_name = os.path.basename(target_file)
        util.v_tmp_debugee_dir = os.path.dirname(target_file)

    else:
        # format: rundll32.exe nameofdll, entrypointfunction arguments
        # we don't use rundll32.exe, but Loaddll.exe instead
        # todo......
        target_file = os.path.abspath(r"Loaddll.exe")

        target_dll = os.path.abspath(target_dll)
        if target_entry is None:
            cmd_line = "%s" % (target_dll)
        else:
            cmd_line = "%s, %s" % (target_dll, target_entry)

        util.v_tmp_debugee_name = os.path.basename(target_dll)
        util.v_tmp_debugee_dir = os.path.dirname(target_dll)

    # ---------------------------------------------------------------------------
    # load self-parsed symbols
    sym.load_sysdll_syms()
    sym.load_debugee_syms()

    # ---------------------------------------------------------------------------
    # load func address
    debugee.v_tmp_func_cnt_max_when_pt = 100                # when pt func invoke cnt, pt funcs that too freequently called
    debugee.v_tmp_func_cnt_max_runtime = 100                # when debugee run, ignore these funcs.
    debugee.v_tmp_exclude_func_address = []                 # exclude func address
    debugee.v_tmp_exclude_func_name = []                    # exclude func names
    debugee.load_debugee_func_list()                        # !+ set exclude list before load from .txt file
    debugee.v_tmp_debugee_nop_ranges = []                   # ranges to nop: [(start, end), (start, end), ...]
    try:
        # load nope ranges
        from z_1111 import z_tmp_debugee_nop_ranges
        for z_nope_range in z_tmp_debugee_nop_ranges:
            if z_nope_range not in apis.v_tmp_ignore_cat_names:
                debugee.v_tmp_debugee_nop_ranges.append(z_nope_range)
    except:
        pass
    # ---------------------------------------------------------------------------
    # configs - run

    # is hide debugger
    try:
        from z_1111 import z_tmp_is_hide_debugger
        v_tmp_is_hide_debugger = z_tmp_is_hide_debugger
    except:
        v_tmp_is_hide_debugger = True

    try:
        # only install api hook when debugee ep is hit. set to guarantee some code will be executed and executed quickly...
        # sometimes we need it be False, because we need redirect EOP to some other address.
        from z_1111 import z_tmp_is_bp_apis_only_when_debugee_ep_hit
        v_tmp_is_bp_apis_only_when_debugee_ep_hit = z_tmp_is_bp_apis_only_when_debugee_ep_hit
    except:
        v_tmp_is_bp_apis_only_when_debugee_ep_hit = True
    # there are some dlls with different version, we're not sure which version is loaded.
    # so, we ignore it by default.
    v_tmp_is_always_check_sys_dll_sym = True                # is always check we have sys dll symbol

    apis.v_tmp_is_intrude_debugee = True                    # is intrude debugee. sometimes we need to set this false, or debugee may xxx
    apis.v_tmp_fake_tick_start = None                       # is modify ret of GetTickCount()
    apis.v_tmp_is_shorten_sleep = True                      # is shorten sleep
    apis.v_tmp_is_ignore_all_wait_obj = False               # is ignore all wait for single/multiple objects
    apis.v_tmp_is_record_alloc_retn = True                  # is record memory alloc result
    apis.v_tmp_is_bpmmwrite_alloc_retn = False              # is set mm write bp at alloc result
    apis.v_tmp_is_backup_remove_dir_file = False            # is backup dir/file
    apis.v_tmp_is_all_socket_success = False                # is all socket api return success
    apis.v_tmp_is_save_send_data_to_file = False            # is save send data to file
    apis.v_tmp_is_save_recv_data_to_file = False            # is save recv data to file
    apis.v_tmp_is_access_success = False                    # is api "access" ret success
    # if mutex name has invalid chars, we can't compare mutex names.
    # in that case, we ignore all mutex
    apis.v_tmp_ignore_mutex_names = []                      # ignore mutex names
    apis.v_tmp_is_ignore_all_mutex = False                  # is ignore all mutex
    apis.v_tmp_equal_cmp_strings = []                       # equal strings, a list of tuple, each item: (str1, str2). for windows path, prefix with 'r'

    try:
        from z_1111 import z_tmp_new_sock_connect_ip        # new connect ip addr, in this format: "\xC0\xA8\x01\x0A", which means: 192.168.1.10
        from z_1111 import z_tmp_new_sock_connect_port      # new connect port, __int16
        from z_1111 import z_tmp_new_http_connect_addr      # new http connect addr, in this format: "192.168.1.10"
        apis.v_tmp_new_sock_connect_ip = z_tmp_new_sock_connect_ip
        apis.v_tmp_new_sock_connect_port = z_tmp_new_sock_connect_port
        apis.v_tmp_new_http_connect_addr = z_tmp_new_http_connect_addr
    except:
        apis.v_tmp_new_sock_connect_ip = None
        apis.v_tmp_new_sock_connect_port = None
        apis.v_tmp_new_http_connect_addr = None

    # fake module file name
    try:
        from z_1111 import z_tmp_fake_module_file_name
        apis.v_tmp_fake_module_file_name = z_tmp_fake_module_file_name
    except:
        apis.v_tmp_fake_module_file_name = None

    apis.v_tmp_ignore_cat_names = [                         # cat names that we're not intereseted in particular sample. only available when type has "a"
    ]
    try:
        # load ignore cats of this sample
        from z_1111 import z_tmp_ignore_cat_names
        for z_cat_name in z_tmp_ignore_cat_names:
            if z_cat_name not in apis.v_tmp_ignore_cat_names:
                apis.v_tmp_ignore_cat_names.append(z_cat_name)
    except:
        pass
    apis.v_tmp_ignore_api_names = [                         # api names that we're not interested in particular sample
        "WaitForSingleObjectEx",
        "WaitForMultipleObjectsEx",
        "CreateEventW",
        "_access",
        "EncryptFileW",
        "DecryptFileW",
        "ZwDelayExecution",

        # # test these apis
        # "CreateWindowExW"                     # 4
        # "Thread32Next",                       # 3
        # "PeekMessageA",                       # 2
        # "RegOpenKeyExW",                      # 2
        # "RaiseException",                     # 2
        # "CreateFileW",                        # 2
        # "LocalAlloc",                         # 2
        # "VirtualProtectEx",                   # 2
        # "KillTimer",                          # 2
        # "RegOpenKeyExA",                      # 1
        # "OpenFileMappingW",                   # 1
        # "CreateToolhelp32Snapshot",           # 1
        # "VirtualAllocEx",                     # 1
        # "lstrlenA",                           # 1
        # "CallNextHookEx",                     # 1
        # "DispatchMessageA",                   # 1

        # xx
        # "SleepEx",
    ]
    try:
        # load ignore apis of this sample
        from z_1111 import z_tmp_ignore_api_names
        for z_api_name in z_tmp_ignore_api_names:
            if z_api_name not in apis.v_tmp_ignore_api_names:
                apis.v_tmp_ignore_api_names.append(z_api_name)
    except:
        pass
    ignore_AutoIt_apis = [
        # too much
        "PeekMessageW", "DispatchMessageW", "KillTimer", "SetTimer",
        # other
    ]
    is_debugee_AutoIt = False
    if is_debugee_AutoIt:
        for autoit_api in ignore_AutoIt_apis:
            if autoit_api not in apis.v_tmp_ignore_api_names:
                apis.v_tmp_ignore_api_names.append(autoit_api)
    # set type and gather api
    #     "s" for all solid apis        add
    #     "u" for all unsolid apis      add
    #     "x" for special apis          add
    #     "t" for test apis             replace
    #     "n" for none                  replace
    # allow combination: "xt"
    apis.v_tmp_gather_api_type_str = "sux"
    apis.gather_apis()
    # # only bp alloc apis. do this when VirtualAllocEx doesn't help.
    # apis.gather_alloc_apis()

    debugee.v_tmp_is_install_debugee_patches = True         # is install debugee patches
    debugee.v_tmp_is_isntall_debugee_hooks = True           # is install debugee hooks
    debugee.v_tmp_is_install_debugee_func_starts = True     # is install debugee func start bps

    pydbg.v_tmp_is_treat_WaitForDebugEvent_as_termination = False  # is treat WaitForDebugEvent time out as process termination

    # ---------------------------------------------------------------------------
    # configs - pt

    v_tmp_is_pt_new_dll_load = False                        # is pt when new dll load
    v_tmp_is_pt_all_exceptions = False                      # is pt when any exception
    v_tmp_is_pt_unnormal_exceptions = False                 # is pt any unnormal exception

    apis.v_tmp_is_check_call_stack = True                   # is check call stack
    apis.v_tmp_is_pt_all_api_invoke_only = False            # is only pt api name, do not "do" other operations
    apis.v_tmp_is_pt_all_api_invoke_always = False          # is always pt api name, will "do" other operations also
    apis.v_tmp_is_pt_all_api_stacks_always = False          # is always pt api stacks, will "do" other operations also
    apis.v_tmp_is_pt_filtered_api_stacks = False            # is pt filered api call stack
    apis.v_tmp_is_pt_param_log_detail = False               # is pt param log details when param_log_ctrl.get_log()
    apis.v_tmp_is_pt_api_invoke_time = False                # is log time elasped for this api
    apis.v_tmp_is_pt_when_set_api_bp = False                # is pt when set bp at api

    output.v_tmp_is_pt_stacks_before_api_parse = False      # is pt callstacks before parsing api
    output.v_tmp_is_pt_parse_api_summary_collision = False  # is pt api summary collision when parsing api records

    debugee.v_tmp_is_pt_func_invoke = False                 # is pt func invoke

    # pt when process exit
    apis.v_tmp_is_pt_process_exit_call_stacks = True        # is pt call stacks when process exit
    apis.v_tmp_is_pt_process_exit_api_summary = True        # is pt api summary when process exit
    apis.v_tmp_is_pt_manual_resolved_funcs = False          # is pt debugee manual resolved funcs. we use this to enrich functionality of xrkpydbg.
    debugee.v_tmp_is_pt_func_tree_when_process_exit = True  # is pt func tree when process exit
    debugee.v_tmp_is_pt_func_cnt_when_process_exit = True   # is pt func cnt when process exit
    log.v_tmp_is_save_process_exit_log = False              # is save log record to file

    # ---------------------------------------------------------------------------
    # dbg session
    dbg = pydbg.pydbg(is_log=False)
    dbg.set_callback(defines.LOAD_DLL_DEBUG_EVENT, callback_func=callback_load_sys_dll)
    dbg.set_callback(defines.EXIT_PROCESS_DEBUG_EVENT, callback_func=callback_process_exit)
    dbg.set_callback(defines.EXCEPTION_DEBUG_EVENT, callback_func=callback_any_exception)
    dbg.load(target_file, command_line=cmd_line)
    # actually, len(dbg.system_dlls) == 0, so we don't install hook here
    dbg.run()
    print "xrkpydbg - debug session finish"

    # ---------------------------------------------------------------------------
    output.export_api_summary()
    print "xrkpydbg - export api summary finish"
    print "=" * 200
    print ""


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
