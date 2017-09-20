# -*- coding: utf-8 -*

"""
0. 整合其他脚本

1. 各种导出，跟调试器配合使用

2. 动态解析出来的函数，设置其参数类型，之类的
   包括UIF解析结果、pydbg解析结果等

3. 先手动处理"unexplored"
   idaapi.next_unknown()
   idaapi.prev_unknown()
   idaapi.find_unknown()
   把代码标记为"explored"

4. 在非函数代码中，跳转到前面的/后面的函数定义/数据定义/0xCC之类的

5. 在函数代码中，跳转到函数头/尾

6. 字符串窗口：
   对字符串筛选、标色
   使用floss的功能，补充字符串(因为过程中资源消耗的问题: 要有弹窗提示; 用单独的进程来搞，把结果写入文件，再从文件中读取)

7. 单独的BinDiff程序，偶尔无法比较; IDA内置的BinDiff，最后在导出结果时一直失败





# 补充样本: 这个可以搞

"""
"""
1. IDA: Ctrl+Q: Problem列表:
   NODISASM : CC、数据
   ALREADY  : 数据被解析为代码
   BADSTACK : 堆栈不平。那些没有负数堆栈的，都可以F5
   DECISION : 不会执行的代码
   ROLLBACK : 代码段的数据、字符串等
   SIGFNREF : Sig匹配不确定。一般都是短函数
"""


import os
import sys
import idaapi
import inspect
import xrk_log

file_path = os.path.abspath(inspect.getsourcefile(lambda: 0))
file_dir = os.path.dirname(inspect.getsourcefile(lambda: 0))

# 要在这里插入path，不然弹出的界面没有图标
sys.path.insert(0, os.path.join(file_dir, "xrk_pyeditor\\icons"))
from ico import *


#
# 避免重新打开IDA来加载修改后的py文件的方式：
# 用固定的py文件，注册功能，在功能代码中调用：idaapi.IDAPython_ExecScript()
#


#
# 可用的快捷键：
# Alt-N
# Alt-Z
# Ctrl-H
# Ctrl-Y
#

# ---------------------------------------------------------------------------
# log, proxy to xrklog.py

v_log_header = "[XRK-LOADER] >> "


def msg(str_):
    xrk_log.msg(v_log_header, str_)


def msgs(strs):
    xrk_log.msgs(v_log_header, strs)


def warn(str_):
    xrk_log.warn(v_log_header, str_)


# ---------------------------------------------------------------------------
class handler_test(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        """
            @param: ctx : obj : idaapi.action_activation_ctx_t()
        """
        msg("hander test -- activate")

    def update(self, ctx):
        """
            @param: ctx : obj : idaapi.action_update_ctx_t()

            @return: int : idaapi.AST_XX(enum action_state_t{})
        """
        msg("hander test -- update")
        return idaapi.AST_ENABLE_ALWAYS


class handler_pt_list(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        lines = []
        lines.append("Ctrl + Alt + 0  >> print registered script file list")
        lines.append("Ctrl + Alt + 1  >> test")
        lines.append("Ctrl + Alt + 2  >> exec py_editory.py to pop script editor window")
        # lines.append("Ctrl + Alt + 3  >> walk to next unexplored")
        lines.append("Ctrl + Alt + 4  >> auto rename")
        lines.append("Ctrl + Alt + 5  >> export something")
        lines.append("Ctrl + Alt + 6  >> patch string from z_ida_patch.py")
        lines.append("Ctrl + Alt + 7  >> patch binary from _patch.bin")
        lines.append("Ctrl + Alt + 8  >> exec xrk_test.py to test something")
        msgs(lines)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class handler_py_editor(idaapi.action_handler_t):
    """
        exec pyeditor.py to pop up python editor window
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        """
            exec script to pop up python editor window
        """
        g = globals()
        idaapi.IDAPython_ExecScript(os.path.join(file_dir, "xrk_pyeditor\\pyeditor.py"), g)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class handler_exec_py_script(idaapi.action_handler_t):
    def __init__(self, py_script_name):
        """
            store python file path
        """
        idaapi.action_handler_t.__init__(self)
        self.py_script_name = py_script_name
        self.py_script_path = os.path.join(file_dir, py_script_name)

        if not os.path.exists(self.py_script_path):
            warn("python script file not exists: %s" % self.py_script_path)

    def activate(self, ctx):
        """
            execute script
        """
        if not os.path.exists(self.py_script_path):
            warn("python script file not exists: %s" % self.py_script_path)
        else:
            msg("exec py script: %s" % self.py_script_name)
            g = globals()
            idaapi.IDAPython_ExecScript(self.py_script_path, g)

    def update(self, ctx):
        """
            TODO: update @return accordingly.
        """
        return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
def callback(evt, *args):
    """
    """
    # msg("cbk - evt - %d" % evt)
    return 0


# ---------------------------------------------------------------------------
class xrkloader(idaapi.plugin_t):

    flags = idaapi.PLUGIN_FIX
    comment = "This is loader for many scripts"

    help = "register many shortcuts to execute standalone python scripts"
    wanted_name = "xrkloader"
    wanted_hotkey = "ALT-N"
    is_act_no_shortcut_registered = False
    is_act_with_shortcut_registered = False
    is_decompile_cbk_installed = False

    def init(self):
        """
        """
        # msg("init()")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        """
            1. register actions(shortcuts)
            2. install decompile callback
        """
        # msg("run()")

        # actions - no shortcut
        if not self.is_act_no_shortcut_registered:
            # idaapi.register_action()
            self.is_act_no_shortcut_registered = True
            msg("register actions no shortcuts success")
        else:
            msg("actions no shortcut already registered")

        # actions - shortcut
        if not self.is_act_with_shortcut_registered:
            idaapi.register_action(idaapi.action_desc_t("print script list", "print script list", handler_pt_list(), "Ctrl-Alt-0", "print script list(with shortcuts)"))
            idaapi.register_action(idaapi.action_desc_t("test", "test", handler_test(), "Ctrl-Alt-1", "just test for xrk loader"))
            idaapi.register_action(idaapi.action_desc_t("py_editor", "py_editor", handler_exec_py_script("xrk_pyeditor\\pyeditor.py"), "Ctrl-Alt-2", "python script editor"))
            # idaapi.register_action(idaapi.action_desc_t("unexp_walk", "unexp_walk", handler_exec_py_script("xrk_unexp_walk.py"), "Ctrl-Alt-3", "walk to next unexplorered code"))
            idaapi.register_action(idaapi.action_desc_t("auto_rename", "auto_rename", handler_exec_py_script("xrk_rename.py"), "Ctrl-Alt-4", "auto rename some functions"))
            idaapi.register_action(idaapi.action_desc_t("export", "export", handler_exec_py_script("xrk_export.py"), "Ctrl-Alt-5", "export something(code)"))
            idaapi.register_action(idaapi.action_desc_t("patch_string", "patch_string", handler_exec_py_script("xrk_path_str.py"), "Ctrl-Alt-6", "patch string from z_ida_patch.py"))
            idaapi.register_action(idaapi.action_desc_t("patch_binary", "patch_binary", handler_exec_py_script("xrk_path_bin.py"), "Ctrl-Alt-7", "patch binary from _patch.bin"))
            idaapi.register_action(idaapi.action_desc_t("test_script", "test_script", handler_exec_py_script("xrk_test.py"), "Ctrl-Alt-8", "exec test script"))
            self.is_act_with_shortcut_registered = True
            msg("register actions with shortcuts success")
        else:
            msg("actions with shortcut already registered")

        # decompile callback
        if not self.is_decompile_cbk_installed:
            if idaapi.init_hexrays_plugin():
                msg("decompiler version: %s" % idaapi.get_hexrays_version())
                self.is_decompile_cbk_installed = idaapi.install_hexrays_callback(callback)
                if not self.is_decompile_cbk_installed:
                    warn("install decompile callback fail")
                else:
                    msg("install decompile callback success")
            else:
                warn("init hexrays fail, not installing decompile callback")
        else:
            msg("decompile callback already installed")

        # todo: if all success, then this plugin don't require to "run", so we un-register hotkey

        # msg("run() -- finish")

    def term(self):
        """
        """
        # msg("term()")
        pass


# ---------------------------------------------------------------------------
def PLUGIN_ENTRY():
    return xrkloader()


#
# from x_ida.py
#


# ---------------------------------------------------------------------------
# util
# ---------------------------------------------------------------------------


def test():
    print "this is test from x_ida"


def time_str():
    return time.strftime('%Y%m%d_%H_%M_%S', time.localtime(time.time()))

# ---------------------------------------------------------------------------
# function
# ---------------------------------------------------------------------------


def get_non_sub_functions():
    """
        get all functions that do not start with "sub_" and "unknown" and "nullsub"

        @return: LIST: a list of TUPLE. tuple: (start_addr, end_addr, name)
    """
    ret = []
    for f in idautils.Functions():
        name = idc.GetFunctionName(f)
        if not name.startswith("sub_") and not name.startswith("unknown") and not name.startswith("nullsub"):
            ret.append((idc.GetFunctionAttr(f, 0), idc.GetFunctionAttr(f, 4), name))
    return ret


def save_non_sub_function(file_name):
    """
        save format: addr(DEC) name

        @param: file_name: format: xxxx_ida_names.txt
    """
    f = open(file_name, "w")
    for func in get_non_sub_functions():
        f.write("%d %d %s\n" % (func[0], func[1], func[2]))
    print "save non sub functio to file finish: %s" % file_name


"""
ida script:

import x_ida
reload(x_ida)
for x in x_ida.get_non_sub_functions():
    # DEC, not HEX
    print "%d %d %s" % (x[0], x[1], x[2])
"""

# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
