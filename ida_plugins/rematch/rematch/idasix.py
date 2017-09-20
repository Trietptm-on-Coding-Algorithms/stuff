# -*- coding: utf-8 -*-

"""
"""

# -------------------------------------------------------------------------

IDA_SDK_VERSION = None
try:
    import ida_pro
    IDA_SDK_VERSION = ida_pro.IDA_SDK_VERSION
except ImportError:
    import idaapi
    IDA_SDK_VERSION = idaapi.IDA_SDK_VERSION

if not IDA_SDK_VERSION:
    raise Exception("Couldn't figure out IDA version")

# Handle different Qt versions. instead of:
# 1. `from PySide import QtCore, QtGui` or
# 2. `form PyQt5 import QtCore, QtWidgets`
# use:
# `from idasix import QtCore, QtWidgets`
QtGui = None
QtWidgets = None
QtCore = None
if IDA_SDK_VERSION >= 690:
    # IDA version >= 6.9
    from PyQt5 import QtCore, QtGui, QtWidgets
    _ = QtCore
elif IDA_SDK_VERSION < 690:
    # IDA version <= 6.8
    from PySide import QtCore, QtGui
    QtWidgets = QtGui
    _ = QtCore


modules_list = ['ida_allins', 'ida_area', 'ida_auto', 'ida_bytes', 'ida_dbg',
                'ida_diskio', 'ida_entry', 'ida_enum', 'ida_expr', 'ida_fixup',
                'ida_fpro', 'ida_frame', 'ida_funcs', 'ida_gdl', 'ida_graph',
                'ida_hexrays', 'ida_ida', 'ida_idaapi', 'ida_idd', 'ida_idp',
                'ida_ints', 'ida_kernwin', 'ida_lines', 'ida_loader',
                'ida_moves', 'ida_nalt', 'ida_name', 'ida_netnode',
                'ida_offset', 'ida_pro', 'ida_queue', 'ida_registry',
                'ida_search', 'ida_segment', 'ida_srarea', 'ida_strlist',
                'ida_struct', 'ida_typeinf', 'ida_ua', 'ida_xref']
if IDA_SDK_VERSION >= 695:
    import ida_idaapi
    import ida_pro
    import ida_kernwin
    for module in modules_list:
        globals()[module] = __import__(module)
elif IDA_SDK_VERSION < 695:
    import sys
    import idaapi

    ida_idaapi = idaapi
    ida_pro = idaapi
    ida_kernwin = idaapi
    for module in modules_list:
        sys.modules[module] = idaapi


# expose an ida plugin so when this is loaded as a plugin, ida will keep it
# loaded. this enables using idasix as an independent ida plugin instead of
# carrying idasix with every module.
class DummyIDASixPlugin(ida_idaapi.plugin_t):
    # Load when IDA starts and don't unload until it exits
    flags = ida_idaapi.PLUGIN_FIX

    def init(self, *args, **kwargs):
        super(DummyIDASixPlugin, self).__init__(*args, **kwargs)
        return ida_idaapi.PLUGIN_KEEP

    def run(self):
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():  # noqa: N802
    return DummyIDASixPlugin()


# methods in charge of actually fixing ida-related differances between versions
class Fix(object):

    @staticmethod
    def packagespath():
        """Hack required in relatively old IDA linux/osx versions (around
        6.4/5) to successfully load python packages installed in site-packages.

        IDA for linux/osx was using the machine's installed python instead of a
        packaged version, but that version was running without using
        site-packages. This made a user unable to install python packages and
        use them within ida without going through quite a bit of truble,
        without using this.
        """
        import sys
        import os
        new_path = os.path.join(sys.prefix, "Lib", "site-packages")
        if os.path.exists(new_path) and new_path not in sys.path:
            sys.path += [new_path]

    @staticmethod
    def actionhandlerobject():
        """Before IDA 6.95, `action_handler_t` does not inherit from `object`
        and that makes some python magic fail. Since 6.95 `action_handler_t`
        inherits `object`. This fix makes reachable `action_handler_t` inherit
        from `object` before 6.95, and also protects against multiple-object
        inheritance.
        """
        # if action_handler_t is already defined from within a module named
        # the same as our module, method has been called for the second time
        # and should be ignored.
        action_handler_t_name = ida_kernwin.action_handler_t.__name__
        if action_handler_t_name == "action_handler_t_objprotect":
            return

        # this makes sure we have an `object` inheriting action_handler_t
        # regardless of version
        if issubclass(ida_kernwin.action_handler_t, object):
            action_handler_t_obj = ida_kernwin.action_handler_t
        else:
            class action_handler_t_obj(object,  # noqa: N801
                                       ida_kernwin.action_handler_t):
                """A base object created by `idasix.Fix.actionhandlerobject` to
                inherit `object`."""
                pass

        # this makes sure object will not be inherited for a second time, which
        # is an issue for certain ida versions.
        class action_handler_mc(type):  # noqa: N801

            def __new__(cls, name, bases, dct):
                bases = tuple(base for base in bases if base is not object)
                return super(action_handler_mc, cls).__new__(cls, name, bases,
                                                             dct)

        class action_handler_t_objprotect(action_handler_t_obj):  # noqa: N801
            """An object inheriting from ``idasix.Fix.action_handler_t_obj`
            that uses a metaclass to protect against multiple `object`
            inharitance. This makes sure that `object` is only inherited once
            even when a user manually inherits from it again"""
            __metaclass__ = action_handler_mc

        ida_kernwin.action_handler_t = action_handler_t_objprotect

    @staticmethod
    def qtsignalslot():
        """While pre-6.8 qt4 library pyside exposted `Qtcore.Signal` and
        `QtCore.Slot`, new pyqt library exposes those same methods as
        `QtCore.pyqtSignal` and `QtCore.pyqtSlot`. This fix makes sure
        `Qtcore.Signal` and `QtCore.Slot` are always available"""
        if IDA_SDK_VERSION >= 690:
            QtCore.Signal = QtCore.pyqtSignal
            QtCore.Slot = QtCore.pyqtSlot
        elif IDA_SDK_VERSION < 690:
            pass


Fix.packagespath()
Fix.actionhandlerobject()
Fix.qtsignalslot()
