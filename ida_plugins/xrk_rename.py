# -*- coding: utf-8 -*

"""
modified version of auto_re
"""

from collections import defaultdict
import idaapi
from idaapi import o_reg, o_imm, o_far, o_near, o_mem
import traceback

import idautils


HAS_PYSIDE = False
try:
    from PySide import QtGui, QtCore
    from PySide.QtGui import QTreeView, QVBoxLayout

    _slot = QtCore.Slot
    global HAS_PYSIDE
    HAS_PYSIDE = True
except ImportError:
    from PyQt5 import QtGui, QtCore
    from PyQt5.QtWidgets import QTreeView, QVBoxLayout

    # dummy
    def _slot(fn):
        def wrap(*args, **kwargs):
            return fn(*args, **kwargs)
        return wrap

import xrk_log
# from PyQt5 import QtGui, QtCore
# from PyQt5.QtWidgets import QTreeView, QVBoxLayout

# ---------------------------------------------------------------------------
# log, proxy to xrklog.py

v_log_header = "[XRK-LOADER] >> "


def msg(str_):
    xrk_log.msg(v_log_header, str_)


def msgs(strs):
    xrk_log.msgs(v_log_header, strs)


def warn(str_):
    xrk_log.warn(v_log_header, str)


# ---------------------------------------------------------------------------
# tags

TAGS_IGNORE_LIST = {
    'OpenProcessToken',
    'DisconnectNamedPipe'
}

IGNORE_CALL_LIST = {
    'RtlNtStatusToDosError',
    'GetLastError',
    'SetLastError'
}

TAGS = {
    'net': [
        'WSAStartup', 'socket', 'recv', 'recvfrom', 'send', 'sendto', 'acccept', 'bind', 'listen', 'select',
        'setsockopt', 'ioctlsocket', 'closesocket', 'WSAAccept', 'WSARecv', 'WSARecvFrom', 'WSASend', 'WSASendTo',
        'WSASocket', 'WSAConnect', 'ConnectEx', 'TransmitFile', 'HTTPOpenRequest', 'HTTPSendRequest',
        'URLDownloadToFile', 'InternetCrackUrl', 'InternetOpen', 'InternetOpen', 'InternetConnect',
        'InternetOpenUrl', 'InternetQueryOption', 'InternetSetOption', 'InternetReadFile', 'InternetWriteFile',
        'InternetGetConnectedState', 'InternetSetStatusCallback', 'DnsQuery', 'getaddrinfo', 'GetAddrInfo',
        'GetAdaptersInfo', 'GetAdaptersAddresses', 'HttpQueryInfo', 'ObtainUserAgentString', 'WNetGetProviderName',
        'GetBestInterfaceEx', 'gethostbyname', 'getsockname', 'connect'],
    'spawn': [
        'CreateProcess', 'ShellExecute', 'ShellExecuteEx', 'system', 'CreateProcessInternal', 'NtCreateProcess',
        'ZwCreateProcess', 'NtCreateProcessEx', 'ZwCreateProcessEx', 'NtCreateUserProcess', 'ZwCreateUserProcess',
        'RtlCreateUserProcess', 'NtCreateSection', 'ZwCreateSection', 'NtOpenSection', 'ZwOpenSection',
        'NtAllocateVirtualMemory', 'ZwAllocateVirtualMemory', 'NtWriteVirtualMemory', 'ZwWriteVirtualMemory',
        'NtMapViewOfSection', 'ZwMapViewOfSection', 'OpenSCManager', 'CreateService', 'OpenService',
        'StartService', 'ControlService'],
    'inject': [
        'OpenProcess-disabled', 'ZwOpenProcess', 'WriteProcessMemory', 'CreateRemoteThread', 'QueueUserAPC'],
    'com': [
        'CoCreateInstance', 'CoInitializeSecurity', 'CoGetClassObject', 'OleConvertOLESTREAMToIStorage'],
    'crypto': [
        'CryptAcquireContext', 'CryptProtectData', 'CryptUnprotectData', 'CryptProtectMemory',
        'CryptUnprotectMemory', 'CryptDecrypt', 'CryptEncrypt', 'CryptHashData', 'CryptDecodeMessage',
        'CryptDecryptMessage', 'CryptEncryptMessage', 'CryptHashMessage', 'CryptExportKey', 'CryptGenKey',
        'CryptCreateHash', 'CryptDecodeObjectEx', 'EncryptMessage', 'DecryptMessage']
}

blacklist = {'@__security_check_cookie@4', '__SEH_prolog4', '__SEH_epilog4'}
replacements = [
    ('??3@YAXPAX@Z', 'alloc'),
    ('?', '')
]


_PREFIX_NAME = 'au_re_'
_MIN_MAX_MATH_OPS_TO_ALLOW_RENAME = 10


# ---------------------------------------------------------------------------
def get_addr_width():
    return '16' if idaapi.cvar.inf.is_64bit() else '8'


# ---------------------------------------------------------------------------
class AutoREView(idaapi.PluginForm):
    ADDR_ROLE = QtCore.Qt.UserRole + 1

    def __init__(self, data):
        """
        """
        super(AutoREView, self).__init__()
        self._data = data

    def Show(self):
        return idaapi.PluginForm.Show(self, 'AutoRE', options=idaapi.PluginForm.FORM_PERSIST)

    def OnCreate(self, form):
        """
        """
        # if HAS_PYSIDE:
        #     self.parent = self.FormToPySideWidget(form)
        # else:
        self.parent = self.FormToPyQtWidget(form)

        self.tv = QTreeView()
        self.tv.setExpandsOnDoubleClick(False)

        root_layout = QVBoxLayout(self.parent)
        # self.le_filter = QLineEdit(self.parent)

        # root_layout.addWidget(self.le_filter)
        root_layout.addWidget(self.tv)

        self.parent.setLayout(root_layout)

        self._model = QtGui.QStandardItemModel()
        self._init_model()
        self.tv.setModel(self._model)

        self.tv.setColumnWidth(0, 200)
        self.tv.setColumnWidth(1, 300)
        self.tv.header().setStretchLastSection(True)

        self.tv.expandAll()

        self.tv.doubleClicked.connect(self.on_navigate_to_method_requested)
        # self.le_filter.textChanged.connect(self.on_filter_text_changed)

    def OnClose(self, form):
        """
        """
        # msg('TODO: OnClose(): clear the pointer to form in the plugin'
        pass

    def _tv_init_header(self, model):
        """
        """
        item_header = QtGui.QStandardItem("EA")
        item_header.setToolTip("Address")
        model.setHorizontalHeaderItem(0, item_header)

        item_header = QtGui.QStandardItem("Function name")
        model.setHorizontalHeaderItem(1, item_header)

        item_header = QtGui.QStandardItem("API called")
        model.setHorizontalHeaderItem(2, item_header)

    def _tv_make_tag_item(self, name):
        """
        """
        rv = QtGui.QStandardItem(name)

        rv.setEditable(False)
        return [rv, QtGui.QStandardItem(), QtGui.QStandardItem()]

    def _tv_make_ref_item(self, tag, ref):
        """
        """
        ea_item = QtGui.QStandardItem(('%0' + get_addr_width() + 'X') % ref['ea'])
        ea_item.setEditable(False)
        ea_item.setData(ref['ea'], self.ADDR_ROLE)

        name_item = QtGui.QStandardItem(ref['name'])
        name_item.setEditable(False)
        name_item.setData(ref['ea'], self.ADDR_ROLE)

        apis = ', '.join(ref['tags'][tag])
        api_name = QtGui.QStandardItem(apis)
        api_name.setEditable(False)
        api_name.setData(ref['ea'], self.ADDR_ROLE)
        api_name.setToolTip(apis)

        return [ea_item, name_item, api_name]

    def _init_model(self):
        """
        """
        self._model.clear()

        root_node = self._model.invisibleRootItem()
        self._tv_init_header(self._model)

        for tag, refs in self._data.items():
            item_tag_list = self._tv_make_tag_item(tag)
            item_tag = item_tag_list[0]

            root_node.appendRow(item_tag_list)

            for ref in refs:
                ref_item_list = self._tv_make_ref_item(tag, ref)

                item_tag.appendRow(ref_item_list)

    def on_navigate_to_method_requested(self, index):
        """
        """
        addr = index.data(role=self.ADDR_ROLE)
        if addr is not None:
            idaapi.jumpto(addr)

    # def on_filter_text_changed(self, text):
    #     msg('on_text_changed: %s' % text


# ---------------------------------------------------------------------------
def handle_tags(fn, fn_an):
    """
    """
    tags = dict(fn_an['tags'])
    if not tags:
        return
    msg('fn: %#08x tags: %s' % (fn.startEA, tags))
    cmt = idaapi.get_func_cmt(fn, True)
    if cmt:
        cmt += '\n'
    s = str(tags.keys())
    name = idaapi.get_ea_name(fn.startEA)
    item = {'ea': fn.startEA, 'name': name, 'tags': tags}
    if not cmt or s not in cmt:
        idaapi.set_func_cmt(fn, '%sTAGS: %s' % (cmt or '', s), True)
    # self.mark_position(fn.startEA, 'TAGS: %s' % s)
    for tag in tags:
        if tag not in _data:
            _data[tag] = list()
        _data[tag].append(item)


def handle_calls(fn, fn_an):
    """
    """
    num_calls = len(fn_an['calls'])
    if num_calls != 1:
        return

    dis = fn_an['calls'][0]
    if dis.Op1.type not in (o_imm, o_far, o_near, o_mem):
        return

    ea = dis.Op1.value
    if not ea and dis.Op1.addr:
        ea = dis.Op1.addr

    if idaapi.has_dummy_name(idaapi.getFlags(ea)):
        return

    possible_name = idaapi.get_ea_name(ea)
    if not possible_name or possible_name in blacklist:
        return

    normalized = normalize_name(possible_name)

    # if self._cfg.get('auto_rename'):
    if len(fn_an['math']) < _MIN_MAX_MATH_OPS_TO_ALLOW_RENAME:
        idaapi.do_name_anyway(fn.startEA, normalized)
    # TODO: add an API to the view
    msg('fn: %#08x: %d calls, %d math%s possible name: %s, normalized: %s' % (
        fn.startEA, len(fn_an['calls']), len(fn_an['math']), 'has bads' if fn_an['has_bads'] else '',
        possible_name, normalized))


def disasm_func(fn):
    """
        @param: fn  : obj : ida.func_t()

        @return: a list of dict : each dict item like this:
                                  {"ea": addr_of_line, "fn_ea": addr_of_function_start, "insn": obj_of_idaapi.insn_t()}
    """
    rv = list()
    items = list(idautils.FuncItems(fn.startEA))
    for item_ea in items:
        obj = {'ea': item_ea, 'fn_ea': fn.startEA, 'insn': None}
        if idaapi.decode_insn(item_ea) > 0:
            obj['insn'] = idaapi.cmd.copy()
        rv.append(obj)
    return rv


def analysis_handle_call_insn(dis, rv):
    """
    """
    rv['calls'].append(dis)
    if dis.Op1.type != o_mem or not dis.Op1.addr:
        return

    name = idaapi.get_ea_name(dis.Op1.addr)
    name = name.replace(idaapi.FUNC_IMPORT_PREFIX, '')

    if '@' in name:
        name = name.split('@')[0]

    if not name:
        return

    if name in IGNORE_CALL_LIST:
        rv['calls'].pop()
        return

    for tag, names in TAGS.items():
        if name in TAGS_IGNORE_LIST:
            continue

        for tag_api in names:
            if tag_api in name:
                # msg('%#08x: %s, tag: %s' % (dis.ea, name, tag)
                rv['tags'][tag].append(name)
                break


def analyze_func(fn):
    """
        @param: fn  : obj : ida.func_t()

        @return: dict :
    """
    rv = {'fn': fn, 'calls': [], 'math': [], 'has_bads': False, 'tags': defaultdict(list)}
    items = disasm_func(fn)

    # iter each line of this function
    for item in items:

        insn = item['insn']
        if insn is None:
            rv['has_bads'] = True
            continue

        if insn.itype in (idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni):
            analysis_handle_call_insn(insn, rv)

        elif insn.itype == idaapi.NN_xor:
            if insn.Op1.type == o_reg and insn.Op2.type == o_reg and insn.Op1.reg == insn.Op2.reg:
                continue
            rv['math'].append(insn)

        elif insn.itype in (idaapi.NN_shr, idaapi.NN_shl, idaapi.NN_sal, idaapi.NN_sar, idaapi.NN_ror,
                            idaapi.NN_rol, idaapi.NN_rcl, idaapi.NN_rcl):
            # TODO
            rv['math'].append(insn)

    return rv


def normalize_name(n):
    """
    """
    for repl in replacements:
        n = n.replace(*repl)
    if '@' in n:
        n = n.split('@')[0]
    if len(n) < 3:
        return ''
    if not n.startswith(_PREFIX_NAME):
        n = _PREFIX_NAME + n
    return n


# ---------------------------------------------------------------------------
if __name__ == "__main__":

    # import sip
    try:
        _data = dict()
        count = idaapi.get_func_qty()
        for i in xrange(count):
            fn = idaapi.getn_func(i)
            fn_an = analyze_func(fn)

            # if fn_an['math']:
            #   msg('fn: %#08x has math' % fn.startEA

            if idaapi.has_dummy_name(idaapi.getFlags(fn.startEA)):
                handle_calls(fn, fn_an)

            handle_tags(fn, fn_an)

        # view = AutoREView(_data)
        # view.Show()
    except:
        idaapi.msg('AutoRE: error: %s\n' % traceback.format_exc())
