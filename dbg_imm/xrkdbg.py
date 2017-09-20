# -*- coding: utf-8 -*-

"""
    debugger functions

    1. imm
    2. xrkpydbg
"""

import os
import sys
import string
import pickle
import inspect
import traceback

v_is_imm = True

try:
    import debugger
    import immutils
    import debugtypes
except:
    this_path = os.path.split(os.path.realpath(inspect.stack()[-1][1]))[0]
    sys.path.append(this_path)
    try:
        import debugger
        import immutils
        import debugtypes
    except Exception, e:
        try:
            import xrkpydbg as debugger
            import xrkpydbg as immutils
            import xrkpydbg as debugtypes
            v_is_imm = False
        except:
            lines = ["xrkdbg import error: %s" % e]
            error = traceback.format_exc()
            while len(error) > 200:
                tmp = error[:200]
                lines.append("  %s" % tmp)
                error = error[200:]
            lines.append("  %s" % error)
            try:
                import immlib as dbglib
                dbg = dbglib.Debugger()
                for line in lines:
                    dbg.log(line, highlight=1)
            except:
                for line in lines:
                    print line

            assert False


def addKnowledge(id_, obj_, force_add=0x0):
    # return dbg.addKnowledge(id=id_, object=obj_, force_add=force_add)
    pickled_object = pickle.dumps(obj_)
    return debugger.add_knowledge(pickled_object, id_, force_add)


def getKnowledge(id_):
    # return dbg.getKnowledge(id=id_)
    pickled_object = debugger.get_knowledge(id_)
    if not pickled_object:
        return None
    return pickle.loads(pickled_object)


def forgetKnowledge(id_):
    # return dbg.forgetKnowledge(id=id_)
    return debugger.forget_knowledge(id_)


def cleanKnowledge():
    # return dbg.cleanKnowledge()
    for id_ in debugger.list_knowledge():
        forgetKnowledge(id_)


def cleanHooks():
    # return dbg.cleanHooks()
    for id_ in listHooks():
        debugger.remove_hook(id_)


def cleanUp():
    cleanHooks()
    cleanKnowledge()


def listHooks():
    # return dbg.listHooks()
    return debugger.list_hook()


def setComment(addr, comment):
    # return dbg.setComment(address=addr, comment=comment)
    return debugger.set_comment(addr, comment)


def setBreakpoint(addr):
    # return dbg.setBreakpoint(adresss=addr)
    # flags = BpFlags["TY_ACTIVE"] //0x200L
    return debugger.set_breakpoint(addr, 0x200L, "")


def setLoggingBreakpoint(addr):
    return debugger.set_logging_breakpoint(addr)


# HB_CODE = 1
def setHardwareBreakpoint(addr, type_=1, size=1):
    # return dbg.setHardwareBreakpoint(addr=addr, type=type_, size=size)
    return debugger.set_hardware_breakpoint(type_, addr, size)


def deleteBreakpoint(addr):
    # return dbg.deleteBreakpoint(address=addr, address2=0)
    return debugger.delete_breakpoints(addr, 0)


def log(msg, addr=0xbadf00d, highlight=False, gray=False, focus=0):
    if v_is_imm:
        return debugger.add_to_list(addr, int(highlight), msg[:255], focus)
    else:
        print msg


def logLines(msg, addr=0, highlight=False, gray=False, focus=0):
    """
        @param: msg: STRING: msgs split by "\n"
    """
    import immlib as dbglib
    dbg = dbglib.Debugger()
    return dbg.logLines(data=msg, address=addr, highlight=highlight, gray=gray, focus=focus)


def readMemory(addr, size):
    # return dbg.readMemory(address=addr, size=size)
    return debugger.read_memory(addr, size, 0x01 | 0x02)


def readShort(addr):
    # return dbg.readShort(address=addr)
    short = readMemory(addr, 0x2)
    return immutils.str2int16_swapped(short)


def readLong(addr):
    # return dbg.readLong(address=addr)
    long = readMemory(addr, 0x4)
    if len(long) == 4:
        try:
            return immutils.str2int32_swapped(long)
        except ValueError:
            raise Exception("readLong failed to gather a long at 0x%08x" % addr)
    else:
        raise Exception("readLong failed to gather a long at 0x%08x" % addr)


def readUntil(address, ending):
    readed = []
    while(1):
        read = readMemory(address, 16)
        address += 16
        ndx = read.find(ending)
        if ndx != -1:
            readed.append(read[0:ndx])
            break
        else:
            readed.append(read)

    return string.joinfields(readed, "")


def readString(addr):
    # return dbg.readString(address=addr)
    return readUntil(addr, '\x00')


def readWString(addr):
    # return dbg.readWString(address=addr)
    wstring = readUntil(addr, "\x00\x00")
    if not wstring.endswith("\x00"):
        wstring = wstring + "\x00"
    return wstring


def writeLong(addr, value):
    # return dbg.writeLong(address=addr, dword=value)
    return debugger.write_memory(immutils.intel_order(value), addr, 4, 0x2)


def writeMemory(addr, buf):
    # return dbg.writeMemory(address=addr, buf=buf)
    return debugger.write_memory(buf, addr, len(buf), 0x2)


def error(msg):
    # return dbg.error(msg=msg)
    return debugger.error(msg)


def getAddress(exp):
    # return dbg.getAddress(expression=exp)
    return debugger.get_addr_from_exp(exp)


def getFunctionEnd(addr):
    import immlib as dbglib
    dbg = dbglib.Debugger()
    return dbg.getFunctionEnd(function_address=addr)
    """
    if type(addr) in (type(1), type(1L)):
        func = __getFunction(addr)
        return func.getFunctionEnd()
    elif isinstance(addr, Function):
        return addr.getFunctionEnd()
    else:
        raise Exception("Function type not recognized")
    """


def getMemoryPages():
    import immlib as dbglib
    dbg = dbglib.Debugger()
    return dbg.getMemoryPages()
    """
    ret = {}
    pages = debugger.get_memory_pages()

    for addr in pages.keys():
        m = debugtypes.MemoryPage(addr, dbglib.Debugger())
        m._getfromtuple(pages[addr])
        ret[addr] = m
    return ret
    """


def getMemoryPageByAddress(addr):
    # return dbg.getMemoryPageByAddress(address=addr)
    pages = getMemoryPages()
    for a in pages.keys():
        mem = pages[a]
        if mem.baseaddress <= addr and (mem.getBaseAddress() + mem.size) > addr:
            return mem
    return None


def callStack():
    # return dbg.callStack()
    ret = []
    callstack = debugger.get_call_stack()
    for a in callstack:
        s = debugtypes.Stack()
        s._setfromtuple(a)
        ret.append(s)
    return ret


def getComment(addr, type_=0xFD):
    # return dbg.getComment(address=addr, type=type_)
    comment = None
    if type == 0xFD:
        comment = debugger.get_comment(addr, 0x36)
        if not comment:
            comment = debugger.get_comment(addr, 0x39)
            if not comment:
                comment = debugger.get_comment(addr, 0x37)
                if not comment:
                    comment = debugger.get_comment(addr, 0x3A)
    else:
        comment = debugger.get_comment(addr, type_)

    return comment


def getRegs():
    # return dbg.getRegs()
    return debugger.get_regs()


def setReg(reg_name, value):
    v_regs = {"EAX": 0, "ECX": 1, "EDX": 2, "EBX": 3, "ESP": 4, "EBP": 5, "ESI": 6, "EDI": 7, "EIP": 8}
    return debugger.set_reg(v_regs[reg_name], value)


def getEvent():
    import immlib as dbglib
    dbg = dbglib.Debugger()
    return dbg.getEvent()
    """
    event = debugger.get_event()
    EventCode = event[0][0]
    try:
        return self.Eventndx[ EventCode ]( event )
    except KeyError: # We cannot handle this event
        return None
    """


def isAnalysed(addr):
    # return dbg.isAnalysed(address=addr)
    ret = debugger.is_analysed(addr)
    if ret == -1:
        return 0
    else:
        return ret


def analyseCode(addr):
    # return dbg.analyseCode(address=addr)
    return debugger.analyse_code(addr)


def decodeAddress(addr):
    # return dbg.decodeAddress(address=addr)
    return debugger.decode_address(addr)


def getDebuggedPid():
    # return dbg.getDebuggedPid()
    return debugger.get_PID()


def getDebuggedName():
    # return dbg.getDebuggedName()
    return debugger.get_debugged_name()


def getAllModules():
    import immlib as dbglib
    dbg = dbglib.Debugger()
    return dbg.getAllModules()
    """
    ret = {}
    modulos = debugger.get_all_modules()
    symbol = 1
    for mod in modulos.keys():

        m = Module(mod, modulos[mod][0], modulos[mod][1], modulos[mod][2])
        mod_dict = self._getmoduleinfo(modulos[mod][0])
        m.setModuleExtension(mod_dict)
        if symbol:
            self.getAllSymbols() #_getsymbols()
            symbol = 0

        try:
            m.setSymbols( self.Symbols[ mod.lower() ] )
        except KeyError:
            pass
        ret[mod] = m
    return ret
    """


def getModuleByAddress(addr):
    import immlib as dbglib
    dbg = dbglib.Debugger()
    return dbg.getModuleByAddress(address=addr)


def getModule(name):
    import immlib as dbglib
    dbg = dbglib.Debugger()
    return dbg.getModule(name=name)


def getStatus():
    # return dbg.getStatus()
    return debugger.get_status()


def remoteVirtualAlloc(size=0x10000, interactive=True):
    # return dbg.remoteVirtualAlloc(size=size, interactive=interactive)
    return debugger.pVirtualAllocEx(0x0, size, 0x1000, 0x40)


def disasmCode(addr):
    import immlib as dbglib
    dbg = dbglib.Debugger()
    return dbg.disasmCode(address=addr)


def getThreadId():
    return debugger.get_thread_id()


def remove_hook(desc):
    return debugger.remove_hook(desc)


def getAllHandles():
    import immlib as dbglib
    dbg = dbglib.Debugger()
    return dbg.getAllHandles()


def gotoDisasmWindow(addr):
    import immlib as dbglib
    dbg = dbglib.Debugger()
    return dbg.gotoDisasmWindow(addr)


def gotoDumpWindow(addr):
    import immlib as dbglib
    dbg = dbglib.Debugger()
    return dbg.gotoDumpWindow(addr)
