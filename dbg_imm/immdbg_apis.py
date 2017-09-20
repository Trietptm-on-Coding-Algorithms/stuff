class Debugger(object):

    def clearState(self):
        pass

    ### Immunity Debugger Knowledge ###

    def addKnowledge(self, id, object, force_add = 0x0):
            """
                This function add a python object to the knowledge database.

                @type  id: STRING
                @param id: unique name tag of the object

                @type  object: Python object
                @param object: Object to be saved in the knowledge database
                """
        pass

    def getKnowledge(self,id):
            """
                Gets python object from the knowledge database.

                @type  id: STRING
                @param id: unique name tag of the object

                @rtype:  PYTHON OBJECT
                @return: Object retrieved from the knowledge database
                """
        pass

    def listKnowledge(self):
        """
            Gets the list of saved objects in the knowledge database.

            @rtype: TUPLE
            @return: List of String ids currently saved
            """
        pass

    def findPacker(self, name, OnMemory = True):
        """
            Find possible Packer/Cryptors/etc on a Module

            @type name: STRING
            @param name: Module name

            @type  OnMemory: (Optional, Def: True) BOOLEAN
            @param OnMemory: Whether to look in memory or on a file.

            @rtype:  LIST of TUPLES in the form of (DWORD, LIST OF STRING)
            @return: A list of the Packer founded (Offset, List of Packer found in that address)
            """
        pass

    def forgetKnowledge(self,id):
        """
            Remove python object from knowledge database.

            @type  id: STRING
            @param id: unique name tag of the object
            """
        pass

    def cleanKnowledge(self):
        """ Clean ID memory from known objects
            """
        pass

    def addGenHook(self,object):
        """
            Add a hook to Immunity Debugger
            """
        pass

    def cleanHooks(self):
        """
            Clean ID memory from hook objects
            """
        pass

    def cleanUp(self):
        """
            Clean ID memory for every kind of object saved in it
            """
        pass

    def getPEBAddress(self):
        """
            Gets PEB.
            @rtype:  DWORD
            @return: PEB address
            """
        pass

### Disassembling / Analyzing Functions / etc ###

    def analyseCode(self,address):
        """
            Analyse module's code

            @type  Address: DWORD
            @param Address: Address from module to be analysed
            """
        pass

    def isAnalysed(self,address):
        """
            Check if module is already analysed

            @type  Address: DWORD
            @param Address: Address from module

            @rtype: DWORD
            @return: 1 if module already analysed
            """
        pass

    def setVariable(self,address,string):
        """
           Set Variable name to specified address.

           @type Address: DWORD
           @param Address: Address from assembly line

           @type String: STRING
           @param String: Variable name to be set
           """
        pass

    def getVariable(self,address):
        """
           Get Variable name from specified address

           @type Address: DWORD
           @param Address: Address from assembly line

           @rtype: STRING
           @return: Variable name for given address.

        """
        pass

    def validateAddress(self, address, perm):
        """
        It validates if a given address has the permissions provided in <perm>.
        perm = RWXNC (N=No Access, C=Write Copy)
        """
        pass

    def getCurrentTEBAddress(self):
        pass

    def disasm(self, address, mode = DISASM_ALL):
        """
            disasm address

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  Mode: (Optional, Def: DISASM_ALL)
            @param Mode: disasm mode

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    # disasmSize 0.00007515 usec/pass
    def disasmSizeOnly(self, address):
        """
            Determine command size only

            @type  Address: DWORD
            @param Address: Address to disasm

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    # disasmData 0.00007375 usec/pass
    def disasmData(self, address):
        """
            Determine size and analysis data

            @type  Address: DWORD
            @param Address: Address to disasm

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    def disasmTrace(self, address):
        """
            Trace integer registers

            @type  Address: DWORD
            @param Address: Address to disasm

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    # disasmFile 0.00007934 usec/pass
    def disasmFile(self, address):
        """
            Disassembly, no symbols/registers

            @type  Address: DWORD
            @param Address: Address to disasm

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    # disasmCode 0.00008549 usec/pass
    def disasmCode(self, address):
        """
            Disassembly, registers undefined

            @type  Address: DWORD
            @param Address: Address to disasm

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    def disasmRTrace(self, address):
        """
            Disassemble with run-trace registers

            @type  Address: DWORD
            @param Address: Address to disasm

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    def disasmForward( self, address, nlines=1, mode = DISASM_ALL):
        """
            disasm nlines forward of given address

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @type  Mode: (Optional, Def: DISASM_ALL)
            @param Mode: disasm mode

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    def disasmForwardAddressOnly(self, address, nlines=1):
        """
            disasm nlines forward to the given address

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @type  Mode: (Optional, Def: DISASM_ALL)
            @param Mode: disasm mode

            @rtype:  DWORD
            @return: Address of the opcode
            """
        pass

    def disasmForwardSizeOnly(self, address, nlines=1):
        """
            Determine command size only

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    def disasmForwardData(self, address, nlines=1):
        """
            Determine size and analysis data

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode

            """
        pass

    def disasmForwardTrace(self, address, nlines=1):
        """
            Trace integer registers

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    def disasmForwardFile(self, address, nlines=1):
        """
            Disassembly, no symbols/registers

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    def disasmForwardCode(self, address, nlines=1):
        """
            Disassembly, registers undefined

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    def disasmForwardRTrace(self, address, nlines=1):
        """
            Disassemble with run-trace registers

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    def disasmBackward( self, address, nlines = 1, mode = DISASM_ALL):
        """
            disasm nlines backward from the given address

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    def disasmBackwardAddressOnly(self,address,nlines=1):
        """
            disasm nlines backward of given address

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  DWORD
            @return: Address of the Opcode
            """
        pass

    def disasmBackwardSizeOnly(self, address, nlines = 1):
        """
            Determine command size only

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    def disasmBackwardData(self, address, nlines = 1):
        """
            Determine size and analysis data

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    def disasmBackwardTrace(self, address, nlines = 1):
        """
            Trace integer registers

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    def disasmBackwardFile(self, address, nlines = 1):
        """
            Disassembly, no symbols/registers

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    def disasmBackwardCode(self, address, nlines = 1):
        """
            Disassembly, registers undefined

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    def disasmBackwardRTrace(self, address, nlines = 1):
        """
            Disassemble with run-trace registers

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    def findDecode(self, address):
        """
            Get the internal decode information from an analysed module

            @type  Address: DWORD
            @param Address: Address in the range of the module page

            @rtype:  Decode OBJECT
            @return: Decode Object containing the analized information
            """
        pass

    def goNextProcedure(self):
        """
            Go to next procedure

            @rtype: DWORD
            @return: Address of next procedure
            """
        pass

    def goPreviousProcedure(self):
        """
            Go to previous procedure

            @rtype:  DWORD
            @return: Address of previous procedure
            """
        pass

    def getOpcode(self,address):
        """
            Get address's Opcode

            @type  Address: DWORD
            @param Address: Address to disasm

            @rtype:  opCode Object (Check libanalyze.py)
            @return: Disassmbled Opcode
            """
        pass

    def assemble(self, code,address=0x0):
        """
            assemble code.

            @type  code: STRING
            @param code: Code to be assembled

            @rtype:  STRING
            @return: Opcodes of the assembled code
            """
        pass

     def decodeAddress(self,address):
        """
            Decode given address

            @rtype: STRING
            @return: decoded value
            """
        pass

    def undecorateName(self,decorated):
        """
            Undecorate given name

            @type decorated: STRING
            @param decorated: decorated name
            @rtype: STRING
            @return: undecorated name
            """
        pass

    def getTraceArgs(self, address, tracedarg, shownonusersupplied = False):
        """
            Trace Parameters of a function, return only when is user-supplied

            @type  Address: DWORD
            @param Address: Address of the function call

            @type  Tracedarg: DWORD
            @param Tracedarg: Parameter to trace

            @type  Shownonusersupplied: BOOLEAN
            @param Shownonusersupplied: (Optional, Def: False) Flag whether or not show user supplied param

            @rtype: TUPLES
            @return: Returns a tuple of (Push Opcode, TABLE of OPCODES setting the PUSH)
            """
        pass

    def getAllFunctions(self,address):
        """
            Gets all function of given module's address

            @rtype: LIST
            @return: Function start address
            """
        pass

    def getFunction(self, address):
        """
            Get the Function information

            @type  Address: DWORD
            @param Address: Address of the function

            @rtype:  Function Object
            @return: Function Object containing information of the requested function

            """
        pass

    def getFunctionBegin(self,address):
        """
            Find start address of funcion

            @rtype:  DWORD
            @return: Start Address
            """
        pass

    def getFunctionEnd(self, function_address):
        """
            Get all the possible ends of a Function

            @type  function_address: DWORD
            @param function_address: Address of the function

            @rtype:  LIST
            @return: List of Address of all the possible ret address
            """
        pass

    def getAllBasicBlocks(self,address):
        """
            Gets all basic blocks of given procedure (Deprecated, use Function)

            @rtype: LIST
            @return: (start,end) addresses of basic blocks
            """
        pass

    def findDataRef(self,address):
        """
            Find data references to given address

            @rtype:  LIST
            @return: Table with found references
            """
        pass

    def getXrefFrom(self, address):
        """
            Get X Reference from a given address

            @type  Address: DWORD
            @param Address: Address

            @rtype:  LIST
            @return: List of X reference from the given address
            """
        pass

    def getXrefTo(self, address):
        """
            Get X Reference to a given address

            @type  Address: DWORD
            @param Address: Address

            @rtype:  LIST
            @return: List of X reference to the given address
            """
        pass

    def getInterCalls(self,address):
        """
            Get intermodular calls

            @type  Address: DWORD
            @param Address: Address

            @rtype: DICTIONARY
            @return: Dict of intermodular calls to the given address
            """
        pass

    ### Gathering Information for the debugged process ###
    # All kind of information that can be gathered for the process (PEB, Heap, Events, Modules, etc)

    def getRegs(self):
        """
            Get CPU Context values.

            @rtype:  DICTIONARY
            @return: x86 Registers
            """
        pass

    def getRegsRepr(self):
        """
            We have to do this to handle the Long integers, which XML-RPC cannot do

            @rtype: DICTIONARY
            @return: x86 registers in string format (repr)
            """
        pass

    def setReg(self,reg,value):
        """
            Set REG value

            @type  reg: STRING
            @param reg: Register name

            @type  value: DWORD
            @param vale: Value to set the register
            """
        pass

    def getPEB(self):
        """
            Get the PEB information of the debugged process

            @rtype:  PEB OBJECT
            @return: PEB
            """
        pass

    def getHeap(self, addr, restore = False):
        """
            Get Heap Information

            @type  addr: DWORD
            @param addr: Address of the heap

            @type  restore: BOOLEAN
            @param restore: (Optional, Def: False) Flag whether or not use a restore heap

            @rtype: PHeap OBJECT
            @return: Heap
            """
        pass

    def getDebuggedName(self):
        """
            Get debugged name

            @rtype:  STRING
            @return: Name of the Process been debugged
            """
        pass

    def getDebuggedPid(self):
        """
            Get debugged pid

            @rtype:  DWORD
            @return: Process ID
            """
        pass

    def isAdmin(self):
        """
        Is debugger running as admin?
        @rtype: INTEGER
        @return: 1 if running as admin
        """
        pass

    def getInfoPanel(self):
        """
            Get information displayed on Info Panel

            @rtype: TUPLE
            @return: Python Tuple with the 3 lines from InfoPanel
            """
        pass

    def getCurrentAddress(self):
        """
            Get the current address been focus on the disasm window

            @rtype:  DWORD
            @return: Address
            """
        pass

    def getAllModules(self):
        """
            Get all loaded modules.

            @rtype:  DICTIONARY
            @return: Dict of Modules
            """
        pass

    def getModuleByAddress(self, address):
        pass

    def getModule(self, name):
        """
            Get Module Information

            @type  name: STRING
            @param name: Name of the module

            @rtype:  Module OBJECT
            @return: A Module object
            """
        pass

    def _getmoduleinfo(self,base_address):
        pass

    def getReferencedStrings(self,code_base):
        """
            Get all referenced string from module

            @type  name: DWORD
            @param name: Code Base Address
            @rtype: LIST
            @return: A list of tuples with referenced strings (address, string, comment)
            """
        pass

    def ps(self):
        """
            List all active processes.

            @rtype:  LIST
            @return: A list of tuples with process information (pid, name, path, services, tcp list, udp list)
            """
        pass

    def getSehChain(self):
        """
            Get the SEH chain.

            @rtype:  LIST
            @return: A list of tuples with SEH information (seh, handler)
            """
        pass

    def getEvent(self):
        """
            Get the current Event

            @rtype:  Event Object
            @return: Event
            """
        pass

    def getPage(self, addr):
        """
            Get a memory page.

            @type  addr: DWORD
            @param addr: Address of a beginning of the Page

            @rtype:  Page OBJECT
            @return: Memory Page
            """
        pass

    def getMemoryPageByOwner(self, owner):
        """
            Get the Memory Pages belonging to the given dll.

            @type  owner: STRING
            @param owner: Name of the dll

            @rtype:  LIST
            @return: LIST of Memory Pages belonging to the given dll
            """
        pass

    def getMemoryPageByOwnerAddress(self, owner_addr):
        """
            Get the Memory Pages belonging to the given dll by its base address.

            @type  owner: STRING
            @param owner: Name of the dll

            @rtype:  LIST
            @return: LIST of Memory Pages belonging to the given dll
            """
        pass

    def getMemoryPageByAddress(self, address):
        """
            Get a memory page.

            @type  address: DWORD
            @param address: Address in the range of the Page

            @rtype:  Page OBJECT
            @return: Memory Page
            """
        pass

    def getMemoryPages(self):
        """
            Get All memory pages.

            @rtype:  DICTIONARY
            @return: List of all memory pages
            """
        pass

    def vmQuery(self,address):
        """
            Query Memory Page

            @type  address: DWORD
            @param address: Base Address of memory page

            @rtype:  Python List
            @return: List with memory page structure
            """
        pass

    def getAllHandles(self):
        """
            Get all handles.

            @rtype:  DICTIONARY
            @return: All the process handles
            """
        pass

    def getAllThreads(self):
        """
            Get all threads.
            @rtype: LIST
            @return: All process threads
            """
        pass

    def getAllSymbols(self):
        """
            Get All Symbols.

            @rtype:  DICTIONARY
            @return: All the symbols of the process
            """
        pass

    def getAllSymbolsFromModule(self,address):
        """
            Get Symbols from module.
            @type  Address: DWORD
            @param Address: Address from module.

            @rtype:  DICTIONARY
            @return: All the symbols of the module
            """
        pass

    def callStack(self):
        """
            Get a Back Trace (Call stack).

            @rtype:  LIST of Stack OBJECT
            @return: list of all the stack trace
            """
        pass

    def getCallTree(self,address=0):
        """
            Get the call tree of given address.
            @rtype: LIST of Call tuples
            @return: list of all the call tree
            ulong          line;                 // Line number in column
            ulong          dummy;                // Must be 1
            ulong          type;                 // Type, set of TY_xxx
            ulong          entry;                // Address of function
            ulong          from;                 // Address of calling instruction
            ulong          calls;                // Address of called subfunction
            """
        pass

    def findModule(self, address):
        """
            Find which module an address belongs to.

            @type  address: DWORD
            @param address: Address

            @rtype: LIST
            @return: Tuple of module information (name, base address)

            """
        pass

    def findModuleByName(self, modname):
        """
            Find a module by name (case insensitive).

            @type  modname: STRING
            @param modname: Module Name

            @rtype: OBJECT|BOOLEAN
            @return: a Module object matching the given name or False if it's not found or name is ambiguous

            """
        pass

    def getHeapsAddress(self):
        """
            Get a the process heaps

            @rtype: LIST of DWORD
            @return: List of Heap Address
            """
        pass

    def getAddressOfExpression(self, expression):
        """
            Get the address from an expression as ntdll.RtlAllocateHeap

            @type  expression: STRING
            @param expression: Expression to translate into an address

            @rtype:  DWORD
            @return: Address of the Expression
            """
        pass

    def getAddress(self, expression):
        """
            Get the address from an expression as ntdll.RtlAllocateHeap

            @type  expression: STRING
            @param expression: Expression to translate into an address

            @rtype:  DWORD
            @return: Address of the Expression

            """
        pass

### Displaying information ###
# Error, Log, Creating new windows, etc

    def error(self, msg):
        """
            This function shows an Error dialog with a custom message.

            @type  msg: STRING
            @param msg: Message
            """
        pass

    def openTextFile(self,path=""):
        """
            Opens text file in MDI windows. ( if no path is specified browsefile dialog will pop up )

            @type:  STRING
            @param: (Optional, Def= "") Path to file
            """
        pass

    def setStatusBar(self, msg):
        """
            Sets the status bar message.

            @type  msg: STRING
            @param msg: Message
            """
        pass

    def clearStatusBar(self):
        """
            Removes the current status bar message.
            """
        pass

    def logLines(self, data, address = 0, highlight = False, gray = False , focus = 0):
        """
            Adds multiple lines of ASCII text to the log window.

            @type  msg: LIST of STRING
            @param msg: List of Message to add (max size of msg is 255 bytes)

            @type  address: DWORD
            @param address: Address associated with the message

            @type  highlight: BOOLEAN
            @param highlight: Set highlight text

            @type  gray: BOOLEAN
            @param gray: Set gray text
            """
        pass

    def log(self, msg, address = 0xbadf00d ,highlight = False, gray = False , focus = 0):
        """
            Adds a single line of ASCII text to the log window.

            @type  msg: STRING
            @param msg: Message (max size is 255 bytes)

            @type  address: DWORD
            @param address: Address associated with the message

            @type  highlight: BOOLEAN
            @param highlight: Set highlight text

            @type  gray: BOOLEAN
            @param gray: Set gray text
            """
        pass

    def updateLog(self):
        """
            Forces an immediate update of the log window.
            """
        pass

    def createLogWindow(self):
        """
            Creates or restores the log window.
            """
        pass

    def createWindow(self, title, col_titles):
        """
            Creates a custom window.

            @type  title: STRING
            @param title: Window title

            @type  col_titles: LIST OF STRING
            @param col_titles: Column titles list

            @return HWND: Handler of created table
            """
        pass

    def createTable(self,title,col_titles):
        """
            Creates a custom window.

            @type  title: STRING
            @param title: Window title

            @type  col_titles: LIST OF STRING
            @param col_titles: Column titles list
            """
        pass

    def setFocus(self,handler):
        """
            Set focus on window.

            @type handler: ULONG
            @param handler: Windows Handler

            @return phandler: Handle to the window that previously had the focus.
            """
        pass

    def isValidHandle(self,handler):
        """
            Does a window still exist?

            @type handler: ULONG
            @param handler: Windows to check handle

            @return: INT : 1 Exists, 0 Doesnt exist
            """
        pass

    def setStatusBarAndLog(self, addr, msg):
        """
            Sets and logs a status bar message.

            @type  addr: DWORD
            @param addr: Address related with the message

            @type  msg: STRING
            @param msg: Message
            """
        pass

    def flashMessage(self, msg):
        """
            Flashes a message at status bar.

            @type  msg: STRING
            @param msg: Message
            """
        pass

    def setProgressBar(self, message, promille=100):
        """
            Displays a progress bar which can contain formatted text and a progress percentage.
            If the formatted text contains a dollar sign ('$') it will be replaced by the current progress percentage.

            @type  msg: STRING
            @param msg: Message

            @type  promille: DWORD
            @param promille: Progress. At 0 the progress bar is closed and the previous message restored.
            """
        pass

    def closeProgressBar(self):
        """
            Close Progress Bar.
            """
        pass

    def getComment(self, address,type=0xFD):
        """
            Get the comment of the opcode line.

            @type  address: DWORD
            @param address: Address of the requested comment

            @rtype:  STRING
            @return: Requested comment
            """
        pass

    #If you are unsure about what kind of comment are you looking for,
    #dont use this methods, and go for the automatic one "getComment(address)"

    def getUserComment(self,address):
        pass

    def getArgumentsComment(self,address):
        pass

    def getAnalyseComment(self,address):
        pass

    def getLibraryComment(self,address):
        pass

    def setComment(self, address, comment):
        """
            Set a comment.

            @type  address: DWORD
            @param address: Address of the Comment

            @type  comment: STRING
            @param comment: Comment to add
            """
        pass

    def setLabel(self, address, label):
        """
            Set a label.

            @type  adresss: DWORD
            @param address: Address to the new label

            @type  label: STRING
            @param label: Label to add
            """
        pass

    def markBegin(self):
        """
            Place a start mark for timming your script
            """
        pass

    def markEnd(self):
        """
            Place an End mark for timming your script

            @rtype  time: DWORD
            @return time: time in seconds
            """
        pass

    def findDependecies(self, lookfor):
        """
            Find exported function on the loaded dlls.

            @type  lookfor: TABLE of DWORD
            @param lookfor: Table of functions to search

            @rtype: DICTIONARY
            @return: Dictionary
            """
        #lookfor = ["rpcrt4.rpcserveruseprotseq","rpcrt4.rpcserveruseprotseqex","rpcrt4.rpcserveruseprotseqw", "rpcrt4.rpcserveruseprotseqEp", "rpcrt4.rpcserveruseprotseqif",\
        #           "rpcrt4.rpcserveruseallprotseqs", "rpcrt4.rpcserveruseallprotseqsif", "rpcrt4.rpcserveruseprotseqepw",\
        #           "rpcrt4.rpcserveruseprotseqepexw", "rpcrt4.rpcserveruseallprotseqsifw"]
        pass

    def isVmWare(self):
        """
            Check if debugger is running under a vmware machine

            @rtype:  DWORD
            @return: 1 if vmware machine exists
            """
        pass

    ### Breakpoint Functions ###
    # All kind of breakpoint functions

    # For manual breakpoints:
    #     key     shiftkey                Action
    #    VK_F2   0                       Toggle unconditional breakpoint
    #    VK_F2   Pressed (not 0)         Set conditional breakpoint
    #    VK_F4   Pressed (not 0)         Set logging breakpoint

    def manualBreakpoint(self, address, key, shiftkey, font):
        """
            Set a Manual Breakpoint.

            @type  address: DWORD
            @param address: Address of the breakpoint

            @type  key: DWORD
            @param key: VK_F2 (Conditional Breakpoint) or VK_F4 (Logging Breakpoint)

            @type  shiftkey: DWORD
            @param shiftkey: State of the shiftkey

            @type  font: STRING
            @param font: See ImmFonts
            """
        pass

    def setUnconditionalBreakpoint(self, address, font="fixed"):
        """
            Set an Unconditional Breakpoint.

            @type  address: DWORD
            @param address: Address for the breakpoint

            @type  font: STRING
            @param font: (Optional, Def: fixed) Font for the breakpoint
            """
        pass

    def setConditionalBreakpoint(self, address, font="fixed"):
        """
            Set a Conditional Breakpoint.

            @type  address: DWORD
            @param address: Address for the breakpoint

            @type  font: STRING
            @param font: (Optional, Def: fixed) Font for the breakpoint
            """
        pass

    def setLoggingBreakpoint(self, address):
        """
            Set a Logging Breakpoint. (This breakpoint will not puase the execution, it will just act as a Watch point"

            @type  address: DWORD
            @param address: Address for the breakpoint
            """
        pass

    def setWatchPoint(self,address):
        """
            Set a watching Breakpoint.

            @type  address: DWORD
            @param address: Address for the watchpoint
            """
        pass

#define    TY_SET         0x00000100      // Code INT3 is in memory
#define    TY_ACTIVE      0x00000200      // Permanent breakpoint
#define    TY_DISABLED    0x00000400      // Permanent disabled breakpoint
#define    TY_ONESHOT     0x00000800      // Temporary stop
#define    TY_TEMP        0x00001000      // Temporary breakpoint
#define    TY_KEEPCODE    0x00002000      // Set and keep command code
#define    TY_KEEPCOND    0x00004000      // Keep condition unchanged (0: remove)
#define    TY_NOUPDATE    0x00008000      // Don't redraw breakpoint window
#define    TY_RTRACE      0x00010000      // Pseudotype of run trace breakpoint

    def setTemporaryBreakpoint(self, address, continue_execution = False, stoptrace = False):
        """
            Set a Temporary Breakpoint.

            @type  address: DWORD
            @param address: Address for the breakpoint

            @type  continue_execution: BOOLEAN
            @param continue_execution: Automatically removes temporary breakpoint when hit and continue execution

            @type  stoptrace: BOOLEAN
            @param stoptrace: Stop any kind of trace or animation when hit
            """
        pass

    def setBreakpoint(self, address):
        """
            Set a Breakpoint.

            @type  address: DWORD
            @param address: Address for the breakpoint
            """
        pass

    def setBreakpointOnName(self,name):
        """
            Set a Breakpoint.

            @type  Name: STRING
            @param Name: name of the function to bp

            @rtype:  DWORD
            @return: Address of name
            """
        pass

    def disableBreakpoint(self, address):
        """
            Disable Breakpoint.

            @type  address: DWORD
            @param address: Address for the breakpoint
            """
        pass

    def deleteBreakpoint(self,address,address2=0):
        """
            Delete Breakpoint.

            @type address: DWORD
            @param address: Start range of addresses to delete breakpoints
            @type address2: DWORD
            @param Address: End range of addresses to delete breakpoints
            """
        pass

    def getBreakpointType(self, address):
        """
            Get the Breakpoint type.

            @type  address: DWORD
            @param address: Address for the breakpoint

            @rtype: STRING
            @return: Breakpoint type
            """
        pass

    def setMemBreakpoint(self,addr, type, size=4):
        """
            Modifies or removes a memory breakpoint.

            @type  address: DWORD
            @param address: Address for the breakpoint

            @type  type: DWORD
            @param type: Type of Memory Breakpoint (READ/WRITE/SFX)

            @type  size: DWORD
            @param size: (Optional, Def: 4) Size of Memory Breakpoint
            """
        pass

    def disableMemBreakpoint(self, addr):
        """
            Disable Memory Breakpoint.
            """
        pass

    def setHardwareBreakpoint(self,addr,type=HB_CODE,size=1):
        """
            Sets Hardware breakpoint
            """
        pass

    ### Read/Write/Search ###
    # Read/Write from process memory

    def writeLong(self, address, dword):
        """
            Write long to memory address.

            @type  address: DWORD
            @param address: Address

            @type  dword: DWORD
            @param dword: long to write
            """
        pass

    def writeMemory(self, address, buf):
        """
            Write buffer to memory address.

            @type  address: DWORD
            @param address: Address

            @type  buf: BUFFER
            @param buf: Buffer
            """
        pass

    def readMemory(self, address, size):
        """
            Read block of memory.

            @type  address: DWORD
            @param address: Address

            @type  size: DWORD
            @param size: Size

            @rtype:  BUFFER
            @return: Process memory
            """
        pass

    def readLong(self, address):
        """
            Read a Long from the debugged process

            @type  address: DWORD
            @param address: Address

            @rtype:  DWORD
            @return: Long
            """
        pass

    def readString(self, address):
        """
            Read a string from the remote process

            @type  address: DWORD
            @param address: Address of the string

            @rtype:  String
            @return: String
            """
        pass

    def readWString(self,address):
        """
            Read a unicode string from the remote process

            @type  address: DWORD
            @param address: Address of the unicode string

            @rtype:  Unicode String
            @return: Unicode String
            """
        pass

    def readUntil(self, address, ending):
        """
            Read string until ending starting at given address

            @param Address: Start address
            @return Readed String
            """
        pass

    def readShort(self, address):
        """
            Read a short integer from the remote process

            @type  address: DWORD
            @param address: Address of the short

            @rtype:  Short Integer
            @return: Short
            """
        pass

    def searchShort(self, short , flag=None):
        """
            Search a short integer on the remote process memory

            @type  short: SHORT
            @param short: Short integer to search for

            @type flag: STRING
            @param flag: Memory Protection String Flag

            @rtype:  List
            @return: List of address of the short integer founded
            """
        pass

    def searchLong(self, long, flag=None):
        """
            Search a short integer on the remote process memory

            @type  long: DWORD
            @param long: integer to search for
            @type flag: STRING
            @param flag: Memory Protection String Flag

            @rtype:  List
            @return: List of address of the integer founded
            """
        pass

    def searchOnExecute(self,buf):
        """
            Search string in executable memory.

            @param buf: Buffer to search for
            @return: A list of address where the string was found on memory
            """
        pass

    def searchOnWrite(self,buf):
        """
            Search string in writable memory.

            @param buf: Buffer to search for
            @return: A list of address where the string was found on memory
            """
        pass

    def searchOnRead(self,buf):
        """
            Search string in readable memory.

            @param buf: Buffer to search for
            @return: A list of address where the string was found on memory
            """
        pass

    def search( self, buf, flag = None ):
        pass

    def oldSearch(self, buf,flag=None):
        """
            Search string in memory.

            @param buf: Buffer to search for
            @param flag: Memory Protection String Flag
            @return: A list of address where the string was found on memory
            """
        pass

    def searchCommands(self, cmd):
        """
            Search for a sequence of commands in all executable modules loaded.

            @type  cmd: STRING
            @param cmd: Assembly code to search for (Search using regexp is available. See Documentation)

            @rtype:  List
            @return: List of address of the command found

            NOTE: Since ImmunityDebugger 1.2 , the returning tuple[1] value is deprecated,
            if you need the opcode string of the resulted address, you'll have to do a immlib.disasm(tuple[0]).
            """
        pass

    def searchCommandsOnModule(self,address,cmd):
        """
            Search for a sequence of commands in given executable module.

            @type  cmd: STRING
            @param cmd: Assembly code to search for (Search using regexp is available. See Documentation)

            @rtype:  List
            @return: List of address of the command found

            NOTE: Since ImmunityDebugger 1.2 , the returning tuple[1] value is deprecated,
            if you need the opcode string of the resulted address, you'll have to do a immlib.disasm(tuple[0]).
            """
        pass

    ### Execution control ###
    # All kind of functions that interact with code execution

    def run(self, address=0):
        """
            Run Process untill address.

            @param address: Address
            """
        pass

    def runTillRet(self):
        """
            Run Process till ret.
            """
        pass

    def pause(self):
        """Pause process"""
        pass

    def stepOver(self, address=0):
        """
            Step-Over Process untill address.

            @type  address: DWORD
            @param address: (Optional, Def = 0) Address
            """
        pass

    def stepIn(self, address=0):
        """
            Step-in Process untill address.

            @type  address: DWORD
            @param address: (Optional, Def = 0) Address
            """
        pass

    def quitDebugger(self):
        """
            Quits debugger
            """
        pass

    def ignoreSingleStep(self,flag="CONTINUE"):
        """
            Ignore Single Step events

            @type flag: STRING
            @param flag: How to continue after a single event is catched
            flag = DISABLE : Disable ignoring
            flag = FORCE : Conventional Force continue method
            flag = CONTINUE : Transparent continue method

            CAUTION: This method overrides GUI option 'single-step break'
            """
        pass

    #Consider the following three methods of experimental nature.
    def openProcess(self, path,mode=0):
        """
            Open process for debugging

            @type path: STRING
            @param path: Path to file to debug
            @type mode: INTEGER
            @param mode: How to start: -2 SILENT, 0 NORMAL
            """
        pass

    def restartProcess(self,mode=-1):
        """
            Restart debuggee

            @type mode: INTEGER
            @param mode: How to restart : -2 SILENT, -1 MSGBOX
            """
        pass

    def Attach(self, pid):
        """
            Attach to an active process

            @type pid: INTEGER
            @param pid: Process Id.
            """
        pass

    def Detach(self):
        """
            Detach from active process

            """
        #this methos is still very experimental
        pass

    def prepareForNewProcess(self):
        """
            Prepare Debugger for fresh debugging session

            NOTE: be sure to know what you are doing when
            calling this method
            """
        pass

    ### GUI interaction ###
    # Whatever interaction on the gui

    def goSilent(self,silent):
        """
            Set/Unset silent debugging flag

            @type silent: INTEGER
            @param silent: 1 to set silent, 0 to unset
            """
        pass

    def addHeader(self,address,header,color="Black"):
        """
            Add a header to given row.

            @type address: DWORD
            @param address: Address to add the header into
            @type header: STRING
            @param header: Header string to add into row
            @type color: STRING
            @param color: Color of text
            """
        pass

    def removeHeader(self,address):
        """
            Removes header from row.

            @type address: DWORD
            @param address: Address to remove the header from
            """
        pass

    def removeLine(self,address):
        """
            Removes header from row.
            @type address: DWORD
            @param address: Address to remove the header from
            """
        pass

    def getHeader(self,address):
        """
            Get Header from row.
            @type address: DWORD
            @param address: Address to get the headers from
            @return PYLIST: List of strings
            """
        pass

    def addLine(self,address,header,color="Black"):
        """
            Add a line to cpu window.
            @type address: DWORD
            @param address: Address to add line
            @type header: STRING
            @param header: Header string to add into row
            @type color: STRING
            @param color: Color of text
            """
        pass

    def gotoDisasmWindow(self, addr):
        """
            GoTo the Disassembler Window.

            @type  addr: DWORD
            @param addr: Address to show on the Disassembler Window
            """
        pass

    def gotoDumpWindow(self, addr):
        """
            GoTo Dump Window.

            @type  addr: DWORD
            @param addr: Address to show on the Dump Window
            """
        pass

    def gotoStackWindow(self, addr):
        """
            GoTo the Stack Window.
            @type  addr: DWORD
            @param addr: Address to show on the Stack Window
            """
        pass

    def inputBox(self,title):
        """
            Creates Dialog with an input_box.

            @type  title: STRING
            @param title: Title for the input_box dialog

            @return: String from the inputbox
            """
        pass

    def comboBox(self,title,combolist):
        """
            Creates Dialog with a combo_box.

            @type  title: STRING
            @param title: Title for the dialog

            @type  combolist: LIST
            @param combolist: List of items to add to combo dialog

            @return: Selected item
            """
        pass

    ### Debugger State ###
    # The state of the debugger

    def getStatus(self):
        """
            Get the status of the debugged process.

            @return: Status of the debugged process
            """
        pass

    def isStopped(self):
        """
            Is the debugged process stopped?

            @rtype:  BOOL
            @return: Boolean (True/False)
            """
        pass

    def isEvent(self):
        """
            Is the debugged process in an event state?

            @rtype:  BOOL
            @return: Boolean (True/False)
            """
        pass

    def isRunning(self):
        """
            Is the debugged process running?

            @rtype:  BOOL
            @return: Boolean (True/False)
            """
        pass

    def isFinished(self):
        """
            Is the debugged process finished?

            @rtype:  BOOL
            @return: Boolean (True/False)
            """
        pass

    def isClosing(self):
        """
            Is the debugged process closed?

            @rtype:  BOOL
            @return: Boolean (True/False)
            """
        pass

    def listHooks(self):
        """
            List of active hooks

            @rtype: LIST
            @return: List of active hooks
            """
        pass

    def removeHook(self,hook_str):
        """
            Unhook from memory
            """
        pass

    # afterHookAddr = hookAddr + idx
    # ndx = function num
    # table = [ (reg), (reg, offset) ]
    def _createCodeforHook( self, memAddress, afterHookAddr, ndx, table, execute_prelude, alloc_size):
        pass

    def addFastLogHook(self,  hook, alloc_size = 0x100000):
        pass

    ### Remote Allocation/Deallocation ###

    def rVirtualAlloc(self, lpAddress, dwSize, flAllocationType, flProtect):
        """
            Virtual Allocation on the Debugged Process

            @type  lpAddress: DWORD
            @param lpAddress: Desired starting Address

            @type  dwSize: DWORD
            @param dwSize: Size of the memory to be allocated (in bytes)

            @type  flAllocationType: DWORD
            @param flAllocationType: Type of Memory Allocation (MEM_COMMIT, MEM_RESERVED, MEM_RESET, etc)

            @type  flProtect: DWORD
            @param flProtect: Flag protection of the memory allocated

            @rtype:  DWORD
            @return: Address of the memory allocated
            """
        pass

    # default dwFreetype == MEM_RELEASE
    def rVirtualFree(self, lpAddress, dwSize = 0x0, dwFreeType = 0x8000):
        """
            Virtual Free of memory on the Debugged Process

            @type  size: DWORD
            @param size: (Optional, Def: 0) Size of the memory to free

            @type  dwFreeType: DWORD
            @param dwFreeType: (Optional, Def: MEM_RELEASE) Type of Free operation

            @rtype:  DWORD
            @return: On Successful, returns a non zero value
            """
        pass

    def remoteVirtualAlloc(self, size = 0x10000, interactive = True):
        """
            Virtual Allocation on the Debugged Process

            @type  size: DWORD
            @param size: (Optional, Def: 0x10000) Size of the memory to allocated, in bytes

            @rtype:  DWORD
            @return: Address of the memory allocated
            """
        pass

    ### OS information ###

    def getOsVersion(self):
        pass

    def getOsRelease(self):
        pass

    def getOsInformation(self):
        """
            Get OS information

            @rtype: TUPLE
            @return: List with ( system, release, version)
            """
        pass

    def getThreadId(self):
        """
            Return current debuggee thread id

            @trype: LONG
            @return: Thread ID
            """
        pass

    ### Accessing Recognition Routines ###

    def searchFunctionByName(self, name, heuristic = 90, module = None, version = None, data=""):
        """
            Look up into our dictionaries to find a function match.

            @type  name: STRING
            @param name: Name of the function to search

            @type  module: STRING
            @param module: name of a module to restrict the search

            @type  version: STRING
            @param version: restrict the search to the given version

            @type  heuristic: INTEGER
            @param heuristic: heuristic threasold to consider a real function match

            @type  data: STRING|LIST
            @param data: Name (or list of names) of the .dat file inside the Data folder, where're stored the function
            patterns. Use an empty string to use all the files in the Data folder.

            @rtype: DWORD|None
            @return: the address of the function or None if we can't find it
            """
        pass

    def searchFunctionByHeuristic(self, csvline, heuristic = 90, module = None, data=""):
        """
            Search memory to find a function that fullfit the options.

            @type  csvline: STRING
            @param csvline: A line of a Data CSV file. This's a simple support for copy 'n paste from a CSV file.

            @type  heuristic: INTEGER
            @param heuristic: heuristic threasold to consider a real function match

            @type  module: STRING
            @param module: name of a module to restrict the search

            @type  data: STRING|LIST
            @param data: Name (or list of names) of the .dat file inside the Data folder, where're stored the function
            patterns. Use an empty string to use all the files in the Data folder.

            @rtype: DWORD|None
            @return: the address of the function or None if we can't find it
            """
        pass

    def resolvFunctionByAddress(self, address, heuristic=90,data=""):
        """
            Look up into our dictionaries to find a function match.

            @type  address: DWORD
            @param address: Address of the function to search

            @type  heuristic: INTEGER
            @param heuristic: heuristic threasold to consider a real function match

            @type  data: STRING|LIST
            @param data: Name (or list of names) of the .dat file inside the Data folder, where're stored the function
            patterns. Use an empty string to use all the files in the Data folder.

            @rtype: STRING
            @return: a STRING with the function's real name or the given address if there's no match
            """
        pass

    def makeFunctionHashHeuristic(self, address, compressed = False, followCalls = True, data=""):
        """
            @type  address: DWORD
            @param address: address of the function to hash

            @type  compressed: Boolean
            @param compressed: return a compressed base64 representation or the raw data

            @type  followCalls: Boolean
            @param followCalls: follow the first call in a single basic block function

            @type  data: STRING|LIST
            @param data: Name (or list of names) of the .dat file inside the Data folder, where're stored the function
            patterns. Use an empty string to use all the files in the Data folder.

            @rtype: LIST
            @return: the first element is described below and the second is the result of this same function but over the first
            call of a single basic block function (if applies), each element is like this:
            a base64 representation of the compressed version of each bb hash:
            [4 bytes BB(i) start][4 bytes BB(i) 1st edge][4 bytes BB(i) 2nd edge]
            0 <= i < BB count
            or the same but like a LIST with raw data.
            """
        pass

    def makeFunctionHashExact(self, address,data=""):
        """
            Return a SHA-1 hash of the function, taking the raw bytes as data.

            @type  address: DWORD
            @param address: address of the function to hash

            @type  data: STRING|LIST
            @param data: Name (or list of names) of the .dat file inside the Data folder, where're stored the function
            patterns. Use an empty string to use all the files in the Data folder.

            @rtype: STRING
            @return: SHA-1 hash of the function
            """
        pass

    def makeFunctionHash(self, address, compressed = False,data=""):
        """
            Return a list with the best BB to use for a search and the heuristic hash
            of the function. This two components are the function hash.

            @type  address: DWORD
            @param address: address of the function to hash

            @type  compressed: Boolean
            @param compressed: return a compressed base64 representation or the raw data

            @type  data: STRING|LIST
            @param data: Name (or list of names) of the .dat file inside the Data folder, where're stored the function
            patterns. Use an empty string to use all the files in the Data folder.

            @rtype: LIST
            @return: 1st element is the generalized instructions to use with searchCommand
            2nd element is the heuristic function hash (makeFunctionHashHeuristic)
            3rd element is an exact hash of the function (makeFunctionHashExact)
            """
        pass

    ### Accessing Control Flow Analysis Routines ###

    def findLoops(self, address):
        """
            This function finds Natural Loops inside a function.

            Each loop item has the following structure:
              [ start, end, nodes ]
              start: address of node receiving the back edge.
              end: address of node which has the back edge.
              node: list of node's addresses involved in this loop.

            @type  address: DWORD
            @param address: function start address

            @rtype: LIST
            @return: A list of loops
            """
        pass

    def sleepTillStopped(self, timeout):
        """
            timeout is in seconds. this function will sleep 1 second at a time until timeout is reached
            or the debugger has stopped (probably due to AV)
            returns True if we were stopped before timeout happened
            """
        pass

    def injectDll( self, dll_path ):
        """
            This function loads a DLL into the debugged process.

            @type  dll_path: STRING
            @param dll_path: The full path to the DLL. ie C:\\WINDOWS\\system32\\kernel32.dll

            @rtype: DWORD
            @return: The thread ID of the DLL loading thread.
            """
        pass

