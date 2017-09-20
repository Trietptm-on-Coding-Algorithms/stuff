# -*- coding: utf-8 -*-

"""
    win32 def
"""

import ctypes
from ctypes import Union, Structure
from ctypes.wintypes import BOOL, BYTE, WORD, DWORD, LONG, LPVOID, POINTER, HANDLE
SIZE_T = ctypes.wintypes.c_size_t
CHAR = ctypes.wintypes.c_char
WCHAR = ctypes.wintypes.c_wchar

#
# manually declare entities from Tlhelp32.h since i was unable to import using h2xml.py.
#

TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPMODULE = 0x00000008
TH32CS_INHERIT = 0x80000000
TH32CS_SNAPALL = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)


class THREADENTRY32(Structure):
    """
    typedef struct tagTHREADENTRY32 {
      DWORD dwSize;
      DWORD cntUsage;
      DWORD th32ThreadID;
      DWORD th32OwnerProcessID;
      LONG tpBasePri;
      LONG tpDeltaPri;
      DWORD dwFlags;
    } THREADENTRY32,  *PTHREADENTRY32;
    """
    _pack_ = 1
    _fields_ = [
        ('dwSize', DWORD),
        ('cntUsage', DWORD),
        ('th32ThreadID', DWORD),
        ('th32OwnerProcessID', DWORD),
        ('tpBasePri', DWORD),
        ('tpDeltaPri', DWORD),
        ('dwFlags', DWORD),
    ]


class PROCESSENTRY32W(Structure):
    """
    typedef struct tagPROCESSENTRY32 {
       DWORD dwSize;
       DWORD cntUsage;
       DWORD th32ProcessID;
       ULONG_PTR th32DefaultHeapID;
       DWORD th32ModuleID;
       DWORD cntThreads;
       DWORD th32ParentProcessID;
       LONG pcPriClassBase;
       DWORD dwFlags;
       TCHAR szExeFile[MAX_PATH];
    } PROCESSENTRY32,  *PPROCESSENTRY32;
    """
    # _pack_ = 1
    _fields_ = [
        ('dwSize', DWORD),
        ('cntUsage', DWORD),
        ('th32ProcessID', DWORD),
        ('th32DefaultHeapID', DWORD),
        ('th32ModuleID', DWORD),
        ('cntThreads', DWORD),
        ('th32ParentProcessID', DWORD),
        ('pcPriClassBase', LONG),
        ('dwFlags', DWORD),
        ('szExeFile', WCHAR * 260),
    ]


class MODULEENTRY32(Structure):
    """
    typedef struct tagMODULEENTRY32 {
      DWORD dwSize;
      DWORD th32ModuleID;
      DWORD th32ProcessID;
      DWORD GlblcntUsage;
      DWORD ProccntUsage;
      BYTE* modBaseAddr;
      DWORD modBaseSize;
      HMODULE hModule;
      TCHAR szModule[MAX_MODULE_NAME32 + 1];
      TCHAR szExePath[MAX_PATH];
    } MODULEENTRY32,  *PMODULEENTRY32;
    """
    _pack_ = 1
    _fields_ = [
        ("dwSize", DWORD),
        ("th32ModuleID", DWORD),
        ("th32ProcessID", DWORD),
        ("GlblcntUsage", DWORD),
        ("ProccntUsage", DWORD),
        ("modBaseAddr", DWORD),
        ("modBaseSize", DWORD),
        ("hModule", DWORD),
        ("szModule", CHAR * 256),
        ("szExePath", CHAR * 260),
    ]


# ---------------------------------------------------------------------------
# SYSTEM_INFO


class _SYSTEM_INFO_OEM_ID_STRUCT(Structure):
    _pack_ = 1
    _fields_ = [
        ("wProcessorArchitecture", WORD),
        ("wReserved", WORD),
    ]


class _SYSTEM_INFO_OEM_ID(Union):
    _fields_ = [
        ("dwOemId", DWORD),
        ("w", _SYSTEM_INFO_OEM_ID_STRUCT),
    ]


class SYSTEM_INFO(Structure):
    """
    typedef struct _SYSTEM_INFO {
      union {
        DWORD  dwOemId;
        struct {
          WORD wProcessorArchitecture;
          WORD wReserved;
        };
      };
      DWORD     dwPageSize;
      LPVOID    lpMinimumApplicationAddress;
      LPVOID    lpMaximumApplicationAddress;
      DWORD_PTR dwActiveProcessorMask;
      DWORD     dwNumberOfProcessors;
      DWORD     dwProcessorType;
      DWORD     dwAllocationGranularity;
      WORD      wProcessorLevel;
      WORD      wProcessorRevision;
    } SYSTEM_INFO;
    """
    _pack_ = 1
    _fields_ = [
        ("id", _SYSTEM_INFO_OEM_ID),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", LPVOID),
        ("lpMaximumApplicationAddress", LPVOID),
        ("dwActiveProcessorMask", POINTER(DWORD)),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
    ]

    def __get_dwOemId(self):
        return self.id.dwOemId

    def __set_dwOemId(self, value):
        self.id.dwOemId = value
    dwOemId = property(__get_dwOemId, __set_dwOemId)

    def __get_wProcessorArchitecture(self):
        return self.id.w.wProcessorArchitecture

    def __set_wProcessorArchitecture(self, value):
        self.id.w.wProcessorArchitecture = value
    wProcessorArchitecture = property(__get_wProcessorArchitecture, __set_wProcessorArchitecture)


# ---------------------------------------------------------------------------
# CONTEXT


class FLOATING_SAVE_AREA(Structure):
    """
    typedef struct _FLOATING_SAVE_AREA {
        DWORD   ControlWord;
        DWORD   StatusWord;
        DWORD   TagWord;
        DWORD   ErrorOffset;
        DWORD   ErrorSelector;
        DWORD   DataOffset;
        DWORD   DataSelector;
        BYTE    RegisterArea[SIZE_OF_80387_REGISTERS];
        DWORD   Cr0NpxState;
    } FLOATING_SAVE_AREA;
    """
    _pack_ = 1
    _fields_ = [
        ('ControlWord', DWORD),
        ('StatusWord', DWORD),
        ('TagWord', DWORD),
        ('ErrorOffset', DWORD),
        ('ErrorSelector', DWORD),
        ('DataOffset', DWORD),
        ('DataSelector', DWORD),
        ('RegisterArea', BYTE * 80),
        ('Cr0NpxState', DWORD),
    ]


class CONTEXT(Structure):
    """
    typedef struct _CONTEXT {
        DWORD ContextFlags;
        DWORD   Dr0;
        DWORD   Dr1;
        DWORD   Dr2;
        DWORD   Dr3;
        DWORD   Dr6;
        DWORD   Dr7;
        FLOATING_SAVE_AREA FloatSave;
        DWORD   SegGs;
        DWORD   SegFs;
        DWORD   SegEs;
        DWORD   SegDs;
        DWORD   Edi;
        DWORD   Esi;
        DWORD   Ebx;
        DWORD   Edx;
        DWORD   Ecx;
        DWORD   Eax;
        DWORD   Ebp;
        DWORD   Eip;
        DWORD   SegCs;
        DWORD   EFlags;
        DWORD   Esp;
        DWORD   SegSs;
        BYTE    ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
    } CONTEXT;
    """
    _pack_ = 1
    _fields_ = [
        ('ContextFlags', DWORD),
        ('Dr0', DWORD),
        ('Dr1', DWORD),
        ('Dr2', DWORD),
        ('Dr3', DWORD),
        ('Dr6', DWORD),
        ('Dr7', DWORD),
        ('FloatSave', FLOATING_SAVE_AREA),
        ('SegGs', DWORD),
        ('SegFs', DWORD),
        ('SegEs', DWORD),
        ('SegDs', DWORD),
        ('Edi', DWORD),
        ('Esi', DWORD),
        ('Ebx', DWORD),
        ('Edx', DWORD),
        ('Ecx', DWORD),
        ('Eax', DWORD),
        ('Ebp', DWORD),
        ('Eip', DWORD),
        ('SegCs', DWORD),         # MUST BE SANITIZED
        ('EFlags', DWORD),         # MUST BE SANITIZED
        ('Esp', DWORD),
        ('SegSs', DWORD),
        ('ExtendedRegisters', BYTE * 512),
    ]
    _ctx_debug = ('Dr0', 'Dr1', 'Dr2', 'Dr3', 'Dr6', 'Dr7')
    _ctx_segs = ('SegGs', 'SegFs', 'SegEs', 'SegDs', )
    _ctx_int = ('Edi', 'Esi', 'Ebx', 'Edx', 'Ecx', 'Eax')
    _ctx_ctrl = ('Ebp', 'Eip', 'SegCs', 'EFlags', 'Esp', 'SegSs')


# ---------------------------------------------------------------------------
# TIME


class FILETIME(Structure):
    _pack_ = 1
    _fields_ = [
        ('dwLowDateTime', DWORD),
        ('dwHighDateTime', DWORD)
    ]

    def uint64(self):
        return self.dwHighDateTime << 32 | self.dwLowDateTime


class SYSTEMTIME(Structure):
    _pack_ = 1
    _fields_ = [
        ('wYear', WORD),
        ('wMonth', WORD),
        ('wDayOfWeek', WORD),
        ('wDay', WORD),
        ('wHour', WORD),
        ('wMinute', WORD),
        ('wSecond', WORD),
        ('wMilliseconds', WORD)
    ]

    def __str__(self):
        return "%04d.%02d.%02d.%02d.%02d.%02d.%03d" % (self.wYear, self.wMonth, self.wDay, self.wHour, self.wMinute, self.wSecond, self.wMilliseconds)


# ---------------------------------------------------------------------------
# MISC


class MEMORY_BASIC_INFORMATION(Structure):
    """
    typedef struct _MEMORY_BASIC_INFORMATION {
        PVOID BaseAddress;
        PVOID AllocationBase;
        DWORD AllocationProtect;
        SIZE_T RegionSize;
        DWORD State;
        DWORD Protect;
        DWORD Type;
    } MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
    """
    _pack_ = 1
    _fields_ = [
        ('BaseAddress', SIZE_T),    # remote pointer
        ('AllocationBase', SIZE_T),    # remote pointer
        ('AllocationProtect', DWORD),
        ('RegionSize', SIZE_T),
        ('State', DWORD),
        ('Protect', DWORD),
        ('Type', DWORD),
    ]


class SECURITY_ATTRIBUTES(Structure):
    """
    typedef struct _SECURITY_ATTRIBUTES {
        DWORD nLength;
        LPVOID lpSecurityDescriptor;
        BOOL bInheritHandle;
    } SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;
    """
    _pack_ = 1
    _fields_ = [
        ('nLength', DWORD),
        ('lpSecurityDescriptor', LPVOID),
        ('bInheritHandle', BOOL),
    ]


# ---------------------------------------------------------------------------
# exception


class EXCEPTION_RECORD(Structure):
    """
    typedef struct _EXCEPTION_RECORD {
        DWORD ExceptionCode;
        DWORD ExceptionFlags;
        LPVOID ExceptionRecord;
        LPVOID ExceptionAddress;
        DWORD NumberParameters;
        LPVOID ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
    } EXCEPTION_RECORD, *PEXCEPTION_RECORD;
    """
    _pack_ = 1
    pass
EXCEPTION_RECORD._fields_ = [
    ('ExceptionCode', DWORD),
    ('ExceptionFlags', DWORD),
    ('ExceptionRecord', POINTER(EXCEPTION_RECORD)),
    ('ExceptionAddress', LPVOID),
    ('NumberParameters', DWORD),
    ('ExceptionInformation', LPVOID * 15),
]


class EXCEPTION_DEBUG_INFO(Structure):
    """
    typedef struct _EXCEPTION_DEBUG_INFO {
      EXCEPTION_RECORD ExceptionRecord;
      DWORD dwFirstChance;
    } EXCEPTION_DEBUG_INFO;
    """
    _pack_ = 1
    _fields_ = [
        ('ExceptionRecord', EXCEPTION_RECORD),
        ('dwFirstChance', DWORD),
    ]


class CREATE_THREAD_DEBUG_INFO(Structure):
    """
    typedef struct _CREATE_THREAD_DEBUG_INFO {
      HANDLE hThread;
      LPVOID lpThreadLocalBase;
      LPTHREAD_START_ROUTINE lpStartAddress;
    } CREATE_THREAD_DEBUG_INFO;
    """
    _pack_ = 1
    _fields_ = [
        ('hThread', HANDLE),
        ('lpThreadLocalBase', LPVOID),
        ('lpStartAddress', LPVOID),
    ]


class CREATE_PROCESS_DEBUG_INFO(Structure):
    """
    typedef struct _CREATE_PROCESS_DEBUG_INFO {
      HANDLE hFile;
      HANDLE hProcess;
      HANDLE hThread;
      LPVOID lpBaseOfImage;
      DWORD dwDebugInfoFileOffset;
      DWORD nDebugInfoSize;
      LPVOID lpThreadLocalBase;
      LPTHREAD_START_ROUTINE lpStartAddress;
      LPVOID lpImageName;
      WORD fUnicode;
    } CREATE_PROCESS_DEBUG_INFO;
    """
    _pack_ = 1
    _fields_ = [
        ('hFile', HANDLE),
        ('hProcess', HANDLE),
        ('hThread', HANDLE),
        ('lpBaseOfImage', LPVOID),
        ('dwDebugInfoFileOffset', DWORD),
        ('nDebugInfoSize', DWORD),
        ('lpThreadLocalBase', LPVOID),
        ('lpStartAddress', LPVOID),
        ('lpImageName', LPVOID),
        ('fUnicode', WORD),
    ]


class EXIT_THREAD_DEBUG_INFO(Structure):
    """
    typedef struct _EXIT_THREAD_DEBUG_INFO {
      DWORD dwExitCode;
    } EXIT_THREAD_DEBUG_INFO;
    """
    _pack_ = 1
    _fields_ = [
        ('dwExitCode', DWORD),
    ]


class EXIT_PROCESS_DEBUG_INFO(Structure):
    """
    typedef struct _EXIT_PROCESS_DEBUG_INFO {
      DWORD dwExitCode;
    } EXIT_PROCESS_DEBUG_INFO;
    """
    _pack_ = 1
    _fields_ = [
        ('dwExitCode', DWORD),
    ]


class LOAD_DLL_DEBUG_INFO(Structure):
    """
    typedef struct _LOAD_DLL_DEBUG_INFO {
      HANDLE hFile;
      LPVOID lpBaseOfDll;
      DWORD dwDebugInfoFileOffset;
      DWORD nDebugInfoSize;
      LPVOID lpImageName;
      WORD fUnicode;
    } LOAD_DLL_DEBUG_INFO;
    """
    _pack_ = 1
    _fields_ = [
        ('hFile', HANDLE),
        ('lpBaseOfDll', LPVOID),
        ('dwDebugInfoFileOffset', DWORD),
        ('nDebugInfoSize', DWORD),
        ('lpImageName', LPVOID),
        ('fUnicode', WORD),
    ]


class UNLOAD_DLL_DEBUG_INFO(Structure):
    """
    typedef struct _UNLOAD_DLL_DEBUG_INFO {
      LPVOID lpBaseOfDll;
    } UNLOAD_DLL_DEBUG_INFO;
    """
    _pack_ = 1
    _fields_ = [
        ('lpBaseOfDll', LPVOID),
    ]


class OUTPUT_DEBUG_STRING_INFO(Structure):
    """
    typedef struct _OUTPUT_DEBUG_STRING_INFO {
      LPSTR lpDebugStringData;
      WORD fUnicode;
      WORD nDebugStringLength;
    } OUTPUT_DEBUG_STRING_INFO;
    """
    _pack_ = 1
    _fields_ = [
        ('lpDebugStringData', LPVOID),    # don't use LPSTR
        ('fUnicode', WORD),
        ('nDebugStringLength', WORD),
    ]


class RIP_INFO(Structure):
    """
    typedef struct _RIP_INFO {
        DWORD dwError;
        DWORD dwType;
    } RIP_INFO, *LPRIP_INFO;
    """
    _pack_ = 1
    _fields_ = [
        ('dwError', DWORD),
        ('dwType', DWORD),
    ]


class _DEBUG_EVENT_UNION_(Union):
    _fields_ = [
        ('Exception', EXCEPTION_DEBUG_INFO),
        ('CreateThread', CREATE_THREAD_DEBUG_INFO),
        ('CreateProcessInfo', CREATE_PROCESS_DEBUG_INFO),
        ('ExitThread', EXIT_THREAD_DEBUG_INFO),
        ('ExitProcess', EXIT_PROCESS_DEBUG_INFO),
        ('LoadDll', LOAD_DLL_DEBUG_INFO),
        ('UnloadDll', UNLOAD_DLL_DEBUG_INFO),
        ('DebugString', OUTPUT_DEBUG_STRING_INFO),
        ('RipInfo', RIP_INFO),
    ]


class DEBUG_EVENT(Structure):
    """
    typedef struct _DEBUG_EVENT {
      DWORD dwDebugEventCode;
      DWORD dwProcessId;
      DWORD dwThreadId;
      union {
        EXCEPTION_DEBUG_INFO Exception;
        CREATE_THREAD_DEBUG_INFO CreateThread;
        CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
        EXIT_THREAD_DEBUG_INFO ExitThread;
        EXIT_PROCESS_DEBUG_INFO ExitProcess;
        LOAD_DLL_DEBUG_INFO LoadDll;
        UNLOAD_DLL_DEBUG_INFO UnloadDll;
        OUTPUT_DEBUG_STRING_INFO DebugString;
        RIP_INFO RipInfo;
      } u;
    } DEBUG_EVENT;.
    """
    _pack_ = 1
    _fields_ = [
        ('dwDebugEventCode', DWORD),
        ('dwProcessId', DWORD),
        ('dwThreadId', DWORD),
        ('u', _DEBUG_EVENT_UNION_),
    ]


class LUID(Structure):
    """
    typedef struct _LUID {
      DWORD LowPart;
      LONG HighPart;
    } LUID,
    """
    _pack_ = 1
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", LONG),
    ]


class LUID_AND_ATTRIBUTES(Structure):
    """
    typedef struct _LUID_AND_ATTRIBUTES {
      LUID Luid;
      DWORD Attributes;
    } LUID_AND_ATTRIBUTES,
    """
    _pack_ = 1
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD),
    ]


class TOKEN_PRIVILEGES(Structure):
    """
    typedef struct _TOKEN_PRIVILEGES {
      DWORD PrivilegeCount;
      LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
    } TOKEN_PRIVILEGES,
    """
    _pack_ = 1
    _fields_ = [
        ("PrivilegeCount", DWORD),
        # ("Privileges",      LUID_AND_ATTRIBUTES * ANYSIZE_ARRAY),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
