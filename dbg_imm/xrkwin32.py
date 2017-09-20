# -*- coding: utf-8 -*-

"""
    win32 utility
"""

import xrkwin32def


import ctypes
from ctypes.wintypes import BOOL, DWORD, POINTER, HANDLE, LPWSTR, HMODULE, LPVOID
SIZE_T = ctypes.wintypes.c_size_t
windll = ctypes.windll
kernel32 = ctypes.windll.kernel32
advapi32 = windll.advapi32


# ---------------------------------------------------------------------------
# utils
# ---------------------------------------------------------------------------


def gen(api_call, api_argtypes, api_restype, api_errorcheck=None):
    """
        generate api call for external usage

        @param: api_call: function obj
        @param: api_argtypes: LIST: api arg type list
        @param: api_restype: api return type
        @param: api_errorcheck: function obj, check result, may raise exception
    """
    ret = api_call
    ret.argtypes = api_argtypes
    ret.restype = api_restype
    if api_errorcheck is not None:
        ret.errcheck = api_errorcheck
    return ret


def error_if_0(result, func=None, args=()):
    """
        raise error if result is 0
    """
    if not result:
        raise ctypes.WinError()
    return result


def error_if_not_0(result, func=None, args=()):
    """
        raise error if result is not 0
    """
    if result:
        raise ctypes.WinError()
    return result


def error_if_NULL(result, func=None, args=()):
    """
        raise error if result is NULL
    """
    if result is None:
        raise ctypes.WinError()
    return result


def error_if_not_NULL(result, func=None, args=()):
    """
        raise error if result is not NULL
    """
    if result is not None:
        raise ctypes.WinError()
    return result


def error_if_INVALID_HANDLE_VALUE(result, func=None, args=()):
    """
        raise error if result is INVALID_HANDLE_VALUE(-1, 0xFFFFFFFF)
    """
    if result == -1 or result == 0xFFFFFFFF:
        raise ctypes.WinError()
    return result


def error_if_not_ERROR_SUCCESS(result, func=None, args=()):
    """
        raise error if result is not ERROR_SUCCESS
    """
    # ERROR_SUCCESS 0
    if result != 0:
        raise ctypes.WinError(result)
    return result


def error_if_min1(result, func=None, args=()):
    """
        raise error if result is -1
    """
    if result == -1 or result == 0xFFFFFFFF:
        raise ctypes.WinError()
    return result


# ---------------------------------------------------------------------------
# defs - apis
# ---------------------------------------------------------------------------


"""
BOOL FileTimeToSystemTime(
  const FILETIME* lpFileTime,
  LPSYSTEMTIME lpSystemTime
);
"""
FileTimeToSystemTime = gen(kernel32.FileTimeToSystemTime, [POINTER(xrkwin32def.FILETIME), POINTER(xrkwin32def.SYSTEMTIME)], BOOL, error_if_0)


"""
BOOL SystemTimeToFileTime(
  const SYSTEMTIME* lpSystemTime,
  LPFILETIME lpFileTime
);
"""
SystemTimeToFileTime = gen(kernel32.SystemTimeToFileTime, [POINTER(xrkwin32def.SYSTEMTIME), POINTER(xrkwin32def.FILETIME)], BOOL, error_if_0)


# ---------------------------------------------------------------------------

"""
imagehlp.dll    - CheckSumMappedFile
"""


"""
PSAPI.DLL       - GetProcessImageFileNameW
PSAPI.DLL       - EnumProcessModules
PSAPI.DLL       - GetModuleBaseNameA
PSAPI.DLL       - GetModuleFileNameExA
PSAPI.DLL       - GetModuleFileNameExW
PSAPI.DLL       - EnumProcesses
PSAPI.DLL       - GetMappedFileNameW
PSAPI.DLL       - GetModuleInformation
"""

# ---------------------------------------------------------------------------
# KERNEL32.dll
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# debug


"""
BOOL WINAPI DebugActiveProcess(
  _In_ DWORD dwProcessId
);
"""
DebugActiveProcess = gen(kernel32.DebugActiveProcess, [DWORD], BOOL, error_if_0)


"""
BOOL WINAPI ContinueDebugEvent(
  _In_ DWORD dwProcessId,
  _In_ DWORD dwThreadId,
  _In_ DWORD dwContinueStatus
);
"""
ContinueDebugEvent = gen(kernel32.ContinueDebugEvent, [DWORD, DWORD, DWORD], BOOL, error_if_0)


"""
BOOL WINAPI WaitForDebugEvent(
  _Out_ LPDEBUG_EVENT lpDebugEvent,
  _In_  DWORD         dwMilliseconds
);
"""
WaitForDebugEvent = gen(kernel32.WaitForDebugEvent, [POINTER(xrkwin32def.DEBUG_EVENT), DWORD], BOOL, error_if_0)


# ---------------------------------------------------------------------------
# thread


"""
HANDLE WINAPI CreateRemoteThread(
  _In_  HANDLE                 hProcess,
  _In_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  _In_  SIZE_T                 dwStackSize,
  _In_  LPTHREAD_START_ROUTINE lpStartAddress,
  _In_  LPVOID                 lpParameter,
  _In_  DWORD                  dwCreationFlags,
  _Out_ LPDWORD                lpThreadId
);
"""
CreateRemoteThread = gen(kernel32.CreateRemoteThread, [HANDLE, POINTER(xrkwin32def.SECURITY_ATTRIBUTES), SIZE_T, LPVOID, LPVOID, DWORD, POINTER(DWORD)], HANDLE, error_if_NULL)


"""
HANDLE WINAPI OpenThread(
  _In_ DWORD dwDesiredAccess,
  _In_ BOOL  bInheritHandle,
  _In_ DWORD dwThreadId
);
"""
OpenThread = gen(kernel32.OpenThread, [DWORD, BOOL, DWORD], HANDLE, error_if_NULL)


"""
DWORD WINAPI SuspendThread(
  _In_ HANDLE hThread
);
"""
SuspendThread = gen(kernel32.SuspendThread, [HANDLE], DWORD, error_if_min1)


"""
DWORD WINAPI ResumeThread(
  _In_ HANDLE hThread
);
"""
ResumeThread = gen(kernel32.ResumeThread, [HANDLE], DWORD, error_if_min1)


"""
BOOL WINAPI TerminateThread(
  _Inout_ HANDLE hThread,
  _In_    DWORD  dwExitCode
);
"""
TerminateThread = gen(kernel32.TerminateThread, [HANDLE, DWORD], BOOL, error_if_0)


"""
BOOL WINAPI GetThreadContext(
  _In_    HANDLE    hThread,
  _Inout_ LPCONTEXT lpContext
);
"""
GetThreadContext = gen(kernel32.GetThreadContext, [HANDLE, POINTER(xrkwin32def.CONTEXT)], BOOL, error_if_0)


"""
BOOL WINAPI SetThreadContext(
  _In_       HANDLE  hThread,
  _In_ const CONTEXT *lpContext
);
"""
SetThreadContext = gen(kernel32.SetThreadContext, [HANDLE, POINTER(xrkwin32def.CONTEXT)], BOOL, error_if_0)


"""
BOOL WINAPI GetExitCodeThread(
  _In_  HANDLE  hThread,
  _Out_ LPDWORD lpExitCode
);
"""
GetExitCodeThread = gen(kernel32.GetExitCodeThread, [HANDLE, POINTER(DWORD)], BOOL, error_if_0)


# ---------------------------------------------------------------------------
# process


"""
HANDLE GetCurrentProcess(void);
"""
GetCurrentProcess = gen(kernel32.GetCurrentProcess, [], HANDLE)


"""
HANDLE WINAPI OpenProcess(
  _In_ DWORD dwDesiredAccess,
  _In_ BOOL  bInheritHandle,
  _In_ DWORD dwProcessId
);
"""
OpenProcess = gen(kernel32.OpenProcess, [DWORD, BOOL, DWORD], HANDLE, error_if_NULL)


"""
DWORD WINAPI GetProcessId(
  _In_ HANDLE Process
);
"""
GetProcessId = gen(kernel32.GetProcessId, [HANDLE], DWORD)


"""
BOOL WINAPI FlushInstructionCache(
  _In_ HANDLE  hProcess,
  _In_ LPCVOID lpBaseAddress,
  _In_ SIZE_T  dwSize
);
"""
FlushInstructionCache = gen(kernel32.FlushInstructionCache, [HANDLE, LPVOID, SIZE_T], BOOL, error_if_0)


"""
SIZE_T WINAPI VirtualQueryEx(
  _In_     HANDLE                    hProcess,
  _In_opt_ LPCVOID                   lpAddress,
  _Out_    PMEMORY_BASIC_INFORMATION lpBuffer,
  _In_     SIZE_T                    dwLength
);
"""
VirtualQueryEx = gen(kernel32.VirtualQueryEx, [HANDLE, LPVOID, POINTER(xrkwin32def.MEMORY_BASIC_INFORMATION), SIZE_T], SIZE_T, error_if_0)


"""
BOOL WINAPI VirtualProtectEx(
  _In_  HANDLE hProcess,
  _In_  LPVOID lpAddress,
  _In_  SIZE_T dwSize,
  _In_  DWORD  flNewProtect,
  _Out_ PDWORD lpflOldProtect
);
"""
VirtualProtectEx = gen(kernel32.VirtualProtectEx, [HANDLE, LPVOID, SIZE_T, DWORD, POINTER(DWORD)], BOOL, error_if_0)


"""
BOOL WINAPI ReadProcessMemory(
  _In_  HANDLE  hProcess,
  _In_  LPCVOID lpBaseAddress,
  _Out_ LPVOID  lpBuffer,
  _In_  SIZE_T  nSize,
  _Out_ SIZE_T  *lpNumberOfBytesRead
);
"""
ReadProcessMemory = gen(kernel32.ReadProcessMemory, [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)], BOOL, error_if_0)


"""
BOOL WINAPI WriteProcessMemory(
  _In_  HANDLE  hProcess,
  _In_  LPVOID  lpBaseAddress,
  _In_  LPCVOID lpBuffer,
  _In_  SIZE_T  nSize,
  _Out_ SIZE_T  *lpNumberOfBytesWritten
);
"""
WriteProcessMemory = gen(kernel32.WriteProcessMemory, [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)], BOOL, error_if_0)


# ---------------------------------------------------------------------------
# module


"""
DWORD WINAPI GetModuleFileName(
  _In_opt_ HMODULE hModule,
  _Out_    LPTSTR  lpFilename,
  _In_     DWORD   nSize
);
"""
GetModuleFileNameW = gen(kernel32.GetModuleFileNameW, [HMODULE, LPWSTR, DWORD], DWORD, error_if_0)


"""
FARPROC GetProcAddress(
  HMODULE hModule,
  LPCWSTR lpProcName
);
"""
GetProcAddress = gen(kernel32.GetProcAddress, [HMODULE, LPWSTR], LPVOID, error_if_NULL)


# ---------------------------------------------------------------------------
# handle

"""
BOOL CloseHandle(
  HANDLE hObject
);
"""
CloseHandle = gen(kernel32.CloseHandle, [HANDLE], BOOL, error_if_0)


"""
BOOL WINAPI GetHandleInformation(
  _In_  HANDLE  hObject,
  _Out_ LPDWORD lpdwFlags
);
"""
GetHandleInformation = gen(kernel32.GetHandleInformation, [HANDLE, POINTER(DWORD)], BOOL, error_if_0)


"""
BOOL DuplicateHandle(
  HANDLE hSourceProcessHandle,
  HANDLE hSourceHandle,
  HANDLE hTargetProcessHandle,
  LPHANDLE lpTargetHandle,
  DWORD dwDesiredAccess,
  BOOL bInheritHandle,
  DWORD dwOptions
);
"""
DuplicateHandle = gen(kernel32.DuplicateHandle, [HANDLE, HANDLE, HANDLE, POINTER(HANDLE), DWORD, BOOL, DWORD], BOOL, error_if_0)


# ---------------------------------------------------------------------------
# enums


"""
HANDLE WINAPI CreateToolhelp32Snapshot(
  _In_ DWORD dwFlags,
  _In_ DWORD th32ProcessID
);
"""
CreateToolhelp32Snapshot = gen(kernel32.CreateToolhelp32Snapshot, [DWORD, DWORD], HANDLE, error_if_INVALID_HANDLE_VALUE)


"""
BOOL WINAPI Process32First(
  _In_    HANDLE           hSnapshot,
  _Inout_ LPPROCESSENTRY32W lppe
);
"""
Process32FirstW = gen(kernel32.Process32FirstW, [HANDLE, POINTER(xrkwin32def.PROCESSENTRY32W)], BOOL)


"""
BOOL WINAPI Process32Next(
  _In_  HANDLE           hSnapshot,
  _Out_ LPPROCESSENTRY32W lppe
);
"""
Process32NextW = gen(kernel32.Process32NextW, [HANDLE, POINTER(xrkwin32def.PROCESSENTRY32W)], BOOL)


"""
BOOL WINAPI Thread32First(
  _In_    HANDLE          hSnapshot,
  _Inout_ LPTHREADENTRY32 lpte
);
"""
Thread32First = gen(kernel32.Thread32First, [HANDLE, POINTER(xrkwin32def.THREADENTRY32)], BOOL)


"""
BOOL WINAPI Thread32Next(
  _In_  HANDLE          hSnapshot,
  _Out_ LPTHREADENTRY32 lpte
);
"""
Thread32Next = gen(kernel32.Thread32Next, [HANDLE, POINTER(xrkwin32def.THREADENTRY32)], BOOL)


# ---------------------------------------------------------------------------
# misc


"""
DWORD WINAPI GetTickCount(void);
"""
GetTickCount = gen(kernel32.GetTickCount, [], DWORD)


"""
void WINAPI GetSystemInfo(
  _Out_ LPSYSTEM_INFO lpSystemInfo
);
"""
GetSystemInfo = gen(kernel32.GetSystemInfo, [POINTER(xrkwin32def.SYSTEM_INFO)], None)


"""
void WINAPI FatalAppExit(
  _In_ UINT    uAction,
  _In_ LPCTSTR lpMessageText
);
"""
FatalAppExitW = gen(kernel32.FatalAppExitW, [DWORD, LPWSTR], None)


"""
DWORD WINAPI GetFileType(
  _In_ HANDLE hFile
);
"""
GetFileType = gen(kernel32.GetFileType, [HANDLE], DWORD)


"""
DWORD GetLastError(void);
"""
GetLastError = gen(kernel32.GetLastError, [], DWORD)


"""
USER32.dll      - SendMessageW
USER32.dll      - LoadImageW
USER32.dll      - SendMessageA
USER32.dll      - SetDlgItemTextA
USER32.dll      - GetDlgItem
USER32.dll      - IsDlgButtonChecked
USER32.dll      - MessageBoxA
USER32.dll      - DialogBoxParamA
USER32.dll      - GetDlgItemTextA
USER32.dll      - EndDialog
USER32.dll      - CheckDlgButton
"""


# ---------------------------------------------------------------------------
# ADVAPI32.DLL
# ---------------------------------------------------------------------------


"""
BOOL WINAPI OpenProcessToken(
  _In_  HANDLE  ProcessHandle,
  _In_  DWORD   DesiredAccess,
  _Out_ PHANDLE TokenHandle
);
"""
OpenProcessToken = gen(advapi32.OpenProcessToken, [HANDLE, DWORD, POINTER(HANDLE)], BOOL, error_if_0)


"""
BOOL WINAPI LookupPrivilegeValue(
  _In_opt_ LPCTSTR lpSystemName,
  _In_     LPCTSTR lpName,
  _Out_    PLUID   lpLuid
);
"""
LookupPrivilegeValueW = gen(advapi32.LookupPrivilegeValueW, [LPWSTR, LPWSTR, POINTER(xrkwin32def.LUID)], BOOL, error_if_0)


"""
BOOL WINAPI AdjustTokenPrivileges(
  _In_      HANDLE            TokenHandle,
  _In_      BOOL              DisableAllPrivileges,
  _In_opt_  PTOKEN_PRIVILEGES NewState,
  _In_      DWORD             BufferLength,
  _Out_opt_ PTOKEN_PRIVILEGES PreviousState,
  _Out_opt_ PDWORD            ReturnLength
);
"""
AdjustTokenPrivileges = gen(advapi32.AdjustTokenPrivileges,
                            [HANDLE, BOOL, POINTER(xrkwin32def.TOKEN_PRIVILEGES), DWORD, POINTER(xrkwin32def.TOKEN_PRIVILEGES), POINTER(DWORD)],
                            BOOL,
                            error_if_0)


"""
NTDLL.dll       - NtSetInformationThread
NTDLL.dll       - NtQueryInformationThread
NTDLL.dll       - NtQueryInformationProcess
NTDLL.dll       - NtQueryObject
NTDLL.dll       - NtQuerySystemInformation
"""

# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
