# -*- coding: utf-8 -*-

"""
    xrkmon api list
"""

import os
import sys
import inspect
import traceback

try:
    import xrklog
    import xrkutil
    import xrkmonrun
except:
    this_path = os.path.split(os.path.realpath(inspect.stack()[-1][1]))[0]
    sys.path.append(this_path)
    try:
        import xrklog
        import xrkutil
        import xrkmonrun
    except Exception, e:
        import immlib as dbglib
        dbg = dbglib.Debugger()
        dbg.log("xrkmon api list import error: %s" % e, highlight=1)
        error = traceback.format_exc()
        while len(error) > 200:
            tmp = error[:200]
            dbg.log("  %s" % tmp, highlight=1)
            error = error[200:]
        dbg.log("  %s" % error, highlight=1)

        assert False

# ---------------------------------------------------------------------------
#                                   ALL APIS                                #
# ---------------------------------------------------------------------------

# actually, this is not a good place to store these stuff, but, it's the 'best' place.

v_level_critical = 1
v_level_middle = 5
v_level_optional = 9


v_level_v_to_str_dict = {
    v_level_critical: "critical",
    v_level_middle: "middle",
    v_level_optional: "optional"}


v_level_str_to_v_dict = {
    "critical": v_level_critical,
    "middle": v_level_middle,
    "optional": v_level_optional}


def __level_value_to_str(level_v):
    """
        get level string corresponding to level value

        @param: level_v : INT : level value

        @return: STRING : level string
    """
    if level_v not in v_level_v_to_str_dict:
        raise Exception("invalid level value: %d" % level_v)

    return v_level_v_to_str_dict[level_v]


def __level_str_to_value(level_str):
    """
        get level value corresponding to level string

        @param: level_str : STRING : level string

        @return: INT: level value
    """
    if level_str == "default":
        level_str = "critical"

    if level_str not in v_level_str_to_v_dict:
        raise Exception("invalid level string: %s" % level_str)

    return v_level_str_to_v_dict[level_str]


class apiInfo:
    def __init__(self, dll_name, level, run_cbk):
        """
            api info

            @param: dll_name : STRING : dll name that api belongs to
            @param: level    : INT    : one of v_level_critical/v_level_middle/v_level_optional
            @param: run_cbk  : method : method defined in xrkmonrun.py, prototype: run_xx(regs)
        """
        self.dll_name = dll_name.lower()
        self.level = level
        self.run_cbk = run_cbk

# ---------------------------------------------------------------------------
# DNSAPI.DLL --> DNS
# ---------------------------------------------------------------------------


api_info_dns = {
    "DnsQuery_W": apiInfo("DNSAPI.DLL", v_level_optional, xrkmonrun.run_DnsQuery_W),
    "DnsQuery_UTF8": apiInfo("DNSAPI.DLL", v_level_optional, xrkmonrun.run_DnsQuery_UTF8)}


# ---------------------------------------------------------------------------
# WS2_32.DLL --> SOCKET
# ---------------------------------------------------------------------------


api_info_ws2_32 = {
    "WSAStartup": apiInfo("WS2_32.DLL", v_level_critical, xrkmonrun.run_WSAStartup),
    "GetAddrInfoW": apiInfo("WS2_32.DLL", v_level_critical, xrkmonrun.run_GetAddrInfoW),
    "getaddrinfo": apiInfo("WS2_32.DLL", v_level_critical, xrkmonrun.run_getaddrinfo),
    "gethostbyname": apiInfo("WS2_32.DLL", v_level_critical, xrkmonrun.run_gethostbyname),
    "getsockname": apiInfo("WS2_32.DLL", v_level_optional, xrkmonrun.run_getsockname),
    "WSAAccept": apiInfo("WS2_32.DLL", v_level_optional, xrkmonrun.run_WSAAccept),
    "gethostname": apiInfo("WS2_32.DLL", v_level_optional, xrkmonrun.run_gethostname),
    "freeaddrinfo": apiInfo("WS2_32.DLL", v_level_optional, xrkmonrun.run_freeaddrinfo),
    "gethostbyaddr": apiInfo("WS2_32.DLL", v_level_optional, xrkmonrun.run_gethostbyaddr),
    "GetNameInfoW": apiInfo("WS2_32.DLL", v_level_optional, xrkmonrun.run_GetNameInfoW),
    "getnameinfo": apiInfo("WS2_32.DLL", v_level_optional, xrkmonrun.run_getnameinfo),
    "WSACleanup": apiInfo("WS2_32.DLL", v_level_optional, xrkmonrun.run_WSACleanup),
    "socket": apiInfo("WS2_32.DLL", v_level_critical, xrkmonrun.run_socket),
    "WSASocketW": apiInfo("WS2_32.DLL", v_level_critical, xrkmonrun.run_WSASocketW),
    "closesocket": apiInfo("WS2_32.DLL", v_level_optional, xrkmonrun.run_closesocket),
    "getpeername": apiInfo("WS2_32.DLL", v_level_optional, xrkmonrun.run_getpeername),
    "bind": apiInfo("WS2_32.DLL", v_level_critical, xrkmonrun.run_bind),
    "listen": apiInfo("WS2_32.DLL", v_level_critical, xrkmonrun.run_listen),
    "connect": apiInfo("WS2_32.DLL", v_level_critical, xrkmonrun.run_connect),
    "WSAConnect": apiInfo("WS2_32.DLL", v_level_critical, xrkmonrun.run_WSAConnect),
    "send": apiInfo("WS2_32.DLL", v_level_critical, xrkmonrun.run_send),
    "sendto": apiInfo("WS2_32.DLL", v_level_critical, xrkmonrun.run_sendto),
    "WSASend": apiInfo("WS2_32.DLL", v_level_critical, xrkmonrun.run_WSASend),
    "WSASendTo": apiInfo("WS2_32.DLL", v_level_critical, xrkmonrun.run_WSASendTo),
    "WSASendDisconnect": apiInfo("WS2_32.DLL", v_level_optional, xrkmonrun.run_WSASendDisconnect),
    "recv": apiInfo("WS2_32.DLL", v_level_critical, xrkmonrun.run_recv),
    "recvfrom": apiInfo("WS2_32.DLL", v_level_critical, xrkmonrun.run_recvfrom),
    "WSARecv": apiInfo("WS2_32.DLL", v_level_critical, xrkmonrun.run_WSARecv),
    "WSARecvFrom": apiInfo("WS2_32.DLL", v_level_critical, xrkmonrun.run_WSARecvFrom),
    "WSARecvDisconnect": apiInfo("WS2_32.DLL", v_level_optional, xrkmonrun.run_WSARecvDisconnect),
    "select": apiInfo("WS2_32.DLL", v_level_optional, xrkmonrun.run_select),
    "setsockopt": apiInfo("WS2_32.DLL", v_level_optional, xrkmonrun.run_setsockopt)}


# ---------------------------------------------------------------------------
# WININET.DLL --> INTERNET/HTTP
# ---------------------------------------------------------------------------


api_info_wininet = {
    "InternetOpenA": apiInfo("WININET.DLL", v_level_critical, xrkmonrun.run_InternetOpenA),
    "InternetCrackUrlA": apiInfo("WININET.DLL", v_level_middle, xrkmonrun.run_InternetCrackUrlA),
    "InternetGetCookieExW": apiInfo("WININET.DLL", v_level_optional, xrkmonrun.run_InternetGetCookieExW),
    "InternetSetCookieA": apiInfo("WININET.DLL", v_level_optional, xrkmonrun.run_InternetSetCookieA),
    "InternetSetCookieExA": apiInfo("WININET.DLL", v_level_optional, xrkmonrun.run_InternetSetCookieExA),
    "InternetSetCookieExW": apiInfo("WININET.DLL", v_level_optional, xrkmonrun.run_InternetSetCookieExW),
    "InternetAttemptConnect": apiInfo("WININET.DLL", v_level_optional, xrkmonrun.run_InternetAttemptConnect),
    "InternetConnectA": apiInfo("WININET.DLL", v_level_critical, xrkmonrun.run_InternetConnectA),
    "InternetFindNextFileA": apiInfo("WININET.DLL", v_level_optional, xrkmonrun.run_InternetFindNextFileA),
    "InternetOpenUrlA": apiInfo("WININET.DLL", v_level_critical, xrkmonrun.run_InternetOpenUrlA),
    "InternetReadFile": apiInfo("WININET.DLL", v_level_middle, xrkmonrun.run_InternetReadFile),
    "InternetReadFileExA": apiInfo("WININET.DLL", v_level_middle, xrkmonrun.run_InternetReadFileExA),
    "InternetWriteFile": apiInfo("WININET.DLL", v_level_optional, xrkmonrun.run_InternetWriteFile),
    "InternetCanonicalizeUrlA": apiInfo("WININET.DLL", v_level_optional, xrkmonrun.run_InternetCanonicalizeUrlA),
    "InternetCanonicalizeUrlW": apiInfo("WININET.DLL", v_level_optional, xrkmonrun.run_InternetCanonicalizeUrlW),
    "HttpOpenRequestA": apiInfo("WININET.DLL", v_level_middle, xrkmonrun.run_HttpOpenRequestA),
    "HttpOpenRequestW": apiInfo("WININET.DLL", v_level_middle, xrkmonrun.run_HttpOpenRequestW),
    "HttpSendRequestA": apiInfo("WININET.DLL", v_level_critical, xrkmonrun.run_HttpSendRequestA),
    "HttpSendRequestW": apiInfo("WININET.DLL", v_level_critical, xrkmonrun.run_HttpSendRequestW),
    "HttpSendRequestExA": apiInfo("WININET.DLL", v_level_critical, xrkmonrun.run_HttpSendRequestExA),
    "HttpSendRequestExW": apiInfo("WININET.DLL", v_level_critical, xrkmonrun.run_HttpSendRequestExW),
    "HttpAddRequestHeadersA": apiInfo("WININET.DLL", v_level_critical, xrkmonrun.run_HttpAddRequestHeadersA)}


# ---------------------------------------------------------------------------
# WINHTTP.DLL --> HTTP
# ---------------------------------------------------------------------------


api_info_winhttp = {
    "WinHttpOpen": apiInfo("WINHTTP.DLL", v_level_critical, xrkmonrun.run_WinHttpOpen),
    "WinHttpCloseHandle": apiInfo("WINHTTP.DLL", v_level_critical, xrkmonrun.run_WinHttpCloseHandle),
    "WinHttpConnect": apiInfo("WINHTTP.DLL", v_level_critical, xrkmonrun.run_WinHttpConnect),
    "WinHttpOpenRequest": apiInfo("WINHTTP.DLL", v_level_critical, xrkmonrun.run_WinHttpOpenRequest),
    "WinHttpSendRequest": apiInfo("WINHTTP.DLL", v_level_critical, xrkmonrun.run_WinHttpSendRequest),
    "WinHttpReceiveResponse": apiInfo("WINHTTP.DLL", v_level_critical, xrkmonrun.run_WinHttpReceiveResponse),
    "WinHttpQueryHeaders": apiInfo("WINHTTP.DLL", v_level_optional, xrkmonrun.run_WinHttpQueryHeaders),
    "WinHttpQueryDataAvailable": apiInfo("WINHTTP.DLL", v_level_optional, xrkmonrun.run_WinHttpQueryDataAvailable),
    "WinHttpReadData": apiInfo("WINHTTP.DLL", v_level_critical, xrkmonrun.run_WinHttpReadData),
    "WinHttpAddRequestHeaders": apiInfo("WINHTTP.DLL", v_level_critical, xrkmonrun.run_WinHttpAddRequestHeaders),
    "WinHttpCrackUrl": apiInfo("WINHTTP.DLL", v_level_critical, xrkmonrun.run_WinHttpCrackUrl),
    "WinHttpWriteData": apiInfo("WINHTTP.DLL", v_level_critical, xrkmonrun.run_WinHttpWriteData)}


# ---------------------------------------------------------------------------
# KERNEL32.DLL --> FILE MAPPING
# ---------------------------------------------------------------------------


api_info_file_map = {
    "CreateFileMappingW": apiInfo("KERNEL32.DLL", v_level_middle, xrkmonrun.run_CreateFileMappingW),
    "OpenFileMappingW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_OpenFileMappingW),
    "MapViewOfFileEx": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_MapViewOfFileEx),
    "UnmapViewOfFile": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_UnmapViewOfFile)}


# ---------------------------------------------------------------------------
# KERNEL32.DLL --> FILE
# ---------------------------------------------------------------------------


api_info_file = {
    "WriteFile": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_WriteFile),
    "WriteFileEx": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_WriteFileEx),
    "CopyFileExW": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_CopyFileExW),
    "MoveFileWithProgressW": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_MoveFileWithProgressW),
    "CreateDirectoryW": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_CreateDirectoryW),
    "CreateDirectoryExW": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_CreateDirectoryExW),
    "RemoveDirectoryW": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_RemoveDirectoryW),
    "ReplaceFileW": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_ReplaceFileW),
    "DeleteFileW": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_DeleteFileW),
    "SetFileAttributesW": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_SetFileAttributesW),
    "SetFileTime": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_SetFileTime),
    "CreateFileW": apiInfo("KERNEL32.DLL", v_level_middle, xrkmonrun.run_CreateFileW),
    "ReadFile": apiInfo("KERNEL32.DLL", v_level_middle, xrkmonrun.run_ReadFile),
    "ReadFileEx": apiInfo("KERNEL32.DLL", v_level_middle, xrkmonrun.run_ReadFileEx),
    "DeviceIoControl": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_DeviceIoControl),
    "FindFirstFileExW": apiInfo("KERNEL32.DLL", v_level_middle, xrkmonrun.run_FindFirstFileExW),
    "FindNextFileW": apiInfo("KERNEL32.DLL", v_level_middle, xrkmonrun.run_FindNextFileW),
    "PathFileExistsA": apiInfo("SHLWAPI.DLL", v_level_middle, xrkmonrun.run_PathFileExistsA),
    "PathFileExistsW": apiInfo("SHLWAPI.DLL", v_level_middle, xrkmonrun.run_PathFileExistsW),
    "GetFileTime": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetFileTime)}


# ---------------------------------------------------------------------------
# KERNEL32.DLL --> PROC
# ---------------------------------------------------------------------------


api_info_proc = {
    "CreateToolhelp32Snapshot": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_CreateToolhelp32Snapshot),
    "OpenProcess": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_OpenProcess),
    "ExitProcess": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_ExitProcess),
    "WriteProcessMemory": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_WriteProcessMemory),
    "CreateThread": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_CreateThread),
    "CreateRemoteThread": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_CreateRemoteThread),
    "ReadProcessMemory": apiInfo("KERNEL32.DLL", v_level_middle, xrkmonrun.run_ReadProcessMemory),
    "CreateProcessW": apiInfo("KERNEL32.DLL", v_level_middle, xrkmonrun.run_CreateProcessW),
    "CreateProcessInternalA": apiInfo("KERNEL32.DLL", v_level_middle, xrkmonrun.run_CreateProcessInternalA),
    "CreateProcessInternalW": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_CreateProcessInternalW),
    "ExitThread": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_ExitThread),
    "ResumeThread": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_ResumeThread),
    "SuspendThread": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_SuspendThread),
    "TerminateThread": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_TerminateThread),
    "OpenThread": apiInfo("KERNEL32.DLL", v_level_middle, xrkmonrun.run_OpenThread),
    "GetExitCodeProcess": apiInfo("KERNEL32.DLL", v_level_middle, xrkmonrun.run_GetExitCodeProcess),
    "TerminateProcess": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_TerminateProcess),
    "IsWow64Process": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_IsWow64Process),
    "Thread32Next": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_Thread32Next),
    "Thread32First": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_Thread32First),
    "Module32NextW": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_Module32NextW),
    "Module32FirstW": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_Module32FirstW),
    "Process32NextW": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_Process32NextW),
    "Process32FirstW": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_Process32FirstW)}


# ---------------------------------------------------------------------------
# ADVAPI32.DLL --> REG
# ---------------------------------------------------------------------------


api_info_reg = {
    "RegSetValueExA": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_RegSetValueExA),
    "RegSetValueExW": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_RegSetValueExW),
    "RegDeleteKeyA": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_RegDeleteKeyA),
    "RegDeleteKeyW": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_RegDeleteKeyW),
    "RegDeleteValueA": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_RegDeleteValueA),
    "RegDeleteValueW": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_RegDeleteValueW),
    "RegSaveKeyExA": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_RegSaveKeyExA),
    "RegSaveKeyExW": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_RegSaveKeyExW),
    "RegSaveKeyA": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_RegSaveKeyA),
    "RegSaveKeyW": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_RegSaveKeyW),
    "RegQueryInfoKeyA": apiInfo("ADVAPI32.DLL", v_level_optional, xrkmonrun.run_RegQueryInfoKeyA),
    "RegQueryInfoKeyW": apiInfo("ADVAPI32.DLL", v_level_optional, xrkmonrun.run_RegQueryInfoKeyW),
    "RegQueryMultipleValuesA": apiInfo("ADVAPI32.DLL", v_level_optional, xrkmonrun.run_RegQueryMultipleValuesA),
    "RegQueryMultipleValuesW": apiInfo("ADVAPI32.DLL", v_level_optional, xrkmonrun.run_RegQueryMultipleValuesW),
    "RegQueryValueExA": apiInfo("ADVAPI32.DLL", v_level_optional, xrkmonrun.run_RegQueryValueExA),
    "RegQueryValueExW": apiInfo("ADVAPI32.DLL", v_level_optional, xrkmonrun.run_RegQueryValueExW),
    "RegReplaceKeyA": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_RegReplaceKeyA),
    "RegReplaceKeyW": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_RegReplaceKeyW),
    "RegRestoreKeyA": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_RegRestoreKeyA),
    "RegRestoreKeyW": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_RegRestoreKeyW),
    "RegCreateKeyExA": apiInfo("ADVAPI32.DLL", v_level_middle, xrkmonrun.run_RegCreateKeyExA),
    "RegCreateKeyExW": apiInfo("ADVAPI32.DLL", v_level_middle, xrkmonrun.run_RegCreateKeyExW),
    "RegConnectRegistryW": apiInfo("ADVAPI32.DLL", v_level_middle, xrkmonrun.run_RegConnectRegistryW),
    "RegEnumKeyExA": apiInfo("ADVAPI32.DLL", v_level_middle, xrkmonrun.run_RegEnumKeyExA),
    "RegEnumKeyW": apiInfo("ADVAPI32.DLL", v_level_middle, xrkmonrun.run_RegEnumKeyW),
    "RegEnumKeyExW": apiInfo("ADVAPI32.DLL", v_level_middle, xrkmonrun.run_RegEnumKeyExW),
    "RegEnumValueA": apiInfo("ADVAPI32.DLL", v_level_middle, xrkmonrun.run_RegEnumValueA),
    "RegEnumValueW": apiInfo("ADVAPI32.DLL", v_level_middle, xrkmonrun.run_RegEnumValueW),
    "RegLoadKeyA": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_RegLoadKeyA),
    "RegLoadKeyW": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_RegLoadKeyW),
    "RegOpenKeyExA": apiInfo("ADVAPI32.DLL", v_level_optional, xrkmonrun.run_RegOpenKeyExA),
    "RegOpenKeyExW": apiInfo("ADVAPI32.DLL", v_level_optional, xrkmonrun.run_RegOpenKeyExW)}


# ---------------------------------------------------------------------------
# KERNEL32.DLL --> PROFILE
# ---------------------------------------------------------------------------


api_info_profile = {
    "GetPrivateProfileStringA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetPrivateProfileStringA),
    "GetPrivateProfileStringW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetPrivateProfileStringW),
    "GetPrivateProfileSectionA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetPrivateProfileSectionA),
    "GetPrivateProfileSectionW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetPrivateProfileSectionW),
    "WritePrivateProfileSectionA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_WritePrivateProfileSectionA),
    "WritePrivateProfileSectionW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_WritePrivateProfileSectionW),
    "WritePrivateProfileStringA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_WritePrivateProfileStringA),
    "WritePrivateProfileStringW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_WritePrivateProfileStringW)}


# ---------------------------------------------------------------------------
# KERNEL32.DLL --> MUTEX
# ---------------------------------------------------------------------------


api_info_mutex = {
    "CreateMutexW": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_CreateMutexW),
    "OpenMutexW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_OpenMutexW),
    "ReleaseMutex": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_ReleaseMutex)}


# ---------------------------------------------------------------------------
# KERNEL32.DLL --> VOLUME
# ---------------------------------------------------------------------------


api_info_volume = {
    "GetDiskFreeSpaceW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetDiskFreeSpaceW),
    "GetDiskFreeSpaceExW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetDiskFreeSpaceExW),
    "GetDriveTypeW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetDriveTypeW),
    "GetVolumeInformationW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetVolumeInformationW),
    "GetVolumeNameForVolumeMountPointW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetVolumeNameForVolumeMountPointW),
    "FindFirstVolumeW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_FindFirstVolumeW),
    "FindNextVolumeW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_FindNextVolumeW),
    "GetFullPathNameW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetFullPathNameW),
    "GetVolumePathNamesForVolumeNameW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetVolumePathNamesForVolumeNameW),
    "GetLogicalDriveStringsA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetLogicalDriveStringsA),
    "GetLogicalDriveStringsW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetLogicalDriveStringsW),
    "GetLogicalDrives": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetLogicalDrives)}


# ---------------------------------------------------------------------------
# KERNEL32.DLL --> PIPE
# ---------------------------------------------------------------------------


api_info_pipe = {
    "CallNamedPipeW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_CallNamedPipeW),
    "CreateNamedPipeW": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_CreateNamedPipeW),
    "CreatePipe": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_CreatePipe),
    "WaitNamedPipeW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_WaitNamedPipeW),
    "PeekNamedPipe": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_PeekNamedPipe),
    "ConnectNamedPipe": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_ConnectNamedPipe),
    "DisconnectNamedPipe": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_DisconnectNamedPipe)}


# ---------------------------------------------------------------------------
# KERNEL32.DLL --> ENVIRONMENT
# ---------------------------------------------------------------------------


api_info_evn = {
    "GetEnvironmentStringsA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetEnvironmentStringsA),
    "GetEnvironmentStringsW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetEnvironmentStringsW),
    "GetEnvironmentVariableA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetEnvironmentVariableA),
    "GetEnvironmentVariableW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetEnvironmentVariableW),
    "SetEnvironmentVariableA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_SetEnvironmentVariableA),
    "SetEnvironmentVariableW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_SetEnvironmentVariableW),
    "ExpandEnvironmentStringsA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_ExpandEnvironmentStringsA),
    "ExpandEnvironmentStringsW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_ExpandEnvironmentStringsW)}


# ---------------------------------------------------------------------------
# USER32.DLL --> HOOK
# "NtUserUnhookWindowsHookEx": apiInfo("NTDLL.DLL", v_level_critical, xrkmonrun.run_NtUserUnhookWindowsHookEx)
# ---------------------------------------------------------------------------


api_info_hook = {
    "CallNextHookEx": apiInfo("USER32.DLL", v_level_critical, xrkmonrun.run_CallNextHookEx),
    "SetWindowsHookA": apiInfo("USER32.DLL", v_level_critical, xrkmonrun.run_SetWindowsHookA),
    "SetWindowsHookW": apiInfo("USER32.DLL", v_level_critical, xrkmonrun.run_SetWindowsHookW),
    "SetWindowsHookExA": apiInfo("USER32.DLL", v_level_critical, xrkmonrun.run_SetWindowsHookExA),
    "SetWindowsHookExW": apiInfo("USER32.DLL", v_level_critical, xrkmonrun.run_SetWindowsHookExW),
    "UnhookWindowsHook": apiInfo("USER32.DLL", v_level_critical, xrkmonrun.run_UnhookWindowsHook)}


# ---------------------------------------------------------------------------
# URLMON.DLL --> DOWNLOAD
# ---------------------------------------------------------------------------


api_info_url = {
    "URLDownloadToFileW": apiInfo("URLMON.DLL", v_level_critical, xrkmonrun.run_URLDownloadToFileW),
    "URLDownloadW": apiInfo("URLMON.DLL", v_level_optional, xrkmonrun.run_URLDownloadW),
    "URLDownloadToCacheFileW": apiInfo("URLMON.DLL", v_level_optional, xrkmonrun.run_URLDownloadToCacheFileW)}


# ---------------------------------------------------------------------------
# KERNEL32.DLL --> RESOURCE
# ---------------------------------------------------------------------------


api_info_resc = {
    "FindResourceA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_FindResourceA),
    "FindResourceW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_FindResourceW),
    "FindResourceExA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_FindResourceExA),
    "FindResourceExW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_FindResourceExW),
    "LoadResource": apiInfo("KERNEL32.DLL", v_level_middle, xrkmonrun.run_LoadResource),
    "UpdateResourceW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_UpdateResourceW)}


# ---------------------------------------------------------------------------
# ADVAPI32.DLL --> SERVICE
# ---------------------------------------------------------------------------


api_info_svc = {
    "OpenSCManagerA": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_OpenSCManagerA),
    "OpenSCManagerW": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_OpenSCManagerW),
    "RegisterServiceCtrlHandlerW": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_RegisterServiceCtrlHandlerW),
    "RegisterServiceCtrlHandlerExW": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_RegisterServiceCtrlHandlerExW),
    "StartServiceCtrlDispatcherA": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_StartServiceCtrlDispatcherA),
    "StartServiceCtrlDispatcherW": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_StartServiceCtrlDispatcherW),
    "CreateServiceA": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CreateServiceA),
    "CreateServiceW": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CreateServiceW),
    "OpenServiceA": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_OpenServiceA),
    "OpenServiceW": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_OpenServiceW),
    "DeleteService": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_DeleteService),
    "StartServiceA": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_StartServiceA),
    "StartServiceW": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_StartServiceW),
    "ControlService": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_ControlService),
    "GetServiceDisplayNameA": apiInfo("ADVAPI32.DLL", v_level_optional, xrkmonrun.run_GetServiceDisplayNameA),
    "GetServiceDisplayNameW": apiInfo("ADVAPI32.DLL", v_level_optional, xrkmonrun.run_GetServiceDisplayNameW),
    "GetServiceKeyNameA": apiInfo("ADVAPI32.DLL", v_level_optional, xrkmonrun.run_GetServiceKeyNameA),
    "GetServiceKeyNameW": apiInfo("ADVAPI32.DLL", v_level_optional, xrkmonrun.run_GetServiceKeyNameW)}


# ---------------------------------------------------------------------------
# ADVAPI32.DLL --> EVENT LOG
# ---------------------------------------------------------------------------


api_info_evt_log = {
    "OpenEventLogA": apiInfo("ADVAPI32.DLL", v_level_optional, xrkmonrun.run_OpenEventLogA),
    "OpenEventLogW": apiInfo("ADVAPI32.DLL", v_level_optional, xrkmonrun.run_OpenEventLogW),
    "ClearEventLogW": apiInfo("ADVAPI32.DLL", v_level_optional, xrkmonrun.run_ClearEventLogW)}


# ---------------------------------------------------------------------------
# ADVAPI32.DLL --> PRIVILEDGES
# ---------------------------------------------------------------------------


api_info_priviledges = {
    "AdjustTokenPrivileges": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_AdjustTokenPrivileges),
    "LookupPrivilegeDisplayNameW": apiInfo("ADVAPI32.DLL", v_level_optional, xrkmonrun.run_LookupPrivilegeDisplayNameW),
    "LookupPrivilegeNameW": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_LookupPrivilegeNameW),
    "LookupPrivilegeValueW": apiInfo("ADVAPI32.DLL", v_level_optional, xrkmonrun.run_LookupPrivilegeValueW)}


# ---------------------------------------------------------------------------
# ADVAPI32.DLL --> CRYPTO
# ---------------------------------------------------------------------------


api_info_crypto = {
    "CryptAcquireContextA": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptAcquireContextA),
    "CryptReleaseContext": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptReleaseContext),
    "CryptSetProvParam": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptSetProvParam),
    "CryptGetProvParam": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptGetProvParam),
    "CryptCreateHash": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptCreateHash),
    "CryptHashData": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptHashData),
    "CryptGetHashParam": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptGetHashParam),
    "CryptSetHashParam": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptSetHashParam),
    "CryptHashSessionKey": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptHashSessionKey),
    "CryptDestroyHash": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptDestroyHash),
    "CryptGenRandom": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptGenRandom),
    "CryptDeriveKey": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptDeriveKey),
    "CryptGenKey": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptGenKey),
    "CryptDestroyKey": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptDestroyKey),
    "CryptImportKey": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptImportKey),
    "CryptExportKey": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptExportKey),
    "CryptGetKeyParam": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptGetKeyParam),
    "CryptSetKeyParam": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptSetKeyParam),
    "CryptGetUserKey": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptGetUserKey),
    "CryptSignHashA": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptSignHashA),
    "CryptSignHashW": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptSignHashW),
    "CryptVerifySignatureA": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptVerifySignatureA),
    "CryptVerifySignatureW": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptVerifySignatureW),
    "CryptEncrypt": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptEncrypt),
    "CryptDecrypt": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptDecrypt),
    "CryptDuplicateHash": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptDuplicateHash),
    "CryptDuplicateKey": apiInfo("ADVAPI32.DLL", v_level_critical, xrkmonrun.run_CryptDuplicateKey)}


# ---------------------------------------------------------------------------
# KERNEL32.DLL/NTDLL.DLL --> ALLOC
# ---------------------------------------------------------------------------
# "GlobalAlloc": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GlobalAlloc),
# "GlobalReAlloc": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GlobalReAlloc),
# "HeapAlloc": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_HeapAlloc),
# "HeapReAlloc": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_HeapReAlloc),


api_info_alloc = {
    "RtlAllocateHeap": apiInfo("NTDLL.DLL", v_level_optional, xrkmonrun.run_RtlAllocateHeap),
    "RtlReAllocateHeap": apiInfo("NTDLL.DLL", v_level_optional, xrkmonrun.run_RtlReAllocateHeap),
    "LocalAlloc": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_LocalAlloc),
    "VirtualAlloc": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_VirtualAlloc),
    "VirtualAllocEx": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_VirtualAllocEx)}


# ---------------------------------------------------------------------------
# OLE32.DLL --> COM
# ---------------------------------------------------------------------------


api_info_com = {
    "CoInitializeEx": apiInfo("OLE32.DLL", v_level_critical, xrkmonrun.run_CoInitializeEx),
    "CoCreateInstanceEx": apiInfo("OLE32.DLL", v_level_critical, xrkmonrun.run_CoCreateInstanceEx)}


# ---------------------------------------------------------------------------
# KERNEL32.DLL/NTDLL.DLL --> STRING
# ---------------------------------------------------------------------------


api_info_string = {
    "lstrcatA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_lstrcatA),
    "lstrcatW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_lstrcatW),
    "lstrcmpA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_lstrcmpA),
    "lstrcmpW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_lstrcmpW),
    "lstrcmpiA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_lstrcmpiA),
    "lstrcmpiW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_lstrcmpiW),
    "lstrcpyA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_lstrcpyA),
    "lstrcpyW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_lstrcpyW),
    "lstrcpynA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_lstrcpynA),
    "lstrcpynW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_lstrcpynW),
    "lstrlenA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_lstrlenA),
    "lstrlenW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_lstrlenW),
    "RtlInitString": apiInfo("NTDLL.DLL", v_level_optional, xrkmonrun.run_RtlInitString),
    "RtlInitAnsiString": apiInfo("NTDLL.DLL", v_level_optional, xrkmonrun.run_RtlInitAnsiString),
    "RtlInitUnicodeString": apiInfo("NTDLL.DLL", v_level_optional, xrkmonrun.run_RtlInitUnicodeString),
    "RtlInitUnicodeStringEx": apiInfo("NTDLL.DLL", v_level_optional, xrkmonrun.run_RtlInitUnicodeStringEx),
    "RtlIsDosDeviceName_U": apiInfo("NTDLL.DLL", v_level_optional, xrkmonrun.run_RtlIsDosDeviceName_U),
    "RtlDosPathNameToNtPathName_U": apiInfo("NTDLL.DLL", v_level_optional, xrkmonrun.run_RtlDosPathNameToNtPathName_U),
    "wnsprintfA": apiInfo("SHLWAPI.DLL", v_level_optional, xrkmonrun.run_wnsprintfA),
    "wnsprintfW": apiInfo("SHLWAPI.DLL", v_level_optional, xrkmonrun.run_wnsprintfW)}


# ---------------------------------------------------------------------------
# USER32.DLL --> WIN
# ---------------------------------------------------------------------------


api_info_win = {
    "DialogBoxParamA": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_DialogBoxParamA),
    "DialogBoxParamW": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_DialogBoxParamW),
    "MessageBoxTimeoutW": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_MessageBoxTimeoutW),
    "MessageBoxIndirectA": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_MessageBoxIndirectA),
    "MessageBoxIndirectW": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_MessageBoxIndirectW),
    "RegisterClassA": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_RegisterClassA),
    "RegisterClassW": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_RegisterClassW),
    "RegisterClassExA": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_RegisterClassExA),
    "RegisterClassExW": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_RegisterClassExW),
    "CreateWindowExA": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_CreateWindowExA),
    "CreateWindowExW": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_CreateWindowExW),
    "CreateWindowStationA": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_CreateWindowStationA),
    "CreateWindowStationW": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_CreateWindowStationW),
    "DispatchMessageA": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_DispatchMessageA),
    "DispatchMessageW": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_DispatchMessageW),
    "PeekMessageA": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_PeekMessageA),
    "PeekMessageW": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_PeekMessageW),
    "PostMessageA": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_PostMessageA),
    "PostMessageW": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_PostMessageW),
    "PostQuitMessage": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_PostQuitMessage),
    "SendMessageA": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_SendMessageA),
    "SendMessageW": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_SendMessageW),
    "RegisterServicesProcess": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_RegisterServicesProcess)}


# ---------------------------------------------------------------------------
# KERNEL32.DLL --> ATOM
# ---------------------------------------------------------------------------


api_info_atoms = {
    "InitAtomTable": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_InitAtomTable),
    "AddAtomA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_AddAtomA),
    "AddAtomW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_AddAtomW),
    "DeleteAtom": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_DeleteAtom),
    "FindAtomA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_FindAtomA),
    "FindAtomW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_FindAtomW),
    "GetAtomNameA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetAtomNameA),
    "GetAtomNameW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetAtomNameW),
    "GlobalAddAtomA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GlobalAddAtomA),
    "GlobalAddAtomW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GlobalAddAtomW),
    "GlobalDeleteAtom": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GlobalDeleteAtom),
    "GlobalFindAtomA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GlobalFindAtomA),
    "GlobalFindAtomW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GlobalFindAtomW),
    "GlobalGetAtomNameA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GlobalGetAtomNameA),
    "GlobalGetAtomNameW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GlobalGetAtomNameW)}


# ---------------------------------------------------------------------------
# USER32.DLL --> CLIPBOARD
# ---------------------------------------------------------------------------


api_info_clipboard = {
    "EmptyClipboard": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_EmptyClipboard),
    "GetClipboardData": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_GetClipboardData),
    "OpenClipboard": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_OpenClipboard),
    "SetClipboardData": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_SetClipboardData)}


# ---------------------------------------------------------------------------
# USER32.DLL/GID32.DLL --> KEY/MOUSE/SCREEN
# ---------------------------------------------------------------------------


api_info_key_mouse_screen = {
    "GetKeyboardState": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_GetKeyboardState),
    "SetKeyboardState": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_SetKeyboardState),
    "GetAsyncKeyState": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_GetAsyncKeyState),
    "GetKeyState": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_GetKeyState),
    "keybd_event": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_keybd_event),
    "mouse_event": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_mouse_event),
    "GetCursorPos": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_GetCursorPos),
    "GetWindowRect": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_GetWindowRect),
    "ScreenToClient": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_ScreenToClient),
    "ClientToScreen": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_ClientToScreen),
    "CreateCompatibleDC": apiInfo("GDI32.DLL", v_level_optional, xrkmonrun.run_CreateCompatibleDC),
    "CreateCompatibleBitmap": apiInfo("GDI32.DLL", v_level_optional, xrkmonrun.run_CreateCompatibleBitmap),
    "BitBlt": apiInfo("GDI32.DLL", v_level_optional, xrkmonrun.run_BitBlt)}


# ---------------------------------------------------------------------------
# KERNEL32.DLL/SHELL32.DLL --> OTHER
# ---------------------------------------------------------------------------


api_info_others = {
    "GetProcAddress": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_GetProcAddress),
    "LoadLibraryExW": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_LoadLibraryExW),
    "VirtualProtectEx": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_VirtualProtectEx),
    "SleepEx": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_SleepEx),
    "IsDebuggerPresent": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_IsDebuggerPresent),
    "QueueUserAPC": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_QueueUserAPC),
    "RaiseException": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_RaiseException),
    "GetComputerNameW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetComputerNameW),
    "GetComputerNameExW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetComputerNameExW),
    "SetComputerNameW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_SetComputerNameW),
    "SetComputerNameExW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_SetComputerNameExW),
    "GetModuleFileNameW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetModuleFileNameW),
    "GetVersion": apiInfo("KERNEL32.DLL", v_level_middle, xrkmonrun.run_GetVersion),
    "GetVersionExW": apiInfo("KERNEL32.DLL", v_level_middle, xrkmonrun.run_GetVersionExW),
    "CreateMailslotW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_CreateMailslotW),
    "GetCommandLineA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetCommandLineA),
    "GetCommandLineW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetCommandLineW),
    "GetStartupInfoA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetStartupInfoA),
    "GetStartupInfoW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetStartupInfoW),
    "OutputDebugStringA": apiInfo("KERNEL32.DLL", v_level_middle, xrkmonrun.run_OutputDebugStringA),
    "SetSystemPowerState": apiInfo("KERNEL32.DLL", v_level_middle, xrkmonrun.run_SetSystemPowerState),
    "SetSystemTime": apiInfo("KERNEL32.DLL", v_level_middle, xrkmonrun.run_SetSystemTime),
    "SetSystemTimeAdjustment": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_SetSystemTimeAdjustment),
    "SetErrorMode": apiInfo("KERNEL32.DLL", v_level_middle, xrkmonrun.run_SetErrorMode),
    "SetUnhandledExceptionFilter": apiInfo("KERNEL32.DLL", v_level_critical, xrkmonrun.run_SetUnhandledExceptionFilter),
    "ShellExecuteExW": apiInfo("SHELL32.DLL", v_level_critical, xrkmonrun.run_ShellExecuteExW),
    "GetSystemTime": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetSystemTime),
    "GetTempPathW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetTempPathW),
    "GetSystemDirectoryA": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetSystemDirectoryA),
    "GetSystemDirectoryW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetSystemDirectoryW),
    "WaitForSingleObjectEx": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_WaitForSingleObjectEx),
    "WaitForMultipleObjectsEx": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_WaitForMultipleObjectsEx),
    "SetProcessDEPPolicy": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_SetProcessDEPPolicy),
    "CreateEventW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_CreateEventW),
    "OpenEventW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_OpenEventW),
    "SetEvent": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_SetEvent),
    "ResetEvent": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_ResetEvent),
    "PulseEvent": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_PulseEvent),
    "DisableThreadLibraryCalls": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_DisableThreadLibraryCalls),
    "FileTimeToSystemTime": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_FileTimeToSystemTime),
    "SystemTimeToFileTime": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_SystemTimeToFileTime),
    "GetModuleHandleW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetModuleHandleW),
    "GetModuleHandleExW": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetModuleHandleExW),
    "GetTickCount": apiInfo("KERNEL32.DLL", v_level_optional, xrkmonrun.run_GetTickCount),
    "SetProcessWindowStation": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_SetProcessWindowStation),
    "OpenDesktopA": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_OpenDesktopA),
    "OpenDesktopW": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_OpenDesktopW),
    "SetThreadDesktop": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_SetThreadDesktop),
    "OpenWindowStationA": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_OpenWindowStationA),
    "OpenWindowStationW": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_OpenWindowStationW),
    "SetTimer": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_SetTimer),
    "SetSystemTimer": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_SetSystemTimer),
    "KillTimer": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_KillTimer),
    "KillSystemTimer": apiInfo("USER32.DLL", v_level_optional, xrkmonrun.run_KillSystemTimer),
    "RasGetConnectStatusW": apiInfo("RASAPI32.DLL", v_level_optional, xrkmonrun.run_RasGetConnectStatusW),
    "OpenProcessToken": apiInfo("ADVAPI32.DLL", v_level_optional, xrkmonrun.run_OpenProcessToken),
    "WNetUseConnectionW": apiInfo("MPR.DLL", v_level_optional, xrkmonrun.run_WNetUseConnectionW)}


# ---------------------------------------------------------------------------
# ALL
# ---------------------------------------------------------------------------


api_cat_dict = {
    "dns": api_info_dns,
    "ws2_32": api_info_ws2_32,
    "wininet": api_info_wininet,
    "winhttp": api_info_winhttp,
    "file_map": api_info_file_map,
    "file": api_info_file,
    "proc": api_info_proc,
    "reg": api_info_reg,
    "profile": api_info_profile,
    "mutex": api_info_mutex,
    "volume": api_info_volume,
    "pipe": api_info_pipe,
    "evn": api_info_evn,
    "hook": api_info_hook,
    "url": api_info_url,
    "resc": api_info_resc,
    "svc": api_info_svc,
    "evt_log": api_info_evt_log,
    "priviledges": api_info_priviledges,
    "crypto": api_info_crypto,
    "alloc": api_info_alloc,
    "com": api_info_com,
    "str": api_info_string,
    "win": api_info_win,
    "atom": api_info_atoms,
    "clipboard": api_info_clipboard,
    "key_mouse_screen": api_info_key_mouse_screen,
    "others": api_info_others}


def get_all_api_info():
    """
        get all apiInfos

        @return: DICT : a dict of all api info: {api_name: apiInfo, api_name: apiInfo}
    """
    ret = {}

    for (d, x) in api_cat_dict.items():
        ret = dict(ret.items() + x.items())

    return ret


def iter_all_api_info():
    """
        yield all apiInfo
    """
    for cat_name in api_cat_dict:
        for api_name in api_cat_dict[cat_name]:
            yield api_cat_dict[cat_name][api_name]


def get_all_api_cats():
    """
        get all category names

        @return: LIST : a list of category names
    """
    return api_cat_dict.keys()


def iter_all_api_cats():
    """
        yield all category names
    """
    for cat_name in api_cat_dict:
        yield cat_name


def get_all_api_names():
    """
        get all api names

        @return: LIST : a list of api names
    """
    return get_all_api_info().keys()


def iter_all_api_names():
    """
        yield all api names
    """
    for cat_name in api_cat_dict:
        for api_name in api_cat_dict[cat_name]:
            yield api_name

# ---------------------------------------------------------------------------
# misc
# ---------------------------------------------------------------------------


def get_api_level(api_name):
    """
        get pre-defined level of api

        @param: api_name : STRING : api name

        @return: STRING: api level string
        @raise: Exception
    """
    api_info_all = get_all_api_info()

    if api_name not in api_info_all:
        raise Exception("invalid api name: %s" % api_name)

    return __level_value_to_str(api_info_all[api_name].level)


def get_dll_name_by_api_name(api_name):
    """
        get dll name that api belongs to

        @param: api_name : STRING : api name

        @return: STRING: dll name
        @raise: Exception
    """
    api_info_all = get_all_api_info()

    if api_name not in api_info_all:
        raise Exception("invalid api name: %s" % api_name)

    return api_info_all[api_name].dll_name


def get_dll_api_dict_by_api_names(api_names):
    """
        generate a dict of dll and api names by api names

        @param: api_names : LIST : a list of api names

        @return: DICT : a dict, like this: {dll_name: {api_name, api_name, ...},
                                            dll_name: {api_name, api_name, ...},
                                            ...}
    """
    ret = {}

    for api_name in api_names:

        dll_name = get_dll_name_by_api_name(api_name).lower()
        if dll_name not in ret:
            ret[dll_name] = []

        ret[dll_name].append(api_name)

    return ret


def get_run_cbk_by_api_name(api_name):
    """
        get run cbk by api name

        @param: api_name : STRING : api name

        @return: obj of method
        @raise: Exception
    """
    api_info_all = get_all_api_info()

    if api_name not in api_info_all:
        raise Exception("invalid api name: %s" % api_name)

    return api_info_all[api_name].run_cbk


def get_apis_by_cat(cat_apis, level="default"):
    """
        get api list from cat_apis, by level

        @param: cat_apis : DICT   : dict pair: {api_name: apiInfo, api_name: apiInfo, ...}
        @param: level    : STRING : level string

        @return: LIST: a list of api names: [api_name, api_name, ...]
    """
    l = __level_str_to_value(level)

    apis = []
    for (d, x) in cat_apis.items():
        if x.level <= l:
            apis.append(d)

    return apis


def get_apis_by_cats(cats, level="default"):
    """
        get api list by categories

        @param: cats  : LIST   : a list of category strings
        @param: level : STRING : level string

        @return: LIST: a list of api name strings
        @raise: Exception
    """
    if len(cats) == 0:
        raise Exception("cats can't be empty")

    if "all" in cats:

        if len(cats) != 1:
            xrklog.error("\"all\" in categories, no need to specify other category")

        return get_all_api_names()

    else:

        ret = []
        for cat in cats:
            if cat not in api_cat_dict:
                xrklog.error("invalid cat: %s" % cat)
            else:
                ret = ret + get_apis_by_cat(api_cat_dict[cat], level)

        return ret


def get_apis_by_cats_and_apis(cats_or_apis, level="default"):
    """
        get apis list from lines, each line might be cat or api

        @param: cats_or_apis : LIST   : a list of api names or category names
        @param: level        : STRING : level string

        @return: LIST: api name list
    """
    api_info_all = get_all_api_info()
    apis = []
    for cat_or_api in cats_or_apis:

        if cat_or_api in api_cat_dict:
            apis = xrkutil.merge_list(apis, get_apis_by_cat(cat_or_api, level=level))[0]

        elif cat_or_api in api_info_all:
            apis = xrkutil.add_to_set(apis, cat_or_api)[0]

        else:
            xrklog.error("invalid cat or api: %s" % cat_or_api)

    return apis


def get_apis_by_dlls(dll_names):
    """
        get api names from dll names

        @param: dll_names : LIST : a list of dll names

        @return: LIST : a list of api names
    """
    # lower dll names
    dlls = []
    for dll_name in dll_names:
        dlls.append(dll_name.lower())

    ret = []
    api_info_all = get_all_api_info()

    for (d, x) in api_info_all.items():
        if x.dll_name.lower() in dlls:
            ret.append(d)

    return ret


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
