# -*- coding: utf-8 -*-

"""
  xrk constants
"""

import os
import sys
import inspect

try:
    # import x_util
    pass
except:
    this_path = os.path.split(os.path.realpath(inspect.stack()[-1][1]))[0]
    sys.path.append(this_path)
    try:
        # import x_util
        pass
    except:
        assert False


"""

RegSetValueA-->RegSetValueExA-->BaseRegSetValue/LocalBaseRegSetValue
RegSetValueW-->RegSetValueExW-->BaseRegSetValue/LocalBaseRegSetValue
RegQueryValueA-->RegQueryValueExA-->BaseRegQueryValue/LocalBaseRegQueryValue
RegQueryValueW-->RegQueryValueExW-->BaseRegQueryValue/LocalBaseRegQueryValue
RegCreateKeyA-->RegCreateKeyExA-->BaseRegCreateKey/LocalBaseRegCreateKey
RegCreateKeyW-->RegCreateKeyExW-->BaseRegCreateKey/LocalBaseRegCreateKey
RegConnectRegistryA-->RegConnectRegistryW
RegEnumKeyA-->RegEnumKeyExA-->BaseRegEnumKey/LocalBaseRegEnumKey
RegOpenKeyA-->RegOpenKeyExA-->BaseRegOpenKey/LocalBaseRegOpenKey
RegOpenKeyW-->RegOpenKeyExW-->BaseRegOpenKey/LocalBaseRegOpenKey
InternetOpenW-->InternetOpenA
InternetFindNextFileW-->InternetFindNextFileA-->InternalInternetFindNextFileA
InternetConnectW-->InternetConnectA-->FtpConnect/HttpConnect
InternetCrackUrlW-->InternetCrackUrlA-->CrackUrl
InternetOpenUrlW-->InternetOpenUrlA
InternetGetCookieA-->InternetGetCookieExA-->InternetGetCookieExW->InternetGetCookieEx2
InternetGetCookieW-->InternetGetCookieExW==>>||
InternetSetCookieW-->InternetSetCookieA-->InternalInternetSetCookie
InternetReadFileExW-->InternetReadFileExA
HttpAddRequestHeadersW-->HttpAddRequestHeadersA-->wHttpAddRequestHeaders
socket-->WSASocketW
WSASocketA-->WSASocketW
CreateProcessA-->CreateProcessInternalA-->CreateProcessInternalW
CreateProcessW-->CreateProcessInternalW
WinExec-->CreateProcessInternalA==>>||
# CreateThread-->CreateRemoteThread==>>||
Process32First-->Process32FirstW-->NtMapViewOfSection/NtUnmapViewOfSection(ntdll)
Process32Next-->Process32NextW-->NtMapViewOfSection/NtUnmapViewOfSection(ntdll)
Module32First-->Module32FirstW-->NtMapViewOfSection/NtUnmapViewOfSection(ntdll)
Module32Next-->Module32NextW-->NtMapViewOfSection/NtUnmapViewOfSection(ntdll)
Thread32First-->NtMapViewOfSection/NtUnmapViewOfSection(ntdll)
Thread32Next-->NtMapViewOfSection/NtUnmapViewOfSection(ntdll)
Toolhelp32ReadProcessMemory-->OpenProcess/ReadProcessMemory
CreateFileMappingA-->CreateFileMappingW-->NtCreateSection(ntdll)
OpenFileMappingA-->OpenFileMappingW-->NtOpenSection(ntdll)
CreateFileA-->CreateFileW-->NtCreateFile(ntdll)
OpenFile-->CreateFileA==>||
_lopen-->CreateFileA==>>||
_lcreat-->CreateFileA==>>||
_lread-->ReadFile==>>||
_lwrite-->WriteFile==>>||
CopyFileA-->CopyFileExW-->BasepCopyFileExW-->BaseCopyStream
CopyFileW-->CopyFileExW==>>||
CopyFileExA-->CopyFileExW==>>||
MoveFileA-->MoveFileWithProgressA-->MoveFileWithProgressW-->BasepCopyFileExW-->BaseCopyStream
MoveFileW-->MoveFileWithProgressW==>||
MoveFileExA-->MoveFileWithProgressA==>>||
MoveFileExW-->MoveFileWithProgressW==>>||
CreateDirectoryA-->CreateDirectoryW-->NtCreateFile(ntdll)
CreateDirectoryExA-->CreateDirectoryExW-->NtOpenFile/NtCreateFile(ntdll)
RemoveDirectoryA-->RemoveDirectoryW-->NtOpenFile/NtSetInformationFile(ntdll)
ReplaceFileA-->ReplaceFileW-->NtOpenFile/NtSetInformationFile(ntdll)
DeleteFileA-->DeleteFileW-->NtOpenFile(ntdll)
FindFirstFileA-->FindFirstFileExW-->NtOpenFile/NtQueryDirectoryFile(ntdll)
FindFirstFileW-->FindFirstFileExW==>||
FindFirstFileExA-->FindFirstFileExW==>||
FindNextFileA-->FindNextFileW-->NtQueryDirectoryFile(ntdll)
SetFileAttributesA-->SetFileAttributesW-->NtOpenFile/NtSetInformationFile(ntdll)
GetFileSize-->GetFileSizeEx-->NtQueryInformationFile
GetPrivateProfileIntA-->GetPrivateProfileStringA-->BaseDllReadWriteIniFile
GetPrivateProfileSectionNamesA-->GetPrivateProfileStringA==>>||
GetPrivateProfileStructA-->GetPrivateProfileStringA==>>||
GetProfileStringA-->GetPrivateProfileStringA==>>||
GetProfileIntA-->GetPrivateProfileIntA==>>||
GetPrivateProfileIntW-->GetPrivateProfileStringW-->BaseDllReadWriteIniFile
GetPrivateProfileSectionNamesW-->GetPrivateProfileStringW==>>||
GetPrivateProfileStructW-->GetPrivateProfileStringW==>>||
GetProfileStringW-->GetPrivateProfileStringW==>>||
GetProfileIntW-->GetPrivateProfileIntW==>>||
GetProfileSectionA-->GetPrivateProfileSectionA==>>||
GetProfileSectionW-->GetPrivateProfileSectionW==>>||
WriteProfileSectionA-->WritePrivateProfileSectionA==>>||
WriteProfileSectionW-->WritePrivateProfileSectionW==>>||
WritePrivateProfileStructA-->WritePrivateProfileStringA
WriteProfileStringA-->WritePrivateProfileStringA==>>||
WritePrivateProfileStructW-->WritePrivateProfileStringW
WriteProfileStringW-->WritePrivateProfileStringW==>>||
SetWindowsHookExA-->SetWindowsHookExAW
SetWindowsHookExW-->SetWindowsHookExAW
URLDownloadA-->URLDownloadW
URLDownloadToFileA-->URLDownloadToFileW-->CFileDownload::CFileDownload
URLDownloadToCacheFileA-->URLDownloadToCacheFileW-->CCacheFileDownload::CCacheFileDownload
RegisterServiceCtrlHandlerA-->RegisterServiceCtrlHandlerW-->RegisterServiceCtrlHandlerHelp
RegisterServiceCtrlHandlerExA-->RegisterServiceCtrlHandlerExW-->RegisterServiceCtrlHandlerHelp
CreateMutexA-->CreateMutexW-->NtCreateMutant(ntdll)
OpenMutexA-->OpenMutexW-->NtOpenMutant(ntdll)
ClearEventLogA-->ClearEventLogW-->ElfClearEventLogFileW
LookupPrivilegeDisplayNameA-->LookupPrivilegeDisplayNameW-->LsaLookupPrivilegeDisplayName
LookupPrivilegeNameA-->LookupPrivilegeNameW-->LsaLookupPrivilegeName
LookupPrivilegeValueA-->LookupPrivilegeValueW-->LsaLookupPrivilegeValue
UpdateResourceA-->UpdateResourceW-->AddResource
GetDiskFreeSpaceA-->GetDiskFreeSpaceW-->NtOpenFile/NtQueryVolumeInformationFile(ntdll)
GetDiskFreeSpaceExA-->GetDiskFreeSpaceExW-->NtOpenFile/NtQueryVolumeInformationFile(ntdll)
GetDriveTypeA-->GetDriveTypeW-->NtOpenFile/NtQueryVolumeInformationFile(ntdll)
GetVolumeInformationA-->GetVolumeInformationW-->NtOpenFile/NtQueryVolumeInformationFile(ntdll)
GetVolumeNameForVolumeMountPointA-->GetVolumeNameForVolumeMountPointW-->BasepGetVolumeNameForVolumeMountPoint
FindFirstVolumeA-->FindFirstVolumeW-->CreateFileW/DeviceIoControl/FindNextVolumeW
FindNextVolumeA-->FindNextVolumeW
GetVolumePathNameA-->GetVolumePathNameW-->GetFullPathNameW
GetVolumePathNamesForVolumeNameA-->GetVolumePathNamesForVolumeNameW-->CreateFileW/DeviceIoControl
CallNamedPipeA-->CallNamedPipeW
CreateNamedPipeA-->CreateNamedPipeW-->NtCreateNamedPipeFile(ntdll)
WaitNamedPipeA-->WaitNamedPipeW-->NtOpenFile/NtFsControlFile(ntdll)、
VirtualProtect-->VirtualProtectEx-->NtProtectVirtualMemory(ntdll)
LoadLibraryA-->LoadLibraryExA-->LoadLibraryExW-->LdrLoadDll(ntdll)
LoadLibraryW-->LoadLibraryExW==>>||
ShellExecuteA-->ShellExecuteExA-->ShellExecuteExW-->ShellExecuteNormal
ShellExecuteW-->ShellExecuteExW==>>||
RealShellExecuteA-->RealShellExecuteExA-->ShellExecuteExA==>>||
RealShellExecuteW-->RealShellExecuteExW-->ShellExecuteExW==>>||
WOWShellExecute-->RealShellExecuteExA==>>||
ShellExec_RunDLLA-->_ShellExec_RunDLL-->ShellExecuteExW
ShellExec_RunDLLW-->_ShellExec_RunDLL==>>||
GetComputerNameA-->GetComputerNameW-->NtOpenKey/NtCreateKey(ntdll)
GetComputerNameExA-->GetComputerNameExW-->BasepGetNameFromReg
SetComputerNameA-->SetComputerNameW-->NtOpenKey/NtSetValueKey(ntdll)
SetComputerNameExA-->SetComputerNameExW-->BaseSetNetbiosName/BaseSetNetbiosName/BaseSetDnsName
GetModuleFileNameA-->GetModuleFileNameW
GetVersionExA-->GetVersionExW
CreateMailslotA-->CreateMailslotW-->NtCreateMailslotFile(ntdll)
OutputDebugStringW-->OutputDebugStringA-->RaiseException
"""

"""
CreateRemoteThread": ["CreateThread"],
for some reason, imm cannot decode this correctly. so, we ignore it.
"""


api_name_to_direct_caller_name = {"RegSetValueExA": ["RegSetValueA"],
                                  "RegSetValueExW": ["RegSetValueW"],
                                  "RegQueryValueExA": ["RegQueryValueA"],
                                  "RegQueryValueExW": ["RegQueryValueW"],
                                  "RegCreateKeyExA": ["RegCreateKeyA"],
                                  "RegCreateKeyExW": ["RegCreateKeyW"],
                                  "RegConnectRegistryW": ["RegConnectRegistryA"],
                                  "RegEnumKeyExA": ["RegEnumKeyA"],
                                  "RegOpenKeyExA": ["RegOpenKeyA"],
                                  "RegOpenKeyExW": ["RegOpenKeyW"],
                                  "InternetOpenA": ["InternetOpenW"],
                                  "InternetFindNextFileA": ["InternetFindNextFileW"],
                                  "InternetConnectA": ["InternetConnectW"],
                                  "InternetCrackUrlA": ["InternetCrackUrlW"],
                                  "InternetOpenUrlA": ["InternetOpenUrlW"],
                                  "InternetGetCookieExW": ["InternetGetCookieExA", "InternetGetCookieW"],
                                  "InternetGetCookieExA": ["InternetGetCookieA"],
                                  "InternetSetCookieA": ["InternetSetCookieW"],
                                  "InternetReadFileExA": ["InternetReadFileExW"],
                                  "HttpAddRequestHeadersA": ["HttpAddRequestHeadersW"],
                                  "WSASocketW": ["socket", "WSASocketA"],
                                  "CreateProcessInternalW": ["CreateProcessW", "CreateProcessInternalA"],
                                  "CreateProcessInternalA": ["CreateProcessA", "WinExec"],
                                  "Process32FirstW": ["Process32First"],
                                  "Process32NextW": ["Process32Next"],
                                  "Module32FirstW": ["Module32First"],
                                  "Module32NextW": ["Module32Next"],
                                  "Thread32First": ["Thread32Next"],
                                  "OpenProcess": ["Toolhelp32ReadProcessMemory"],
                                  "ReadProcessMemory": ["Toolhelp32ReadProcessMemory"],
                                  "CreateFileMappingW": ["CreateFileMappingA"],
                                  "OpenFileMappingW": ["OpenFileMappingA"],
                                  "CreateFileW": ["CreateFileA", "FindFirstVolumeW", "GetVolumePathNamesForVolumeNameW"],
                                  "CreateFileA": ["OpenFile", "_lopen", "_lcreat"],
                                  "ReadFile": ["_lread"],
                                  "WriteFile": ["_lwrite"],
                                  "CopyFileExW": ["CopyFileA", "CopyFileW", "CopyFileExA"],
                                  "MoveFileWithProgressW": ["MoveFileW", "MoveFileExW", "MoveFileWithProgressA"],
                                  "MoveFileWithProgressA": ["MoveFileA", "MoveFileExA"],
                                  "CreateDirectoryW": ["CreateDirectoryA"],
                                  "CreateDirectoryExW": ["CreateDirectoryExA"],
                                  "RemoveDirectoryW": ["RemoveDirectoryA"],
                                  "ReplaceFileW": ["ReplaceFileA"],
                                  "DeleteFileW": ["DeleteFileA"],
                                  "FindFirstFileExW": ["FindFirstFileA", "FindFirstFileW", "FindFirstFileExA"],
                                  "FindNextFileW": ["FindNextFileA"],
                                  "SetFileAttributesW": ["SetFileAttributesA"],
                                  "GetFileSizeEx": ["GetFileSize"],
                                  "GetPrivateProfileStringA": ["GetPrivateProfileIntA", "GetPrivateProfileSectionNamesA", "GetPrivateProfileStructA", "GetProfileStringA"],
                                  "GetPrivateProfileIntA": ["GetProfileIntA"],
                                  "GetPrivateProfileStringW": ["GetPrivateProfileIntW", "GetPrivateProfileSectionNamesW", "GetPrivateProfileStructW", "GetProfileStringW"],
                                  "GetPrivateProfileIntW": ["GetProfileIntW"],
                                  "GetPrivateProfileSectionA": ["GetProfileSectionA"],
                                  "GetPrivateProfileSectionW": ["GetProfileSectionW"],
                                  "WritePrivateProfileSectionA": ["WriteProfileSectionA"],
                                  "WritePrivateProfileSectionW": ["WriteProfileSectionW"],
                                  "WritePrivateProfileStringA": ["WritePrivateProfileStructA", "WriteProfileStringA"],
                                  "WritePrivateProfileStringW": ["WritePrivateProfileStructW", "WriteProfileStringW"],
                                  "SetWindowsHookExAW": ["SetWindowsHookExA", "SetWindowsHookExW"],
                                  "URLDownloadW": ["URLDownloadA"],
                                  "URLDownloadToFileW": ["URLDownloadToFileA"],
                                  "URLDownloadToCacheFileW": ["URLDownloadToCacheFileA"],
                                  "RegisterServiceCtrlHandlerW": ["RegisterServiceCtrlHandlerA"],
                                  "RegisterServiceCtrlHandlerExW": ["RegisterServiceCtrlHandlerExA"],
                                  "CreateMutexW": ["CreateMutexA"],
                                  "OpenMutexW": ["OpenMutexA"],
                                  "ClearEventLogW": ["ClearEventLogA"],
                                  "LookupPrivilegeDisplayNameW": ["LookupPrivilegeDisplayNameA"],
                                  "LookupPrivilegeNameW": ["LookupPrivilegeNameA"],
                                  "LookupPrivilegeValueW": ["LookupPrivilegeValueA"],
                                  "UpdateResourceW": ["UpdateResourceA"],
                                  "GetDiskFreeSpaceW": ["GetDiskFreeSpaceA"],
                                  "GetDiskFreeSpaceExW": ["GetDiskFreeSpaceExA"],
                                  "GetDriveTypeW": ["GetDriveTypeA"],
                                  "GetVolumeInformationW": ["GetVolumeInformationA"],
                                  "GetVolumeNameForVolumeMountPointW": ["GetVolumeNameForVolumeMountPointA"],
                                  "DeviceIoControl": ["FindFirstVolumeW", "GetVolumePathNamesForVolumeNameW"],
                                  "FindNextVolumeW": ["FindFirstVolumeW", "FindNextVolumeA"],
                                  "FindFirstVolumeW": ["FindFirstVolumeA"],
                                  "GetFullPathNameW": ["GetVolumePathNameW"],
                                  "GetVolumePathNameW": ["GetVolumePathNameA"],
                                  "GetVolumePathNamesForVolumeNameW": ["GetVolumePathNamesForVolumeNameA"],
                                  "CallNamedPipeW": ["CallNamedPipeA"],
                                  "CreateNamedPipeW": ["CreateNamedPipeA"],
                                  "WaitNamedPipeW": ["WaitNamedPipeA"],
                                  "VirtualProtectEx": ["VirtualProtect"],
                                  "LoadLibraryExW": ["LoadLibraryExA", "LoadLibraryW"],
                                  "LoadLibraryExA": ["LoadLibraryA"],
                                  "ShellExecuteExW": ["ShellExecuteW", "ShellExecuteExA", "RealShellExecuteExW", "_ShellExec_RunDLL"],
                                  "ShellExecuteExA": ["ShellExecuteA", "RealShellExecuteExA"],
                                  "RealShellExecuteExA": ["RealShellExecuteA", "WOWShellExecute"],
                                  "RealShellExecuteExW": ["RealShellExecuteW"],
                                  "_ShellExec_RunDLL": ["ShellExec_RunDLLA", "ShellExec_RunDLLW"],
                                  "GetComputerNameW": ["GetComputerNameA"],
                                  "GetComputerNameExW": ["GetComputerNameExA"],
                                  "SetComputerNameW": ["SetComputerNameA"],
                                  "SetComputerNameExW": ["SetComputerNameExA"],
                                  "GetModuleFileNameW": ["GetModuleFileNameA"],
                                  "GetVersionExW": ["GetVersionExA"],
                                  "CreateMailslotW": ["CreateMailslotA"],
                                  "OutputDebugStringA": ["OutputDebugStringW"]}


def api_name_to_api_callers(api_name):
    """
        get pre-defined caller apis names of specified api

        @param: api_name : STRING : api name

        @return: LIST : a list of api names
                 None
    """
    if api_name in api_name_to_direct_caller_name:
        return api_name_to_direct_caller_name[api_name]
    return None
