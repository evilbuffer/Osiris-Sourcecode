#pragma once
#include <Windows.h>
#include <TlHelp32.h>

typedef LPVOID(WINAPI* ptVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef HANDLE (WINAPI* ptOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
typedef BOOL (WINAPI* ptProcess32FirstW)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
typedef BOOL (WINAPI* ptProcess32NextW)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
typedef BOOL (WINAPI* ptWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T *lpNumberOfBytesWritten);
typedef LPVOID (WINAPI* ptVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI* ptVirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef BOOL (WINAPI* ptVirtualFreeEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef BOOL (WINAPI* ptSetThreadContext)(HANDLE hThread, const CONTEXT *lpContext);
typedef HANDLE (WINAPI* ptCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef BOOL (WINAPI* ptCloseHandle)(HANDLE hObject);
typedef HANDLE (WINAPI* ptCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);
typedef BOOL (WINAPI* ptCreateProcessW)(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef BOOL (WINAPI* ptVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect	);
typedef VOID (WINAPI* ptExitProcess)(UINT uExitCode);
typedef DWORD (WINAPI* ptGetModuleFileNameW)(HMODULE hModule,LPWSTR lpFilename,DWORD nSize);
typedef BOOL (WINAPI* ptDeleteFileW)(LPCWSTR lpFileName);
typedef VOID (WINAPI* ptSleep)(DWORD dwMilliseconds);
typedef HMODULE (WINAPI* ptLoadLibraryW)(LPCWSTR lpLibFileName);
typedef BOOL (WINAPI* ptIsWow64Process)(HANDLE hProcess, PBOOL Wow64Process);
typedef DWORD (WINAPI* ptGetCurrentProcessId)(VOID);
typedef UINT (WINAPI* ptGetWindowsDirectoryW)(LPWSTR lpBuffer, UINT uSize);
typedef DWORD (WINAPI* ptResumeThread)(HANDLE hThread);
typedef DWORD (WINAPI* ptQueueUserAPC)(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);
typedef UINT (WINAPI* ptGetSystemDirectoryW)(LPWSTR lpBuffer,UINT uSize);
typedef HANDLE (WINAPI* ptFindFirstFileW)(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
typedef BOOL (WINAPI* ptFindNextFileW)(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
typedef HANDLE (WINAPI* ptCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef HANDLE (WINAPI* ptCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,HANDLE hTemplateFile);
typedef BOOL (WINAPI* ptWriteFile)(HANDLE hFile, LPCVOID lpBuffer,DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten,LPOVERLAPPED lpOverlapped);
typedef BOOL (WINAPI* ptReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
typedef DWORD (WINAPI* ptGetFileSize)(HANDLE  hFile,LPDWORD lpFileSizeHigh);
typedef BOOL (WINAPI* ptGetVersionExW)(LPOSVERSIONINFOW lpVersionInformation);
typedef HANDLE (WINAPI* ptFindFirstVolumeW)(LPWSTR lpszVolumeName,DWORD cchBufferLength);
typedef BOOL (WINAPI* ptGetVolumeInformationW)(LPCWSTR lpRootPathName,LPWSTR lpVolumeNameBuffer,DWORD nVolumeNameSize,LPDWORD lpVolumeSerialNumber,LPDWORD lpMaximumComponentLength,LPDWORD lpFileSystemFlags,LPWSTR lpFileSystemNameBuffer,DWORD nFileSystemNameSize);
typedef BOOL (WINAPI* ptFindVolumeClose)(HANDLE hFindVolume);
typedef int (WINAPI* ptwsprintfA)(LPSTR,_Printf_format_string_ LPCSTR,...);
typedef int (WINAPI* ptMultiByteToWideChar)(UINT   CodePage,DWORD  dwFlags,LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr,int cchWideChar);
typedef HMODULE (WINAPI* ptGetModuleHandleW)( LPCWSTR lpModuleName);
typedef BOOL (WINAPI* ptFlushInstructionCache)(HANDLE hProcess, LPCVOID lpBaseAddress,SIZE_T dwSize);
typedef HANDLE (WINAPI* ptGetProcessHeap)(VOID);
typedef LPVOID (WINAPI* ptHeapAlloc)(HANDLE hHeap,DWORD dwFlags,SIZE_T dwBytes);
typedef BOOL (WINAPI* ptHeapFree)(HANDLE hHeap,DWORD dwFlags,LPVOID lpMem);
typedef HANDLE (WINAPI* ptGetCurrentProcess)(VOID);
typedef BOOL (WINAPI* ptThread32First)(HANDLE hSnapshot,LPTHREADENTRY32 lpte);
typedef BOOL (WINAPI* ptThread32Next)(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
typedef HANDLE (WINAPI* ptOpenMutexW)(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName);
typedef HANDLE (WINAPI* ptCreateMutexW)(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName);
typedef SIZE_T (WINAPI* ptVirtualQuery)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer,SIZE_T dwLength);
typedef HANDLE (WINAPI* ptCreateFileMappingW)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName);
typedef LPVOID (WINAPI* ptMapViewOfFile)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
typedef BOOL (WINAPI* ptUnmapViewOfFile)(LPCVOID lpBaseAddress);
typedef BOOL (WINAPI* ptDuplicateHandle)(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
typedef HANDLE (WINAPI* ptGetCurrentThread)(VOID);
typedef BOOL (WINAPI* ptFlushFileBuffers)(HANDLE hFile);
typedef BOOL (WINAPI* ptDisconnectNamedPipe)(HANDLE hNamedPipe);
typedef FARPROC (WINAPI* ptGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef void (WINAPI* ptRtlInitializeCriticalSection)(RTL_CRITICAL_SECTION* lpCriticalSection);
typedef void (WINAPI* ptRtlEnterCriticalSection)(RTL_CRITICAL_SECTION* lpCriticalSection);
typedef void (WINAPI* ptRtlLeaveCriticalSection)(RTL_CRITICAL_SECTION* lpCriticalSection);
typedef BOOL (WINAPI* ptCreateDirectoryW)(
				 __in     LPCWSTR lpPathName,
				 __in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes
				 );
typedef int (WINAPI* ptWideCharToMultiByte)(
					UINT     CodePage,
					DWORD    dwFlags,
					LPCWSTR  lpWideCharStr,
					int      cchWideChar,
					LPSTR   lpMultiByteStr,
					int      cbMultiByte,
					LPCSTR   lpDefaultChar,
					LPBOOL  lpUsedDefaultChar);
typedef BOOL (WINAPI* ptTerminateThread)(
							_Inout_ HANDLE hThread,
							_In_    DWORD  dwExitCode
							);
typedef DWORD (WINAPI* ptGetTickCount)(VOID);