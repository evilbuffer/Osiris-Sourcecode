#pragma once
#include "bot_structs.h"

typedef struct
{
	LPWSTR pwzProcessName;
	DWORD dwProcessID, dwProcessNameHash;
}utils_process_t;

typedef struct
{
	LPWSTR pwzModuleName;
	LPVOID lpBase;
	DWORD dwHash;
}utils_module_t;

enum PATHS
{
	PATH_APPDATA = 0,
	PATH_DESKTOP,
	PATH_STARTUP
};

DWORD WINAPI FindProcessIDByHash(DWORD dwHash);

BOOL WINAPI IsOperatingSystem64Bit();

LPWSTR WINAPI GetWinDir();
DWORD WINAPI GetWinDirEnd(void);

LPWSTR WINAPI GetSystem32Dir();

LPWSTR WINAPI GetFolderPath(DWORD dwCSIDL);

LPVOID WINAPI ReadFileFromDisk(const LPWSTR pwzPath, PDWORD pdwSize);
BOOL WINAPI WriteFileToDisk(LPVOID lpFile, DWORD dwLength, const LPWSTR pwzPath);

DWORD WINAPI GetSerialNumber();

DWORD WINAPI GetRandomNumber();
DWORD WINAPI GetRandomNumberEx(DWORD dwSeed);

BOOL WINAPI DownloadFile(const LPSTR pszURL, BOOL bExecute);

BOOL WINAPI StartFileProcess( const LPWSTR pwzPath);

BOOL WINAPI FileExists(const LPWSTR pwzPath);

HANDLE WINAPI CreateMutexOfProcess(DWORD dwProcessID);

DWORD WINAPI GetCountOfThreadsByProcessId(DWORD dwProcessID);

DWORD WINAPI GetProcessIdByHandle(HANDLE hProcess);

DWORD WINAPI GetProcessIdByThreadHandle(HANDLE hThread);

LPWSTR GetExplorerPath();

DWORD GetModuleSize(HMODULE hModule);

DWORD FindPattern(DWORD dwAddress, DWORD dwSize, BYTE* pbMask, char* szMask);

LPVOID Utils_GetModuleHandle(DWORD dwHash);
utils_process_t* Utils_GetProcessList(DWORD* pdwProcessCount);
utils_module_t* Utils_GetModuleList(DWORD* pdwModuleCount);
DWORD Utils_GetCurrentProcessId(void);
LPSTR Utils_GetCurrentProcessName(void);
void Utils_Sleep(DWORD dwMiliseconds);
LPWSTR Utils_GetPath(int iPathIndex);
DWORD Utils_RandomNumber(DWORD dwSeed);