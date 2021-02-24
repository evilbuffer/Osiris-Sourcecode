#pragma once
#include "api_structs.h"
#include "function_structs.h"

typedef BOOL(WINAPI* ptIsOperatingSystem64Bit)(LPVOID pBotAddress);
typedef LPWSTR (WINAPI* ptGetFolderPath)(LPVOID lpBot, DWORD dwCSIDL);
typedef LPVOID(WINAPI* ptReadFileFromDisk)(LPVOID lpBot, const LPWSTR pwzPath, PDWORD pdwSize);
typedef BOOL(WINAPI* ptWriteFileToDisk)(LPVOID lpBot, LPVOID lpFile, DWORD dwLength, const LPWSTR pwzPath);
typedef DWORD (WINAPI* ptGetSerialNumber)(LPVOID lpBot);
typedef LPVOID (WINAPI* ptGetPCInfo)(LPVOID lpBotAddress);
typedef DWORD (WINAPI* ptGetRandomNumber)(LPVOID lpBot);
typedef BOOL(WINAPI* ptDownloadFile)(LPVOID lpBot, const LPSTR pszURL, BOOL bExecute);

typedef BOOL (WINAPI* ptSendTaskSuccess)(LPVOID lpBot, int iTaskID);
typedef BOOL (WINAPI* ptStartFileProcess)(LPVOID lpBot, const LPWSTR pwzPath);
typedef BOOL (WINAPI* ptFileExists)(LPVOID lpBot, const LPWSTR pwzPath);