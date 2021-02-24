#pragma once
#include "api_structs.h"

DWORD WINAPI crc32Hash(const void *data, DWORD size);
DWORD WINAPI crc32HashEnd(void);

HMODULE WINAPI GetModuleHandleByHash(DWORD dwHash);
DWORD WINAPI GetModuleHandleByHashEnd(void);

BOOL WINAPI _LoadAPIFunctions();

BOOL WINAPI _GetAPIModules();
DWORD WINAPI GetAPIModulesEnd(void);

BOOL WINAPI InitializeAPI();

BOOL WINAPI _LoadLoadedAPIFunctions();

BOOL WINAPI _LoadAPIModules();

HMODULE WINAPI LoadLibraryByHash(DWORD dwHash);

LPVOID WINAPI GetProcAddressByHash(HMODULE module, DWORD dwHash);
