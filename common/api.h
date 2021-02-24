#pragma once
#include "api_structs.h"

HMODULE WINAPI GetModuleHandleByHash(DWORD dwHash);
DWORD WINAPI GetModuleHandleByHashEnd(void);

BOOL WINAPI API_LoadKernel32Functions();

BOOL WINAPI _GetAPIModules();
DWORD WINAPI GetAPIModulesEnd(void);

BOOL WINAPI InitializeAPI();

BOOL WINAPI _LoadLoadedAPIFunctions();

BOOL WINAPI _LoadAPIModules();

HMODULE WINAPI LoadLibraryByHash(DWORD dwHash);

LPVOID WINAPI GetProcAddressByHash(HMODULE module, DWORD dwHash);

BOOL WINAPI _GetNTDLLModule();
BOOL WINAPI _LoadNTDLLFunctions();