#pragma once
#include "bot_structs.h"

typedef struct
{
	LPVOID lpFunctionAddress, lpCallbackAddress;
	LPVOID* lpOriginalFunction;
}hook_t;

BOOL WINAPI HookFunction(LPVOID lpFunctionAddress, LPVOID proxy, LPVOID original, PDWORD length);
BOOL UnhookFunction(CHAR *dll, CHAR *name, LPVOID original, DWORD length);