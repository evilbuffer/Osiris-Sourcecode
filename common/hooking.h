#pragma once
#include "bot_structs.h"

typedef struct
{
	LPVOID lpFunctionAddress, lpCallbackAddress;
	LPVOID* lpOriginalFunction;
	DWORD dwLength;
	BYTE* pHookData; //For hook persistence
}hook_t;

LPVOID GetRemoteProcAddress(HANDLE hProcess, HMODULE hModule, DWORD dwHash);

LPVOID HookRemoteFunction(HANDLE hProcess, HMODULE hMod, DWORD dwHash, LPVOID lpCallbackAddress, PDWORD pdwFunctionSize);
LPVOID HookRemoteFunctionEx(HANDLE hProcess, LPVOID lpFunctionAddress, LPVOID lpCallbackAddress, PDWORD pdwLength);

void UnhookFunctionByOriginal(LPVOID lpOriginal, DWORD dwFunctionSize);