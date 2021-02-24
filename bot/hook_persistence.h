#pragma once
#include "modules.h"

#ifdef MODULE_ROOTKIT
#include "../common/bot_structs.h"

void WINAPI StartHookPersistence(void);
#endif