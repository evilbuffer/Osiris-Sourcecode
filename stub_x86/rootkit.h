#pragma once
#include "modules.h"

#ifdef MODULE_ROOTKIT
#include "bot_structs.h"

extern ptNtCreateThread oNtCreateThread;

BOOL WINAPI InstallRootkit(void);
void WINAPI UnhookProcess(void);
#endif
