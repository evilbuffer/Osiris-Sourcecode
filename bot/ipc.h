#pragma once
#include "modules.h"

#ifdef MODULE_ROOTKIT
#include "../common/bot_structs.h"

BOOL WINAPI RunIPCServer(void);
BOOL WINAPI RunIPCClient(void);
#endif

