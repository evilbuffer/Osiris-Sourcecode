#pragma once
#include "modules.h"

#ifdef MODULE_ROOTKIT
#include "bot_structs.h"

BOOL WINAPI RunIPCServer(void);
BOOL WINAPI RunIPCClient(void);
#endif

