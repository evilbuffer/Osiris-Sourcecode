#pragma once
#include "bot_structs.h"
typedef HMODULE (WINAPI* ptGetModuleHandleByHash)(struct bot_t* pBot, functions_t* pFunctions, crc_t* pCrc, DWORD dwHash);