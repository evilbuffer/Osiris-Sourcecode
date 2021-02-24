#pragma once
#include "modules.h"

#ifdef MODULE_DEBUG
#include "..\common\bot_structs.h"

void WINAPI InitDebug(void);
void WINAPI WriteDebugData(const LPSTR pszFunction, const LPSTR pszData, const LPSTR pszFile, int iLine);

#define WDEBUG(data) WriteDebugData(__FUNCTION__, ##data, __FILE__, __LINE__)
#endif