#pragma once
#include "modules.h"

#ifdef MODULE_BACKCONNECT
#include "bot_structs.h"

typedef struct
{
	LPSTR pszServerAddress;
	int iPort;
}backconnect_info_t;
#endif