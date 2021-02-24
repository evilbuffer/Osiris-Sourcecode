#pragma once
#include "../common/bot_structs.h"

enum REPORT_TYPES
{
	REPORT_HTTP = 0
};

BOOL SendPOST(const LPSTR pszHost, const LPSTR pszPage, const LPSTR pszData, LPSTR* ppszResponse);
BOOL StartConnectionThread();
BOOL WINAPI SendTaskSuccess(int iTaskID);