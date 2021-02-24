#pragma once
#include "bot_structs.h"

BOOL SendPOST(const LPSTR pszHost, const LPSTR pszPage, const LPSTR pszData, LPSTR* ppszResponse);
BOOL StartConnectionThread();
BOOL WINAPI SendTaskSuccess(int iTaskID);