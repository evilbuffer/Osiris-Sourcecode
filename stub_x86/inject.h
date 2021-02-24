#pragma once
#include <Windows.h>
#include "bot_structs.h"

LPVOID WINAPI InjectData(HANDLE hProcess, LPVOID pData, DWORD dwSize);
void WINAPI InjectDataEnd();

BOOL InjectBotEx(DWORD dwProcessID, LPTHREAD_START_ROUTINE start);
DWORD InjectBot(LPTHREAD_START_ROUTINE start);

LPVOID CopyModule(HANDLE proc, LPVOID image);

DWORD InjectCodeEx(HANDLE hProcess, LPVOID lpFunction);
DWORD InjectCode(DWORD dwProcessID, LPVOID lpFunction);