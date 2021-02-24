#pragma once
#include "bot_structs.h"

BOOL Thread_CreateThread(LPTHREAD_START_ROUTINE lpStart, const LPVOID lpArguments);
HANDLE Thread_CreateThreadEx(LPTHREAD_START_ROUTINE lpStart, const LPVOID lpArguments);