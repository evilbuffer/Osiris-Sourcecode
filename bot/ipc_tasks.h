#pragma once
#include "modules.h"

#ifdef MODULE_ROOTKIT
#include "../common/bot_structs.h"

enum IPC_Tasks
{
	DELETE_FILE = 0
};

typedef void(*pfnIPCTask)(const LPSTR pszArguments);

typedef struct
{
	int iTask;
	pfnIPCTask Callback;
}ipc_task_t;

void ExecuteIPCClientTask(const LPSTR pszData);
void ExecuteIPCServerTask(const LPSTR pszData);
#endif