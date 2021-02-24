#pragma once
#include "../common/bot_structs.h"

enum Tasks
{
	DOWNLOAD_EXECUTE = 0,
	UPDATE = 1,
	UNINSTALL = 2
};

typedef void(*pfnTask)(int iTaskID, const LPSTR pszArguments);

typedef struct  
{
	unsigned int iTask;
	pfnTask TaskProc;
}task_t;

BOOL ExecuteTask(const LPSTR pszResponse);