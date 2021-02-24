#include "ipc_tasks.h"

#ifdef MODULE_ROOTKIT
#include "../common/mem.h"
#include "../common/string.h"

void ExecuteIPCClientTask(const LPSTR pszData)
{

}

void Server_DeleteFile(const LPSTR pszArguments)
{

}

void ExecuteIPCServerTask(const LPSTR pszData)
{
	ipc_task_t Tasks[] =
	{
		{DELETE_FILE, Server_DeleteFile}
	};

	int iDelimCount = -1;

	if ((iDelimCount = CharCountA(pszData, '|')) == 0)
		return;


}
#endif