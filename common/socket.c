#include "socket.h"

#include "mem.h"
#include "string.h"

WSADATA wsaData;

void Socket_Init(void)
{
	CWA(WSAStartup)(MAKEWORD(2,2), &wsaData);
}

void Socket_Uninit(void)
{
	CWA(WSACleanup)();
}

unsigned int Socket_ReceiveData(SOCKET hSock, LPSTR* ppszBuffer)
{
	unsigned int iRead;
	char szBuffer[3072];
	memzero(&szBuffer, sizeof(szBuffer));

	if((iRead = CWA(recv)(hSock, szBuffer, 3071, 0)) > 0)
	{
		*ppszBuffer = StrCopyA(szBuffer, iRead);
	}
	else iRead = 0;

	return iRead;
}

BOOL Socket_SendData(SOCKET hSock, const LPSTR pszBuffer)
{
	return Socket_SendDataEx(hSock, pszBuffer, StrLengthA(pszBuffer));
}

/*
	ToDo:
	- Find out limit of length for a single send() call.
	- Implement full_send() based on this limit.
*/
BOOL Socket_SendDataEx(SOCKET hSock, const LPSTR pszBuffer, unsigned int iLength)
{
	BOOL bSent = FALSE;

	if(CWA(send)(hSock, pszBuffer, iLength, 0) > 0)
		bSent = TRUE;

	return bSent;
}

SOCKET Socket_Connect(const LPSTR pszHost, unsigned int iPort)
{
	BOOL bConnected;
	struct addrinfo* result, *ptr;
	struct addrinfo hints;
	SOCKADDR_IN destinationAddress;

	SOCKET hSock = INVALID_SOCKET;

	result = NULL;
	ptr = NULL;
	bConnected = FALSE;

	if(CWA(getaddrinfo)(pszHost, NULL, &hints, &result) == 0)
	{
		for(ptr = result; ptr != NULL; ptr = ptr->ai_next)
		{
			hSock = CWA(socket)(ptr->ai_family, ptr->ai_socktype, IPPROTO_TCP);

			if(hSock != INVALID_SOCKET)
			{
				memzero(&destinationAddress, sizeof(SOCKADDR_IN));
				destinationAddress.sin_family = ptr->ai_family;
				destinationAddress.sin_addr = ((struct sockaddr_in*)(ptr->ai_addr))->sin_addr;
				destinationAddress.sin_port = CWA(htons)(iPort);

				if(CWA(connect)(hSock, (struct sockaddr*)&destinationAddress, sizeof(SOCKADDR_IN)) == 0)
					bConnected = TRUE;
			}
		}
		
		CWA(freeaddrinfo)(result);
	}

	if(bConnected == FALSE && hSock != INVALID_SOCKET)
	{
		CWA(closesocket)(hSock);
		hSock = INVALID_SOCKET;
	}

	return hSock;
}

BOOL Socket_Accept(SOCKET hServer, SOCKET* hClient, SOCKADDR_IN* pClientAddress)
{
	int iSize;
	BOOL bAccepted = FALSE;

	if(hServer == INVALID_SOCKET) return FALSE;

	memzero(pClientAddress, sizeof(SOCKADDR_IN));

	iSize = sizeof(SOCKADDR_IN);

	if((*hClient = CWA(accept)(hServer, (struct sockaddr*)pClientAddress, &iSize)) != INVALID_SOCKET)
		bAccepted = TRUE;

	return bAccepted;
}

BOOL Socket_Listen(SOCKET* hServer, unsigned int iPort)
{
	SOCKADDR_IN ServerAddress;
	BOOL bSuccess = FALSE;

	if((*hServer = CWA(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
		return FALSE;

	memzero(&ServerAddress, sizeof(SOCKADDR_IN));
	ServerAddress.sin_family = AF_INET;
	ServerAddress.sin_addr.S_un.S_addr = 0x0100007F; //localhost
	ServerAddress.sin_port = CWA(htons)(iPort);

	if(CWA(bind)(*hServer, (struct sockaddr*)&ServerAddress, sizeof(ServerAddress)) == 0)
	{
		if(CWA(listen)(*hServer, 100) == 0)
			bSuccess = TRUE;
	}

	return bSuccess;
}