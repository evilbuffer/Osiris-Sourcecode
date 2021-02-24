#pragma once
#include "bot_structs.h"

void Socket_Init(void);
void Socket_Uninit(void);
unsigned int Socket_ReceiveData(SOCKET hSock, LPSTR* ppszBuffer);
BOOL Socket_SendData(SOCKET hSock, const LPSTR pszBuffer);
BOOL Socket_SendDataEx(SOCKET hSock, const LPSTR pszBuffer, unsigned int iLength);
SOCKET Socket_Connect(const LPSTR pszHost, unsigned int iPort);
BOOL Socket_Accept(SOCKET hServer, SOCKET* hClient, SOCKADDR_IN* pClientAddress);
BOOL Socket_Listen(SOCKET* hServer, unsigned int iPort);