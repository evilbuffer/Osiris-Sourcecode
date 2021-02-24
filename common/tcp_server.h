#pragma once
#include "bot_structs.h"

typedef struct
{
	SOCKET hClient;
	SOCKADDR_IN clientAddress;
}client_connection_t;

typedef void(*pfnOnClientConnected)(client_connection_t client);
typedef void(*pfnOnClientReceiveData)(client_connection_t client, const LPSTR pszBuffer, unsigned int iRead);
typedef void(*pfnOnClientDisconnect)(client_connection_t client);

typedef struct
{
	pfnOnClientConnected OnClientConnected;
	pfnOnClientReceiveData OnClientReceiveData;
	pfnOnClientDisconnect OnClientDisconnect;
}tcp_server_callback_t;

typedef struct
{
	SOCKET hServer;
	client_connection_t* connections;
	DWORD connectionCount;
	RTL_CRITICAL_SECTION csConnections;
	
	tcp_server_callback_t callbacks;
}tcp_server_t;

BOOL TCPServer_Create(tcp_server_t* pServer, unsigned int iPort, tcp_server_callback_t callbacks);