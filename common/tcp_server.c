#include "tcp_server.h"

#include "mem.h"
#include "socket.h"
#include "thread.h"

void TCPServer_AddClient(tcp_server_t* pServer, SOCKET hClient, SOCKADDR_IN clientAddress)
{
	client_connection_t* pConnection;
	DWORD i, dwIndex;

	for(i = 0; i < pServer->connectionCount; i++)
	{
		if(pServer->connections[i].hClient == INVALID_SOCKET)
		{
			pConnection = &pServer->connections[i];
			dwIndex = i;
			break;
		}
	}

	if(pConnection == NULL && memreallocEx(&pServer->connections, sizeof(client_connection_t) * (pServer->connectionCount + 1))
	{
		dwIndex = pServer->connectionCount++;
		pConnection = &pServer->connections[dwIndex];
	}

	if(pConnection != NULL)
	{
		pConnection->hClient = hClient;
		memcopy(&pConnection->clientAddress, &clientAddress, sizeof(SOCKADDR_IN));

		if(pServer->callbacks.OnClientConnected != NULL)
			pServer->callbacks.OnClientConnected(*pConnection);
	}
}

DWORD TCPServer_FindClient(const tcp_server_t* pServer, SOCKET hClient)
{
	DWORD i;

	for(i = 0; i < pServer->connectionCount; i++)
	{
		if(pServer->connections[i].hClient == hClient)
			return i;
	}

	return -1;
}

void TCPServer_RemoveClient(tcp_server_t* pServer, SOCKET hClient)
{
	client_connection_t* pConnection;
	DWORD dwNewCount, dwIndex;

	if((dwIndex = TCPServer_FindClient(pServer, hClient)) == -1)
		return;

	pConnection = &pServer->connections[dwIndex];

	if(pConnection != NULL)
	{
		if(pServer->callbacks.OnClientDisconnect != 0)
			pServer->callbacks.OnClientDisconnect(*pConnection);

		CWA(closesocket)(pConnection->hClient);
		memzero(pConnection, sizeof(client_connection_t));
		pConnection->hClient = INVALID_SOCKET;

		dwNewCount = pServer->connectionCount;

		while(pServer->connections[dwNewCount - 1].hClient == INVALID_SOCKET) dwNewCount--;

		if(dwNewCount != pServer->connectionCount)
		{
			if(dwNewCount == 0)
			{
				memfree(pServer->connections);
				pServer->connections = NULL;
			}
			else memreallocEx(&pServer->connections, sizeof(client_connection_t) * dwNewCount);

			pServer->connectionCount = dwNewCount;
		}
	}
}

DWORD WINAPI TCPServer_ReceiveDataThread(tcp_server_t* pServer)
{
	unsigned int iRead;
	DWORD i;
	fd_set fdset;
	LPSTR pszBuffer = NULL;
	
	while(TRUE)
	{
		CWA(RtlEnterCriticalSection)(&pServer->csConnections);
		
		FD_ZERO(&fdset);

		for(i = 0; i < pServer->connectionCount; i++)
		{
			if(pServer->connections[i].hClient == INVALID_SOCKET) continue;

			FD_SET(pServer->connections[i].hClient, &fdset);
		}

		if(CWA(select)(0, &fdset, 0, 0, 0) != SOCKET_ERROR)
		{
			for(i = 0; i < pServer->connectionCount; i++)
			{
				if(pServer->connections[i].hClient == INVALID_SOCKET) continue;

				if(FD_ISSET(pServer->connections[i].hClient, &fdset))
				{
					if((iRead = Socket_ReceiveData(pServer->connections[i].hClient, &pszBuffer)) > 0)
					{
						if(pServer->OnClientReceiveData != NULL)
							pServer->OnClientReceiveData(pServer->connections[i], pszBuffer, iRead);
					}
					else
					{
						TCPServer_RemoveClient(pServer, pServer->connections[i].hClient);
					}
				}
			}
		}

		CWA(RtlLeaveCriticalSection)(&pServer->csConnections);
	}
	return 0;
}

void TCPServer_StartReceiveDataThread(tcp_server_t* pServer)
{
	Thread_CreateThread((LPTHREAD_START_ROUTINE)TCPServer_ReceiveDataThread, (LPVOID)pServer);
}

DWORD WINAPI TCPServer_ConnectionThread(tcp_server_t* pServer)
{
	SOCKET hClient;
	SOCKADDR_IN clientAddress;

	while(Socket_Accept(pServer->hServer, &hClient, &clientAddress))
	{
		CWA(RtlEnterCriticalSection)(&pServer->csConnections);

		//First connection
		if(pServer->connectionCount == 0)
		{
			TCPServer_StartReceiveDataThread(pServer);
		}

		TCPServer_AddClient(pServer, hClient, clientAddress);

		CWA(RtlLeaveCriticalSection)(&pServer->csConnections);
	}

	return 0;
}

BOOL TCPServer_Create(tcp_server_t* pServer, unsigned int iPort, tcp_server_callback_t callbacks)
{
	memzero(pServer, sizeof(tcp_server_t));
	
	if(!Socket_Listen(&pServer->hServer, iPort))
		return FALSE;
	
	CWA(RtlInitializeCriticalSection)(&pServer->csConnections);

	memcopy(&pServer->callbacks, &callbacks, sizeof(tcp_server_callback-t));

	return Thread_CreateThread((LPTHREAD_START_ROUTINE)TCPServer_ConnectionThread, (LPVOID)pServer);
}