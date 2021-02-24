#include "bc_server.h"

#include "..\common\mem.h"
#include "..\common\socket.h"
#include "..\common\tcp_server.h"

tcp_server_t server;

void BCServer_OnClientConnected(client_connection_t client)
{
	Socket_SendData(client.hClient, "penis");
}

void BCServer_OnClientDisconnect(client_connection_t client)
{

}

void BCServer_OnClientReceiveData(client_connection_t client, const LPSTR pszBuffer, unsigned int iRead)
{

}

void BCServer_Start(unsigned int iPort)
{
	tcp_server_callback_t callbacks;
	callbacks.OnClientConnected = BCServer_OnClientConnected;
	callbacks.OnClientDisconnect = BCServer_OnClientDisconnect;
	callbacks.OnClientReceiveData = BCServer_OnClientReceiveData;

	memzero(&server, sizeof(tcp_server_t));

	if(!TCPServer_Create(&server, iPort, callbacks))
	{
		MessageBoxW(0, L"Port is already in-use. Select a different port.", L"Backconnect Server", 0);
		return;
	}
}