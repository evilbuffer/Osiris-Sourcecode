#pragma once
#include "modules.h"

#ifdef MODULE_BACKCONNECT
#include <winsock2.h>
#include <Windows.h>
#include <Ws2tcpip.h>

enum Packets
{
	IDENT = 0x1
};

typedef struct  
{
	int iBlockID;
	char* pszBuffer;
}block_t;

typedef struct  
{
	int iPacketID;
	int iTotalBlocks;
	block_t* Blocks;
}header_t;

typedef struct  
{
	SOCKET hClient;
	header_t Header;
} packet_t;

void WINAPI InitProtocol(void);
void WINAPI HandleHeader(SOCKET hClient, const LPSTR pszData, int iAmount);
void WINAPI HandleBlock(SOCKET hClient, const LPSTR pszData, int iAmount);
BOOL WINAPI SendPacketEx(SOCKET hClient, const LPSTR pszBuffer);
BOOL WINAPI SendPacket(SOCKET hClient, unsigned char bPacket, const LPSTR pszArguments);

#define BLOCK_SIZE 512
#endif