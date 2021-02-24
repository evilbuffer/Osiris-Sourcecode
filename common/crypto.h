#pragma once
#include "bot_structs.h"

typedef struct
{      
	BYTE state[256];       
	BYTE x;        
	BYTE y;
}RC4KEY;

void rc4Init(const void *binKey, WORD binKeySize, RC4KEY *key);
void rc4(void *buffer, DWORD size, RC4KEY *key);
void rc4Full(const void *binKey, WORD binKeySize, void *buffer, DWORD size);
void _RC4( BYTE* pKey, DWORD dwBufferLen, BYTE* pBuffer, DWORD dwKeyLen );
LPBYTE _RC4GenKey(DWORD dwKeySize);
DWORD WINAPI Crypto_crc32Hash(const void *data, DWORD size);
BOOL Crypto_CompareStrWEndByHash(const LPWSTR pwzData, DWORD dwLength, DWORD dwAmount, DWORD dwHash);
BOOL Crypto_CompareUnicodeStringEndByHash(UNICODE_STRING us, DWORD dwAmount, DWORD dwHash);