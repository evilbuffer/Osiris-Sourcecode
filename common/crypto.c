#include "crypto.h"
#include "utils.h"
#include "mem.h"

extern bot_t bot;

#define swap_byte(a, b) {swapByte = a; a = b; b = swapByte;}

void rc4Init(const void *binKey, WORD binKeySize, RC4KEY *key)
{
	register BYTE swapByte;
	register BYTE index1 = 0, index2 = 0;
	LPBYTE state = &key->state[0];
	register WORD i;

	key->x = 0;
	key->y = 0;

	for(i = 0; i < 256; i++)state[i] = i;
	for(i = 0; i < 256; i++)
	{
		index2 = (((LPBYTE)binKey)[index1] + state[i] + index2) & 0xFF;
		swap_byte(state[i], state[index2]);
		if(++index1 == binKeySize)index1 = 0;
	}
}

void rc4(void *buffer, DWORD size, RC4KEY *key)
{
	DWORD i;
	register BYTE swapByte;
	register BYTE x = key->x;
	register BYTE y = key->y;
	LPBYTE state = &key->state[0];

	for(i = 0; i < size; i++)
	{
		x = (x + 1) & 0xFF;
		y = (state[x] + y) & 0xFF;
		swap_byte(state[x], state[y]);
		((LPBYTE)buffer)[i] ^= state[(state[x] + state[y]) & 0xFF];
	}

	key->x = x;
	key->y = y; 

}

void rc4Full(const void *binKey, WORD binKeySize, void *buffer, DWORD size)
{
	RC4KEY key;
	rc4Init(binKey, binKeySize, &key);
	rc4(buffer, size, &key);
}

LPBYTE _RC4GenKey(DWORD dwKeySize)
{
	DWORD i;
	LPBYTE pKey;

	if((pKey = (LPBYTE)memalloc(dwKeySize)) != NULL)
	{
		for(i = 0; i < dwKeySize; i++)
			pKey[i] = GetRandomNumberEx(i + i == 0 ? 0 : pKey[i - 1]) % 256;
	}

	return pKey;
}


void _RC4( BYTE* pKey, DWORD dwBufferLen, BYTE* pBuffer, DWORD dwKeyLen )
{
	BYTE swap = 0;
	int a = 0;
	int RC4_s[256];
	int b = 0;
	int c = 0;
	DWORD dwCount;

	memzero(RC4_s, 256);

	for( a = 0; a < 256; a++ )
		RC4_s[a] = a;

	for( a = 0; a < 256; a++ )
	{
		c = RC4_s[a] + pKey[a % dwKeyLen];
		b = ( b + c ) % 256;
		swap = RC4_s[a];
		RC4_s[a] = RC4_s[b];
		RC4_s[b] = swap;
	}

	for( dwCount = 0; dwCount < dwBufferLen; dwCount++ )
	{
		a = ( a + 1 ) % 256;
		b = ( b + RC4_s[a] ) % 256;
		swap = RC4_s[a];
		RC4_s[a] = RC4_s[b];
		RC4_s[b] = swap;
		pBuffer[dwCount] ^= RC4_s[( RC4_s[a] + RC4_s[b])  % 256];
	}
}

DWORD WINAPI Crypto_crc32Hash(const void *data, DWORD size)
{
	DWORD i, j, crc, cc;

	if (bot.crc.crc32Initialized == FALSE)
	{
		for (i = 0; i < 256; i++)
		{
			crc = i;
			for (j = 8; j > 0; j--)
			{
				if (crc & 0x1)crc = (crc >> 1) ^ 0xEDB88320L;
				else crc >>= 1;
			}
			bot.crc.crc32table[i] = crc;
		}

		bot.crc.crc32Initialized = TRUE;
	}
	cc = 0xFFFFFFFF;
	for (i = 0; i < size; i++)cc = (cc >> 8) ^ bot.crc.crc32table[(((LPBYTE)data)[i] ^ cc) & 0xFF];
	return ~cc;
}

BOOL Crypto_CompareStrWEndByHash(const LPWSTR pwzData, DWORD dwLength, DWORD dwAmount, DWORD dwHash)
{
	LPWSTR pwzBuffer = NULL;
	DWORD dwCurrentHash, dwBufferStartIndex;

	dwBufferStartIndex = dwLength - dwAmount;
	dwCurrentHash = 0;

	if((pwzBuffer = (LPWSTR)memalloc((dwAmount + 1) * 2)) != NULL)
	{
		memcopy(pwzBuffer, pwzData + dwBufferStartIndex, dwAmount * 2);

		dwCurrentHash = Crypto_crc32Hash(pwzBuffer, dwAmount * 2);

		memfree(pwzBuffer);
	}

	if(dwCurrentHash == dwHash)
		return TRUE;

	return FALSE;
}

BOOL Crypto_CompareUnicodeStringEndByHash(UNICODE_STRING us, DWORD dwAmount, DWORD dwHash)
{
	LPWSTR pwzBuffer = NULL;
	DWORD dwCurrentHash, dwBufferStartIndex;

	dwBufferStartIndex = (us.Length / 2) - dwAmount;
	dwCurrentHash = 0;

	if((pwzBuffer = (LPWSTR)memalloc((dwAmount + 1) * 2)) != NULL)
	{
		memcopy(pwzBuffer, us.Buffer + dwBufferStartIndex, dwAmount * 2);

		dwCurrentHash = Crypto_crc32Hash(pwzBuffer, dwAmount * 2);

		memfree(pwzBuffer);
	}

	if(dwCurrentHash == dwHash)
		return TRUE;

	return FALSE;
}