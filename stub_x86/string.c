#include "string.h"

#include "bot_structs.h"

extern bot_t bot;

#include "mem.h"

LPWSTR WINAPI StrCopyW(const LPWSTR pwzInput, DWORD dwLength)
{
	LPWSTR pwzData;

	if ((pwzData = (LPWSTR)memalloc(dwLength * sizeof(wchar_t))) == NULL)
		return NULL;

	memcopy(pwzData, pwzInput, dwLength);

	return pwzData;
}
DWORD WINAPI StrCopyWEnd() { return 0; }

LPSTR WINAPI StrCopyA(const LPSTR pszInput, DWORD dwLength)
{
	LPSTR pszData;

	if ((pszData = (LPSTR)memalloc(dwLength)) == NULL)
		return NULL;

	memcopy(pszData, pszInput, dwLength);

	return pszData;
}

DWORD WINAPI StrLengthW(const LPWSTR pwzInput)
{
	DWORD i;

	i = 0;

	do
	{
		if (pwzInput[i] == 0)
			break;

		i++;
	} while (TRUE);

	return i;
}
DWORD WINAPI StrLengthWEnd() { return 0; }

DWORD WINAPI StrLengthA(const LPSTR pszInput)
{
	DWORD i;

	i = 0;

	do
	{
		if (pszInput[i] == 0)
			break;

		i++;
	} while (TRUE);

	return i;
}
DWORD WINAPI StrLengthAEnd() { return 0; }

LPWSTR WINAPI StrToLowerW(const LPWSTR pwzInput, DWORD dwLength)
{
	DWORD i;
	int c;
	static wchar_t wzInputLower[255];

	if (pwzInput == NULL)
		return NULL;

	memzero(&wzInputLower, sizeof(wzInputLower));

	for (i = 0; i < dwLength; i++)
	{
		c = pwzInput[i];

		if (c >= 65 && c <= 90)
			c += 32;

		wzInputLower[i] = c;
	}

	return wzInputLower;
}

LPWSTR WINAPI StrConcatExW(const LPWSTR pwzSource, DWORD dwSourceLength, const LPWSTR pwzData, DWORD dwDataLength)
{
	wchar_t* pwzTogether = NULL;

	DWORD dwIndex;

	dwIndex = 0;

	if ((pwzTogether = (wchar_t*)memalloc((dwSourceLength + dwDataLength) * 2)) == NULL)
		return NULL;

	if (dwSourceLength > 0)
	{
		memcopy(pwzTogether, pwzSource, dwSourceLength * 2);
		dwIndex += dwSourceLength;
	}

	if (dwDataLength > 0)
	{
		memcopy(pwzTogether + dwIndex, pwzData, dwDataLength * 2);
	}

	return pwzTogether;
}

LPWSTR WINAPI StrConcatW(const LPWSTR pwzSource, const LPWSTR pwzData)
{
	return StrConcatExW(pwzSource, StrLengthW(pwzSource), pwzData, StrLengthW(pwzData));
}
DWORD WINAPI StrConcatWEnd() { return 0; }

BOOL WINAPI EndsWithSlashW(const LPWSTR pwzInput)
{
	DWORD dwLength;

	if ((dwLength = StrLengthW(pwzInput)) == 0)
		return FALSE;

	wchar_t wzData = pwzInput[dwLength];


	if (wzData == L'\\') return TRUE;

	return FALSE;
}

/*
	Compares two strings starting at start
*/
BOOL WINAPI StrCompareW(const LPWSTR pwzInput, const LPWSTR pwzData)
{
	DWORD dwInputLength, dwDataLength, i;

	dwInputLength = StrLengthW(pwzInput);
	dwDataLength = StrLengthW(pwzData);

	if (dwDataLength != dwInputLength)
		return FALSE;

	for (i = 0; i < dwDataLength; i++)
	{
		if (pwzInput[i] != pwzData[i])
			return FALSE;
	}

	return TRUE;
}

/*
	Compares two strings starting at end
*/
BOOL WINAPI StrCompareEndW(const LPWSTR pwzInput, const LPWSTR pwzData)
{
	int i, iInputIndex;

	i = StrLengthW(pwzData);
	iInputIndex = StrLengthW(pwzInput);

	while (i >= 0)
	{
		if (pwzInput[iInputIndex] != pwzData[i])
			return FALSE;
		i--;
		iInputIndex--;
	}

	return TRUE;
}

BOOL WINAPI StrCompareStartW(const LPWSTR pwzInput, const LPWSTR pwzData)
{
	int i;

	for (i = 0; i < StrLengthW(pwzData); i++)
	{
		if (pwzInput[i] != pwzData[i])
			return FALSE;
	}

	return TRUE;
}

BOOL WINAPI StrCompareStartA(const LPSTR pszInput, const LPSTR pszData)
{
	int i;

	for (i = 0; i < StrLengthA(pszData); i++)
	{
		if (pszInput[i] != pszData[i])
			return FALSE;
	}

	return TRUE;
}

DWORD CharCountA(const char* pszBuffer, char c)
{
	DWORD iLength, iCount, i;

	iLength = StrLengthA(pszBuffer);
	iCount = 0;

	for (i = 0; i < iLength; i++)
	{
		if (pszBuffer[i] == c)
			iCount++;
	}

	return iCount;
}

DWORD WINAPI StrIndexOfCharA(const char* pszInput, const char cData)
{
	DWORD dwLength, dwIndex;

	dwLength = StrLengthA(pszInput);

	for (dwIndex = 0; dwIndex < dwLength; dwIndex++)
	{
		if (pszInput[dwIndex] == cData)
			return dwIndex;
	}

	return -1;
}

char* WINAPI StrCopyExA(const char* pszData, DWORD iOffset, DWORD iLength)
{
	char* pszBuffer = NULL;

	DWORD iDataLength = iLength - iOffset;

	if ((pszBuffer = (char*)memalloc(iDataLength)) == NULL)
		return NULL;

	memcopy(pszBuffer, pszData + iOffset, iDataLength);

	return pszBuffer;
}

LPSTR* SplitString(const char* pszBuffer, char c, DWORD dwCount)
{
	LPSTR* ppszData = NULL;

	int iStringIndex, iIndex;

	iStringIndex = 0;
	iIndex = -1;

	if ((ppszData = (LPSTR*)memalloc(dwCount * sizeof(LPSTR))) == NULL)
		return NULL;

	while ((iIndex = StrIndexOfCharA(pszBuffer, c)) > 0)
	{
		ppszData[iStringIndex] = StrCopyExA(pszBuffer, 0, iIndex);
		iIndex++;

		pszBuffer += iIndex;

		iStringIndex++;
	}

	return ppszData;
}


DWORD64 __declspec(naked) _mul64(DWORD64 dwA, DWORD64 dwB)
{
	__asm
	{
		mov  eax, dword ptr[esp + 0x08]
		mov  ecx, dword ptr[esp + 0x10]
			or ecx, eax
			mov  ecx, dword ptr[esp + 0x0C]

			jnz  hard

			mov  eax, dword ptr[esp + 0x04]
			mul  ecx

			ret  0x10

			hard:
		push ebx

			mul  ecx
			mov  ebx, eax

			mov  eax, dword ptr[esp + 0x08]
			mul  dword ptr[esp + 0x14]
			add  ebx, eax

			mov  eax, dword ptr[esp + 0x08]
			mul  ecx
			add  edx, ebx

			pop  ebx
			ret  0x10
	}
}

#if defined _WIN64
#define TCharToIntOP1(IntType) (v <<= 4)
#else
#define TCharToIntOP1(IntType) (v = (sizeof(IntType) == sizeof(int) ? v <<= 4 : (IntType)_mul64(v, 8))) //Выбор будет произведен при компиляции.
#endif

#if defined _WIN64
#define TCharToIntOP2(IntType) (v *= 10)
#else
#define TCharToIntOP2(IntType) (v = (sizeof(IntType) == sizeof(int) ? v *= 10 : (IntType)_mul64(v, 10))) //Выбор будет произведен при компиляции.
#endif
// 
#define TCharToInt(CharType, IntType)\
{\
	unsigned IntType v;\
	BOOL sign;\
	CharType c;\
	sign = FALSE;\
	v = 0;\
	\
	if(*pstrStr == '-'){pstrStr++; sign = TRUE;}\
  else if(*pstrStr == '+')pstrStr++;\
  \
  if(*pstrStr == '0' && (pstrStr[1] == 'x' || pstrStr[1] == 'X'))\
{\
	pstrStr += 2;\
	\
	for(;;)\
{\
	c = *pstrStr;\
	\
	if(c >= '0' && c <= '9')c -= '0';\
	  else if(c >= 'a' && c <= 'f')c = c - 'a' + 0xA;\
	  else if(c >= 'A' && c <= 'F')c = c - 'A' + 0xA;\
	  else break;\
	  \
	  TCharToIntOP1(IntType);\
	  v += c;\
	  pstrStr++;\
}\
}\
  else\
{\
	for(;;)\
{\
	c = *pstrStr;\
	if(c < '0' || c > '9')break;\
	TCharToIntOP2(IntType);\
	v += c - '0';\
	pstrStr++;\
}\
}\
	if(pbSign)*pbSign = sign;\
	return sign ? (v * -(1)) : (v);\
}
// 
int _ToInt32A(LPSTR pstrStr, BOOL *pbSign)
{
	TCharToInt(char, int);
}

int _ToInt32W(LPWSTR pstrStr, BOOL *pbSign)
{
	TCharToInt(wchar_t, int);
}