#include "string.h"

#include "bot_structs.h"

extern bot_t bot;

#include "mem.h"

LPSTR ToStringA(const void* buffer, DWORD dwLength)
{
	LPSTR pszBuffer;

	if((pszBuffer = (LPSTR)memalloc(dwLength + 1)) != NULL)
	{
		memcopy(pszBuffer, buffer, dwLength);
	}

	return pszBuffer;
}

LPWSTR WINAPI StrCopyW(const LPWSTR pwzInput, DWORD dwLength)
{
	LPWSTR pwzData;
	DWORD dwNewStringLength;

	dwNewStringLength = dwLength * sizeof(wchar_t);

	if ((pwzData = (LPWSTR)memalloc(dwNewStringLength + sizeof(wchar_t))) == NULL)
		return NULL;

	memcopy(pwzData, pwzInput, dwNewStringLength);

	return pwzData;
}

DWORD WINAPI StrCopyWEnd() { return 0; }

LPSTR WINAPI StrCopyA(const LPSTR pszInput, DWORD dwLength)
{
	LPSTR pszData;

	if ((pszData = (LPSTR)memalloc(dwLength + 1)) == NULL)
		return NULL;

	memcopy(pszData, pszInput, dwLength);

	return pszData;
}

DWORD WINAPI StrLengthW(const LPWSTR pwzInput)
{
	DWORD i;

	i = 0;

	if(pwzInput == NULL)
		return 0;

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
	int i;

	i = 0;

	if(pszInput == NULL)
		return 0;

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


BOOL StrConcatExA(LPSTR* ppszData, DWORD dwCurrentLength, const LPSTR pszSource, DWORD dwLength)
{
	if(memreallocEx(ppszData, dwCurrentLength + dwLength + 1))
	{
		memcopy((*ppszData) + dwCurrentLength, pszSource, dwLength);
		return TRUE;
	}

	return FALSE;
}

BOOL StrConcatA(LPSTR* ppszData, const LPSTR pszSource)
{
	return StrConcatExA(ppszData, StrLengthA(*ppszData), pszSource, StrLengthA(pszSource));
}

BOOL StrConcatExW(LPWSTR* ppwzData, DWORD dwCurrentLength, const LPWSTR pwzSource, DWORD dwLength)
{
	if(memreallocEx(ppwzData, (dwCurrentLength + dwLength + 1) * sizeof(wchar_t)))
	{
		memcopy((*ppwzData) + dwCurrentLength, pwzSource, dwLength * sizeof(wchar_t));
		return TRUE;
	}

	return FALSE;
}

BOOL StrConcatW(LPWSTR* ppwzData, const LPWSTR pwzSource)
{
	return StrConcatExW(ppwzData, StrLengthW(*ppwzData), pwzSource, StrLengthW(pwzSource));
}

BOOL WINAPI EndsWithSlashW(const LPWSTR pwzInput)
{
	DWORD dwLength;
	wchar_t wzData;

	if ((dwLength = StrLengthW(pwzInput)) == 0)
		return FALSE;

	wzData = pwzInput[dwLength];


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
	DWORD i;

	for (i = 0; i < StrLengthW(pwzData); i++)
	{
		if (pwzInput[i] != pwzData[i])
			return FALSE;
	}

	return TRUE;
}

BOOL WINAPI StrCompareStartA(const LPSTR pszInput, const LPSTR pszData)
{
	DWORD i, dwLength;

	dwLength = StrLengthA(pszData);

	for (i = 0; i < dwLength; i++)
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

DWORD StrIndexOfA(const char* pszInput, const char* pszData)
{
	char* pszDestination = NULL;

	if (pszInput == NULL || pszData == NULL)
		return -1;

	if((pszDestination = CWA(StrStrA)(pszInput, pszData)) == NULL)
		return -1;

	return (DWORD)(pszDestination - pszInput);
}

char* WINAPI StrCopyExA(const char* pszData, DWORD iOffset, DWORD iLength)
{
	char* pszBuffer = NULL;

	DWORD iDataLength = iLength - iOffset;

	if ((pszBuffer = (char*)memalloc(iDataLength + 1)) == NULL)
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

int _vsprintfW(LPWSTR pBuf, int iBufSize, LPCWSTR pstrFormat, va_list arglist)
{
	int iSize;

	if(iBufSize <= 0)return -1;

	memzero(pBuf, iBufSize * sizeof(WCHAR));
	iSize = CWA(wvnsprintfW)(pBuf, iBufSize, pstrFormat, arglist);
	pBuf[iBufSize - 1] = 0;

	if(iSize == -1)
	{
		iSize = StrLengthW(pBuf);
	}
	else pBuf[iSize] = 0;

	return iSize;
}

int _vsprintfA(LPSTR pBuf, int iBufSize, LPCSTR pstrFormat, va_list arglist)
{
	int iSize;
	if(iBufSize <= 0)return -1;

	memzero(pBuf, iBufSize);
	iSize = CWA(wvnsprintfA)(pBuf, iBufSize, pstrFormat, arglist);
	pBuf[iBufSize - 1] = 0;

	if(iSize == -1)
	{
		iSize = StrLengthA(pBuf);
	}
	else pBuf[iSize] = 0;

	return iSize;
}

static int unicodeToX(DWORD codePage, const LPWSTR source, int sourceSize, LPSTR dest, int destSize)
{
	int size;

	if(sourceSize == -1)sourceSize = StrLengthW(source);
	size = CWA(WideCharToMultiByte)(codePage, 0, source, sourceSize, dest, destSize, NULL, NULL);
	if(destSize > 0)
	{
		if(size >= destSize)size = 0; //Нет места на нулевой символ.
		dest[size] = 0;
	}
	return size;
}

static LPSTR unicodeToXEx(DWORD codePage, const LPWSTR source, int size)
{
	int destSize;
	LPSTR dest;

	if(size == -1)size = StrLengthW(source);
	destSize = unicodeToX(codePage, source, size, NULL, 0);
	if(destSize > 0)
	{
		destSize += sizeof(BYTE);
		dest = (LPSTR)memalloc(destSize * sizeof(BYTE));
		if(dest != NULL)
		{
			unicodeToX(codePage, source, size, dest, destSize);
			return dest;
		}
	}
	return NULL;
}

static int xToUnicode(DWORD codePage, const LPSTR source, int sourceSize, LPWSTR dest, int destSize)
{
	int size;
	if(sourceSize == -1)sourceSize = StrLengthA(source);
	size = CWA(MultiByteToWideChar)(codePage, 0, source, sourceSize, dest, destSize);
	if(destSize > 0)
	{
		if(size >= destSize)size = 0; //Нет места на нулевой символ.
		dest[size] = 0;
	}
	return size;
}

static LPWSTR xToUnicodeEx(DWORD codePage, LPSTR source, int size)
{
	int destSize;
	LPWSTR dest;

	if(size == -1)size = StrLengthA(source);
	destSize = xToUnicode(codePage, source, size, NULL, 0);
	if(destSize > 0)
	{
		destSize += sizeof(BYTE);
		dest = (LPWSTR)memalloc(destSize * sizeof(WCHAR));
		if(dest != NULL)
		{
			xToUnicode(codePage, source, size, dest, destSize);
			return dest;
		}
	}
	return NULL;
}


LPSTR unicodeToAnsiEx(const LPWSTR source, int size)
{
	return unicodeToXEx(CP_ACP, source, size);
}

LPWSTR ansiToUnicodeEx(LPSTR source, int size)
{
	return xToUnicodeEx(CP_ACP, source, size);
}

LPSTR StrGetBetweenA(const LPSTR buffer, const LPSTR before, const LPSTR after)
{
	DWORD dwBeforeIndex, dwAfterIndex, dwLength;
	LPSTR pszBuffer;

	if((dwBeforeIndex = StrIndexOfA(buffer, before)) == -1)
		return NULL;

	dwBeforeIndex += StrLengthA(before);
	dwAfterIndex = StrIndexOfA(buffer + dwBeforeIndex, after);
	dwAfterIndex += dwBeforeIndex;

	dwLength = dwAfterIndex - dwBeforeIndex;

	pszBuffer = NULL;

	if((pszBuffer = (LPSTR)memalloc(dwLength + 1)) == NULL)
		return NULL;

	memcopy(pszBuffer, buffer + dwBeforeIndex, dwLength);

	return pszBuffer;
}

BOOL String_ToUnicodeString(PUNICODE_STRING pUI, const LPWSTR pwzBuffer)
{
	DWORD dwLength;

	if(pUI == 0)
		return FALSE;

	dwLength = StrLengthW(pwzBuffer);

	if((pUI->Buffer = StrCopyW(pwzBuffer, dwLength)) == 0)
		return FALSE;

	pUI->Length = dwLength * 2;
	pUI->MaximumLength = dwLength * 2;

	return TRUE;
}

void String_FreeUnicodeString(PUNICODE_STRING pUI)
{
	if(pUI == 0)
		return;

	if(pUI->Buffer != 0)
	{
		memfree(pUI->Buffer);
		memzero(pUI, sizeof(UNICODE_STRING));
	}
}