#pragma once
#include <Windows.h>

LPWSTR WINAPI StrCopyW(const LPWSTR pwzInput, DWORD dwLength);
DWORD WINAPI StrCopyWEnd(void);

LPSTR WINAPI StrCopyA(const LPSTR pszInput, DWORD dwLength);

DWORD WINAPI StrLengthW(const LPWSTR pwzInput);
DWORD WINAPI StrLengthWEnd(void);

DWORD WINAPI StrLengthA(const LPSTR pszInput);
DWORD WINAPI StrLengthAEnd(void);

LPWSTR WINAPI StrToLowerW(const LPWSTR pwzInput, DWORD dwLength);

LPWSTR WINAPI StrConcatExW(const LPWSTR pwzSource, DWORD dwSourceLength, const LPWSTR pwzData, DWORD dwDataLength);

LPWSTR WINAPI StrConcatW(const LPWSTR pwzSource, const LPWSTR pwzData);
DWORD WINAPI StrConcatWEnd(void);

BOOL WINAPI EndsWithSlashW(const LPWSTR pwzInput);
BOOL WINAPI StrCompareW(const LPWSTR pwzInput, const LPWSTR pwzData);
BOOL WINAPI StrCompareEndW(const LPWSTR pwzInput, const LPWSTR pwzData);
BOOL WINAPI StrCompareStartW(const LPWSTR pwzInput, const LPWSTR pwzData);
BOOL WINAPI StrCompareStartA(const LPSTR pszInput, const LPSTR pszData);

DWORD WINAPI StrIndexOfCharA(const char* pszInput, const char cData);
char* WINAPI StrCopyExA(const char* pszData, DWORD iOffset, DWORD iLength);
LPSTR* SplitString(const char* pszBuffer, char c, DWORD dwCount);
DWORD CharCountA(const char* pszBuffer, char c);
int _ToInt32A(LPSTR pstrStr, BOOL *pbSign);
int _ToInt32W(LPWSTR pstrStr, BOOL *pbSign);