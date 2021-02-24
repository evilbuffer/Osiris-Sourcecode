#pragma once
#include <Windows.h>

LPSTR ToStringA(const void* buffer, DWORD dwLength);

LPWSTR WINAPI StrCopyW(const LPWSTR pwzInput, DWORD dwLength);
DWORD WINAPI StrCopyWEnd(void);

LPSTR WINAPI StrCopyA(const LPSTR pszInput, DWORD dwLength);

DWORD WINAPI StrLengthW(const LPWSTR pwzInput);
DWORD WINAPI StrLengthWEnd(void);

DWORD WINAPI StrLengthA(const LPSTR pszInput);
DWORD WINAPI StrLengthAEnd(void);

LPWSTR WINAPI StrToLowerW(const LPWSTR pwzInput, DWORD dwLength);

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
int _vsprintfW(LPWSTR pBuf, int iBufSize, LPCWSTR pstrFormat, va_list arglist);
int _vsprintfA(LPSTR pBuf, int iBufSize, LPCSTR pstrFormat, va_list arglist);

LPSTR unicodeToAnsiEx(const LPWSTR source, int size);
LPWSTR ansiToUnicodeEx(LPSTR source, int size);

BOOL StrConcatA(LPSTR* ppszData, const LPSTR pszSource);
BOOL StrConcatExA(LPSTR* ppszData, DWORD dwCurrentLength, const LPSTR pszSource, DWORD dwLength);

BOOL StrConcatW(LPWSTR* ppwzData, const LPWSTR pwzSource);
BOOL StrConcatExW(LPWSTR* ppwzData, DWORD dwCurrentLength, const LPWSTR pwzSource, DWORD dwLength);

LPSTR StrGetBetweenA(const LPSTR buffer, const LPSTR before, const LPSTR after);
BOOL String_ToUnicodeString(PUNICODE_STRING pUI, const LPWSTR pwzBuffer);
void String_FreeUnicodeString(PUNICODE_STRING pUI);