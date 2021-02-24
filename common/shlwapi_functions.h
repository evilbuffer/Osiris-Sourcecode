#pragma once
#include <Windows.h>
#include <Shlwapi.h>

typedef int (WINAPI* ptwvsprintfA)(LPSTR, LPCSTR, va_list arglist);
typedef int (WINAPI* ptwvsprintfW)(LPWSTR, LPCWSTR, va_list arglist);
typedef LPSTR (WINAPI* ptStrStrA)(LPCSTR lpFirst, LPCSTR lpSrch);
typedef LPWSTR (WINAPI* ptStrStrW)(LPCWSTR lpFirst, LPCWSTR lpSrch);