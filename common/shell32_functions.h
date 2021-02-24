#pragma once
#include <Windows.h>
#include <ShlObj.h>

typedef HRESULT (WINAPI* ptSHGetFolderPathW)(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPWSTR pszPath);