#pragma once
#include <Windows.h>
#include <urlmon.h>
typedef HRESULT (WINAPI* ptURLDownloadToFileW)(_In_opt_ LPUNKNOWN, _In_ LPCWSTR, _In_opt_ LPCWSTR, DWORD, _In_opt_ LPBINDSTATUSCALLBACK);