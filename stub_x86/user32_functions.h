#pragma once
#include <Windows.h>

typedef int (WINAPIV* ptwsprintfW)(
	_Out_ LPWSTR,
	_In_ _Printf_format_string_ LPCWSTR,
	...);

typedef BOOL (WINAPI* ptGetCursorPos)(
	_Out_ LPPOINT lpPoint
	);
