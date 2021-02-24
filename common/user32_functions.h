#pragma once
#include <Windows.h>

typedef int (WINAPIV* ptwsprintfW)(
	_Out_ LPWSTR,
	_In_ _Printf_format_string_ LPCWSTR,
	...);

typedef BOOL (WINAPI* ptGetCursorPos)(
	_Out_ LPPOINT lpPoint
	);

typedef BOOL (WINAPI* ptTranslateMessage)(
  _In_ const MSG *lpMsg
);

typedef BOOL (WINAPI* ptGetKeyboardState)(
  _Out_ PBYTE lpKeyState
);

typedef int (WINAPI* ptToUnicode)(
  _In_           UINT   wVirtKey,
  _In_           UINT   wScanCode,
  _In_opt_ const BYTE   *lpKeyState,
  _Out_          LPWSTR pwszBuff,
  _In_           int    cchBuff,
  _In_           UINT   wFlags
);
