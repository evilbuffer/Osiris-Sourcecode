#pragma once
#include <Windows.h>

typedef BOOL (WINAPI* ptGetUserNameA)(
	_Out_writes_to_opt_(*pcbBuffer, *pcbBuffer) LPSTR lpBuffer,
	_Inout_ LPDWORD pcbBuffer
	);