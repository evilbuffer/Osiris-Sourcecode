#include "hook.h"

#include "hde32.h"

#include "mem.h"

extern bot_t bot;

void SafeMemcpyPadded(LPVOID destination, LPVOID source, DWORD size)
{
	BYTE SourceBuffer[8];

	if (size > 8)
		return;

	//Pad the source buffer with bytes from destination
	memcopy(SourceBuffer, destination, 8);
	memcopy(SourceBuffer, source, size);

#ifndef NO_INLINE_ASM
	__asm
	{
		lea esi, SourceBuffer;
		mov edi, destination;

		mov eax, [edi];
		mov edx, [edi + 4];
		mov ebx, [esi];
		mov ecx, [esi + 4];

		lock cmpxchg8b[edi];
	}
#else
	_InterlockedCompareExchange64((LONGLONG *)destination, *(LONGLONG *)SourceBuffer, *(LONGLONG *)destination);
#endif
}

BOOL WINAPI HookFunction(LPVOID lpFunctionAddress, LPVOID proxy, LPVOID original, PDWORD length)
{
	DWORD TrampolineLength = 0, OriginalProtection;
	hde32s disam;
	BYTE Jump[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

	if (!lpFunctionAddress)
		return FALSE;

	//disassemble length of each instruction, until we have 5 or more bytes worth
	while (TrampolineLength < 5)
	{
		LPVOID InstPointer = (LPVOID)((DWORD)lpFunctionAddress + TrampolineLength);
		TrampolineLength += hde32_disasm(InstPointer, &disam);
	}

	//Build the trampoline buffer
	memcopy(original, lpFunctionAddress, TrampolineLength);
	*(DWORD *)(Jump + 1) = ((DWORD)lpFunctionAddress + TrampolineLength) - ((DWORD)original + TrampolineLength + 5);
	memcopy((LPVOID)((DWORD)original + TrampolineLength), Jump, 5);

	//Make sure the function is writable
	if (!bot.api.pVirtualProtect(lpFunctionAddress, TrampolineLength, PAGE_EXECUTE_READWRITE, &OriginalProtection))
		return FALSE;

	//Build and atomically write the hook
	*(DWORD *)(Jump + 1) = (DWORD)proxy - (DWORD)lpFunctionAddress - 5;
	SafeMemcpyPadded(lpFunctionAddress, Jump, 5);

	//Restore the original page protection
	bot.api.pVirtualProtect(lpFunctionAddress, TrampolineLength, OriginalProtection, &OriginalProtection);

	//Clear CPU instruction cache
	bot.api.pFlushInstructionCache(bot.api.pGetCurrentProcess(), lpFunctionAddress, TrampolineLength);

	*length = TrampolineLength;
	return TRUE;
}

BOOL UnhookFunction(CHAR *dll, CHAR *name, LPVOID original, DWORD length)
{
	LPVOID FunctionAddress;
	DWORD OriginalProtection;

	FunctionAddress = GetProcAddress(GetModuleHandleA(dll), name);
	if (!FunctionAddress)
		return FALSE;

	if (!bot.api.pVirtualProtect(FunctionAddress, length, PAGE_EXECUTE_READWRITE, &OriginalProtection))
		return FALSE;

	SafeMemcpyPadded(FunctionAddress, original, length);

	bot.api.pVirtualProtect(FunctionAddress, length, PAGE_EXECUTE_READWRITE, &OriginalProtection);

	bot.api.pFlushInstructionCache(bot.api.pGetCurrentProcess(), FunctionAddress, length);

	return TRUE;
}