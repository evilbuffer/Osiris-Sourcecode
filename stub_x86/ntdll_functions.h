#pragma once
#include <Windows.h>
#include <NTSecAPI.h>
#include "ntheader.h"

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef ULONG (WINAPI* ptRtlRandomEx)(
	_Inout_ PULONG Seed
	);

typedef NTSTATUS (WINAPI* ptNtCreateUserProcess)(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PVOID ProcessParameters, PVOID CreateInfo, PVOID AttributeList);

typedef NTSTATUS (WINAPI* ptNtCreateThread)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, LPVOID ClientId, PCONTEXT ThreadContext, LPVOID InitialTeb, BOOLEAN CreateSuspended);


typedef NTSTATUS (WINAPI* ptNtQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      int ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);

#define STATUS_SUCCESS                    ((NTSTATUS)0x00000000)
#define RVATOVA( base, offset ) ( (DWORD)base + (DWORD)offset )

typedef NTSYSAPI NTSTATUS(NTAPI *ptNtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);

typedef NTSTATUS (WINAPI* ptLdrLoadDll)(PWCHAR pathToFile, ULONG flags, PUNICODE_STRING moduleFileName, PHANDLE moduleHandle);

typedef NTSTATUS (WINAPI* ptLdrGetDllHandle)(
	IN PWORD                pwPath OPTIONAL,
	IN PVOID                Unused OPTIONAL,
	IN PUNICODE_STRING      ModuleFileName,
	OUT PHANDLE             pHModule);

typedef NTSTATUS (WINAPI* ptNtWriteVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL);

typedef NTSTATUS (WINAPI* ptNtAllocateVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN ULONG                ZeroBits,
	IN OUT PULONG           RegionSize,
	IN ULONG                AllocationType,
	IN ULONG                Protect);

typedef NTSTATUS (WINAPI* ptNtProtectVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection);

typedef NTSTATUS (WINAPI* ptNtDeviceIoControlFile)(
	IN HANDLE               FileHandle,
	IN HANDLE               Event OPTIONAL,
	IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
	IN PVOID                ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK    IoStatusBlock,
	IN ULONG                IoControlCode,
	IN PVOID                InputBuffer OPTIONAL,
	IN ULONG                InputBufferLength,
	OUT PVOID               OutputBuffer OPTIONAL,
	IN ULONG                OutputBufferLength);

typedef NTSTATUS (WINAPI* ptNtSetContextThread)(
	IN HANDLE               ThreadHandle,
	IN PCONTEXT             Context);

typedef NTSTATUS (WINAPI* ptNtOpenProcess)(
	OUT PHANDLE             ProcessHandle,
	IN ACCESS_MASK          AccessMask,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PCLIENT_ID           ClientId);

typedef NTSTATUS (WINAPI* ptNtClose)(
	_In_ HANDLE Handle
	);

typedef NTSTATUS (WINAPI* ptNtCreateFile)(
	_Out_    PHANDLE            FileHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_    PIO_STATUS_BLOCK   IoStatusBlock,
	_In_opt_ PLARGE_INTEGER     AllocationSize,
	_In_     ULONG              FileAttributes,
	_In_     ULONG              ShareAccess,
	_In_     ULONG              CreateDisposition,
	_In_     ULONG              CreateOptions,
	_In_     PVOID              EaBuffer,
	_In_     ULONG              EaLength
	);