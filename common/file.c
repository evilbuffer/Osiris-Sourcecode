#include "file.h"

#include "mem.h"
#include "utils.h"

extern bot_t bot;

HANDLE _GetFileHandle(const LPWSTR pwzPath)
{
	HANDLE hFile;
	OBJECT_ATTRIBUTES os;
	IO_STATUS_BLOCK io;

	memzero(&io, sizeof(IO_STATUS_BLOCK));
	memzero(&os, sizeof(OBJECT_ATTRIBUTES));

	os.Length = sizeof(OBJECT_ATTRIBUTES);

	if((os.ObjectName = memalloc(sizeof(UNICODE_STRING))) == 0)
		return INVALID_HANDLE_VALUE;

	CWA(RtlInitUnicodeString)(os.ObjectName, pwzPath);
	os.Attributes = OBJ_CASE_INSENSITIVE;
	
	hFile = INVALID_HANDLE_VALUE;

	if(!(CWA(NtCreateFile)(&hFile, FILE_GENERIC_READ | /*FILE_GENERIC_WRITE |*/ FILE_APPEND_DATA/*GENERIC_ALL | SYNCHRONIZE*/, &os, &io, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_RANDOM_ACCESS, 0, 0) >= 0))
		hFile = INVALID_HANDLE_VALUE;
	
	memfree(os.ObjectName);

	return hFile;
}

BOOL File_Open(HANDLE* phFile, const LPWSTR pwzNtPath, ACCESS_MASK am, ULONG ulCreateDisposition)
{
	UNICODE_STRING us;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK io;
	BOOL bSuccess;

	*phFile = INVALID_HANDLE_VALUE;

	if(!String_ToUnicodeString(&us, pwzNtPath))
		return FALSE;

	memzero(&io, sizeof(IO_STATUS_BLOCK));

	memzero(&oa, sizeof(OBJECT_ATTRIBUTES));
	oa.Length = sizeof(OBJECT_ATTRIBUTES);
	oa.ObjectName = &us;
	oa.Attributes = OBJ_CASE_INSENSITIVE;

	bSuccess = FALSE;

	if(CWA(NtCreateFile)(phFile, am, &oa, &io, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, ulCreateDisposition, FILE_SYNCHRONOUS_IO_NONALERT | FILE_RANDOM_ACCESS, 0, 0) >= 0)
		bSuccess = TRUE;

	String_FreeUnicodeString(&us);

	return bSuccess;
}

BOOL File_Write(HANDLE hFile, const LPVOID lpBuffer, DWORD dwLength)
{
	IO_STATUS_BLOCK io;
	
	if(CWA(NtWriteFile)(hFile, 0, 0, 0, &io, lpBuffer, dwLength, 0, 0) >= 0)
		return TRUE;

	return FALSE;
}

BOOL File_Read(HANDLE hFile, LPVOID* lppBuffer, DWORD dwLength, PDWORD pdwReadLength)
{
	IO_STATUS_BLOCK io;
	LARGE_INTEGER li;

	li.LowPart = 0;
	li.HighPart = 0;

	if((*lppBuffer = memalloc(dwLength)) != 0)
	{
		if(CWA(NtReadFile)(hFile, 0, 0, 0, &io, *lppBuffer, dwLength, &li, 0) >= 0)
		{
			*pdwReadLength = io.Information;
			return TRUE;
		}
	}

	return FALSE;
}

BOOL File_WriteBuffer(const LPWSTR pwzPath, const LPVOID lpBuffer, DWORD dwLength, BOOL bAppend)
{
	BOOL bSuccess;
	HANDLE hFile;

	bSuccess = FALSE;

	if(File_Open(&hFile, pwzPath, bAppend == TRUE ? FILE_GENERIC_READ | FILE_APPEND_DATA : FILE_GENERIC_WRITE, FILE_OPEN_IF))
	{
		bSuccess = File_Write(hFile, lpBuffer, dwLength);

		CWA(NtClose)(hFile);
	}

	return bSuccess;
}

BOOL File_ReadBuffer(const LPWSTR pwzNtPath, LPVOID* lppBuffer, PDWORD pdwLength)
{
	BOOL bSuccess;
	HANDLE hFile;
	DWORD dwFileSize;

	bSuccess = FALSE;

	if(File_Open(&hFile, pwzNtPath, GENERIC_READ, FILE_OPEN))
	{
		if(File_GetSize(hFile, &dwFileSize))
			bSuccess = File_Read(hFile, lppBuffer, dwFileSize, pdwLength);
	}

	return bSuccess;
}

BOOL File_CreateDirectory(const LPWSTR pwzNtPath)
{
	IO_STATUS_BLOCK io;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING us;
	HANDLE hFile;
	BOOL bSuccess;

	if(!String_ToUnicodeString(&us, pwzNtPath))
		return FALSE;

	memzero(&io, sizeof(IO_STATUS_BLOCK));
	memzero(&oa, sizeof(OBJECT_ATTRIBUTES));

	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.Length = sizeof(OBJECT_ATTRIBUTES);
	oa.ObjectName = &us;

	bSuccess = FALSE;

	if(CWA(NtCreateFile)(&hFile, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &oa, &io, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0) >= 0)
	{
		bSuccess = TRUE;
		CWA(NtClose)(hFile);
	}

	String_FreeUnicodeString(&us);

	return bSuccess;
}

BOOL File_Copy(const LPWSTR pwzOriginalNtPath, const LPWSTR pwzNewNtPath, BOOL bDeleteOriginal)
{
	BOOL bSuccess;
	LPVOID lpFile;
	DWORD dwFileSize;

	if(!File_ReadBuffer(pwzOriginalNtPath, &lpFile, &dwFileSize))
		return FALSE;

	bSuccess = FALSE;

	if(File_WriteBuffer(pwzNewNtPath, lpFile, dwFileSize, FALSE))
	{
		if(bDeleteOriginal)
			File_Delete(pwzOriginalNtPath);

		bSuccess = TRUE;
	}

	memfree(lpFile);

	return bSuccess;
}

BOOL File_Delete(const LPWSTR pwzNtPath)
{
	BOOL bSuccess;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING us;
 
	if(!String_ToUnicodeString(&us, pwzNtPath))
		return FALSE;

	memzero(&oa, sizeof(OBJECT_ATTRIBUTES));
	bSuccess = FALSE;

	oa.ObjectName = &us;
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.Length = sizeof(OBJECT_ATTRIBUTES);

	if(CWA(NtDeleteFile)(&oa) >= 0)
		bSuccess = TRUE;

	String_FreeUnicodeString(&us);

	return bSuccess;
}

BOOL File_IsValidNtPath(const LPWSTR pwzPath)
{
	BOOL bSuccess;
	LPWSTR pwzData;

	bSuccess = FALSE;

	if((pwzData = StrCopyW(pwzPath, 4)) != 0)
	{
		bSuccess = StrCompareW(pwzPath, L"\\??\\");

		memfree(pwzData);
	}

	return bSuccess;
}

BOOL File_DosPathToNtPath(LPWSTR* ppwzPath)
{
	LPWSTR pwzNtPath;

	if(File_IsValidNtPath(*ppwzPath))
		return TRUE;

	pwzNtPath = 0;

	if(StrConcatW(&pwzNtPath, L"\\??\\") && StrConcatW(&pwzNtPath, *ppwzPath))
	{
		memfree(*ppwzPath);
		*ppwzPath = pwzNtPath;

		return TRUE;
	}

	if(pwzNtPath != 0)
		memfree(pwzNtPath);

	return FALSE;
}

BOOL File_GetInfo(HANDLE hFile, PFILE_STANDARD_INFORMATION pFsi)
{
	IO_STATUS_BLOCK io;
	
	memzero(&io, sizeof(IO_STATUS_BLOCK));
	memzero(pFsi, sizeof(FILE_STANDARD_INFORMATION));

	if(CWA(NtQueryInformationFile)(hFile, &io, pFsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation) >= 0)
		return TRUE;
	
	return FALSE;
}

BOOL File_GetSize(HANDLE hFile, PDWORD pdwFileSize)
{
	FILE_STANDARD_INFORMATION fsi;

	*pdwFileSize = 0;

	if(File_GetInfo(hFile, &fsi))
	{
		*pdwFileSize = fsi.AllocationSize.LowPart;

		return TRUE;
	}

	return FALSE;
}