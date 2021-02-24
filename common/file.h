#pragma once
#include "bot_structs.h"

BOOL File_WriteBuffer(const LPWSTR pwzPath, const LPVOID lpBuffer, DWORD dwLength, BOOL bAppend);
BOOL File_CreateDirectory(const LPWSTR pwzPath);
BOOL File_GetInfo(HANDLE hFile, PFILE_STANDARD_INFORMATION pFsi);
BOOL File_GetSize(HANDLE hFile, PDWORD pdwFileSize);
BOOL File_Copy(const LPWSTR pwzOriginalNtPath, const LPWSTR pwzNewNtPath, BOOL bDeleteOriginal);
BOOL File_DosPathToNtPath(LPWSTR* ppwzPath);
BOOL File_Delete(const LPWSTR pwzNtPath);