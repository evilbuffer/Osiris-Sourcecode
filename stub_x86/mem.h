#pragma once
#include "api_structs.h"

void WINAPI memInit(void);

LPVOID WINAPI memalloc(DWORD dwSize);
DWORD WINAPI memallocEnd(void);

void WINAPI memfree(void* pData);
DWORD WINAPI memfreeEnd(void);

void WINAPI memzero(LPVOID lpData, DWORD dwLength);
DWORD WINAPI memzeroEnd(void);

void WINAPI memcopy(void* pDestination, const void* pSource, DWORD dwSize);
DWORD WINAPI memcopyEnd(void);

LPVOID WINAPI memrealloc(void *old, SIZE_T size);
BOOL WINAPI memreallocEx(void *old, DWORD size);