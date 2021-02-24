#pragma once
#include <winsock.h>

typedef int (WINAPI* ptWSAStartup)(
	_In_ WORD wVersionRequired,
	_Out_ LPWSADATA lpWSAData);

typedef int (WINAPI* ptWSACleanup)(void);

typedef SOCKET (WINAPI* ptsocket)(
	_In_ int af,
	_In_ int type,
	_In_ int protocol);

typedef int (WINAPI* ptconnect)(
	_In_ SOCKET s,
	_In_reads_bytes_(namelen) const struct sockaddr FAR *name,
	_In_ int namelen);

typedef int (WINAPI* ptclosesocket)(IN SOCKET s);

typedef int (WINAPI* ptsend)(
	_In_ SOCKET s,
	_In_reads_bytes_(len) const char FAR * buf,
	_In_ int len,
	_In_ int flags);

typedef int (WINAPI* ptrecv)(
	_In_ SOCKET s,
	_Out_writes_bytes_to_(len, return) __out_data_source(NETWORK) char FAR * buf,
	_In_ int len,
	_In_ int flags);