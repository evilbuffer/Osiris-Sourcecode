#pragma once
#include <winsock2.h>
#include <Windows.h>
#include <Ws2tcpip.h>

typedef int (WINAPI* ptWSAStartup)(
	_In_ WORD wVersionRequired,
	_Out_ LPWSADATA lpWSAData);

typedef int (WINAPI* ptWSACleanup)(void);

typedef SOCKET (WINAPI* ptsocket)(
	_In_ int af,
	_In_ int type,
	_In_ int protocol);

typedef int (WINAPI* ptconnect)(
	_In_ SOCKET s,const struct sockaddr FAR *name,
	_In_ int namelen);

typedef int (WINAPI* ptclosesocket)(IN SOCKET s);

typedef int (WINAPI* ptsend)(
	_In_ SOCKET s,const char FAR * buf,
	_In_ int len,
	_In_ int flags);

typedef int (WINAPI* ptrecv)(
	_In_ SOCKET s,char FAR * buf,
	_In_ int len,
	_In_ int flags);

typedef u_short (WINAPI* pthtons)(IN u_short hostshort);

typedef unsigned long (WINAPI* ptinet_addr)(IN const char FAR * cp);

typedef struct hostent* (WINAPI* ptgethostbyname)(
	_In_ const char *name
	);


typedef int (WINAPI* ptgetaddrinfo)(
					          PCSTR      pNodeName,
					          PCSTR      pServiceName,
					    const ADDRINFOA  *pHints,
					             PADDRINFOA *ppResult
					   );

typedef int (WINAPI* ptGetAddrInfoW)(
						       PCWSTR     pNodeName,
						       PCWSTR     pServiceName,
						 const ADDRINFOW  *pHints,
						          PADDRINFOW *ppResult
						);

typedef VOID (WINAPI* ptfreeaddrinfo)(PADDRINFOA pAddrInfo);

typedef int (WINAPI* pt__WSAFDIsSet)(
   SOCKET fd,
   fd_set *set
);
typedef int (WINAPI* ptbind)(SOCKET s, const struct sockaddr FAR * name, int namelen);
typedef int (WINAPI* ptlisten)(
    IN SOCKET s,
    IN int backlog
    );
typedef SOCKET (WINAPI* ptaccept)(SOCKET s, struct sockaddr FAR * addr, int FAR * addrlen);
typedef int (WINAPI* ptselect)(int nfds, fd_set FAR * readfds, fd_set FAR * writefds, fd_set FAR * exceptfds, const struct timeval FAR * timeout);