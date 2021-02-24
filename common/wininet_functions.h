#pragma once
#include <Windows.h>
#include <Wininet.h>

typedef HINTERNET (WINAPI* ptInternetOpenW)( LPCWSTR lpszAgent,DWORD dwAccessType,LPCWSTR lpszProxy,LPCWSTR lpszProxyBypass, DWORD dwFlags);
typedef HINTERNET (WINAPI* ptInternetConnectA)(HINTERNET hInternet,LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
typedef BOOL (WINAPI* ptHttpSendRequestA)(HINTERNET hRequest,LPCSTR lpszHeaders,DWORD dwHeadersLength,LPVOID lpOptional,DWORD dwOptionalLength);
typedef BOOL (WINAPI* ptHttpSendRequestW)(HINTERNET hRequest,LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional,DWORD dwOptionalLength);
typedef HINTERNET (WINAPI* ptHttpOpenRequestA)(HINTERNET hConnect,LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer,LPCSTR FAR * lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
typedef BOOL (WINAPI* ptInternetCloseHandle)( HINTERNET hInternet);
typedef BOOL(WINAPI* ptInternetReadFile)(HINTERNET hFile,LPVOID lpBuffer, DWORD dwNumberOfBytesToRead,LPDWORD lpdwNumberOfBytesRead);
typedef HINTERNET (WINAPI* ptHttpOpenRequestW)( HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
typedef HINTERNET (WINAPI* ptInternetConnectW)( HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);