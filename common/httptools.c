#include "httptools.h"

#include "mem.h"
#include "string.h"

LPSTR ParseURLFromBuffer(const LPSTR pszBuffer)
{
	LPSTR pszHost, pszPage, pszURL;
	DWORD dwHostLength, dwPageLength, dwURLLength;

	pszURL = NULL;

	if((pszPage = StrGetBetweenA(pszBuffer, "GET ", " HTTP/1.1")) == NULL)
	{
		if((pszPage = StrGetBetweenA(pszBuffer, "POST ", " HTTP/1.1")) == NULL)
			return NULL;
	}

	if((pszHost = StrGetBetweenA(pszBuffer, "Host: ", "\r\n")) == NULL)
		return NULL;

	dwHostLength = StrLengthA(pszHost);
	dwPageLength = StrLengthA(pszPage);
	dwURLLength = dwHostLength + dwPageLength;

	if((pszURL = (LPSTR)memalloc(dwURLLength + 1)) != NULL)
	{
		memcopy(pszURL, pszHost, dwHostLength);
		memcopy(pszURL + dwHostLength, pszPage, dwPageLength);
		pszURL[dwURLLength] = 0;
	}

	memfree(pszHost);
	memfree(pszPage);

	return pszURL;
}