#include "..\common\bot_structs.h"

#include "..\common\api.h"
#include "..\common\string.h"
#include "..\common\mem.h"
#include "..\common\crypto.h"
#include "..\common\utils.h"
#include "..\common\registry.h"
#include "..\common\file.h"

bot_t bot;

int main()
{
	LPVOID p;
	UNICODE_STRING ps;
	LPSTR pszData;
	DWORD dwLength, dwHash;
	LPWSTR pwzData;

	LPWSTR pwzValueReturned;

	DWORD dwProcessCount, dwModuleCount, i;
	utils_process_t* pProcesses;
	utils_module_t* pModules;

	utils_module_t mod;
	utils_process_t proc;

	memzero(&bot, sizeof(bot_t));

	if(!InitializeAPI())
		return 0;

	pszData = "NtQueryInformationFile";
	dwLength = StrLengthA(pszData);
	dwHash = Crypto_crc32Hash(pszData, dwLength);

	pwzData = L"chrome.dll";
	dwLength = StrLengthW(pwzData);
	dwHash = Crypto_crc32Hash(pwzData, dwLength * 2);

	pwzValueReturned = Utils_GetPath(PATH_DESKTOP);

	if(File_DosPathToNtPath(&pwzValueReturned))
	{
		if(File_CreateDirectory(L"test_dir"))
		{
			return 1;
		}
	}

	return 0;
}