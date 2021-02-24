#include "keylogger.h"

#ifdef MODULE_KEYLOGGER
void Keylogger_TranslateMessage(const MSG* pMsg)
{
	if(pMsg == NULL)
		return;

	if(pMsg->message == WM_KEYDOWN && pMsg->wParam != VK_ESCAPE)
	{
		
	}
}
#endif