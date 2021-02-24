#include <Windows.h>
#include "bot.h"

DWORD Bot_GenerateSeed(DWORD dwObjectSeed)
{
	return BOT_VERSION + dwObjectSeed;
}