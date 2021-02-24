#pragma once
#include "modules.h"

#ifdef MODULE_KEYLOGGER
#include "..\common\bot_structs.h"

void Keylogger_TranslateMessage(const MSG* pMsg);
#endif