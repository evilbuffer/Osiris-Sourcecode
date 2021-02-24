#pragma once
#include "api_structs.h"

typedef struct
{
	apis_t api;
	modules_t modules;

	crc_t crc;

	wchar_t wzBotPath[255];

	HMODULE hLocal;
} bot_t;