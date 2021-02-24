#include "os_info.h"

#include "utils.h"
#include "mem.h"
#include "string.h"

extern bot_t bot;

LPSTR _GetPCUsername()
{
	DWORD dwSize = 255;
	char szUsername[255];
	memzero(&szUsername, sizeof(szUsername));

	if (bot.api.pGetUserNameA(szUsername, &dwSize))
	{
		return StrCopyA(szUsername, dwSize);
	}

	return NULL;
}

DWORD _GetOperatingSystem()
{
	DWORD dwOSVersion = 0;

	OSVERSIONINFOEXW osvi;
	memzero(&osvi, sizeof(OSVERSIONINFOEXW));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

	if (bot.api.pGetVersionExW((OSVERSIONINFOW*)&osvi))
	{
		if (osvi.wProductType == VER_NT_WORKSTATION)
		{
			if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0)
				dwOSVersion = WINDOWS_2000;
			else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1 || osvi.dwMinorVersion == 2)
				dwOSVersion = WINDOWS_XP;
			else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0)
				dwOSVersion = WINDOWS_VISTA;
			else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1)
				dwOSVersion = WINDOWS_7;
			else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 2)
				dwOSVersion = WINDOWS_8;
			else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 3)
				dwOSVersion = WINDOWS_8_1;
			else if (osvi.dwMajorVersion == 10)
				dwOSVersion = WINDOWS_10;
		}
		else if (osvi.wProductType == VER_NT_DOMAIN_CONTROLLER || osvi.wProductType == VER_NT_SERVER)
		{
			if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2) dwOSVersion = WINDOWS_SERVER_2003;
			else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0) dwOSVersion = WINDOWS_SERVER_2008;
			else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1) dwOSVersion = WINDOWS_SERVER_2008;
			else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 2 || osvi.dwMinorVersion == 3) dwOSVersion = WINDOWS_SERVER_2012;
			else if (osvi.dwMajorVersion == 10) dwOSVersion = WINDOWS_SERVER_2016;
		}
	}

	return dwOSVersion;
}

LPVOID WINAPI GetPCInfo(void)
{
	static pc_info_t info;
	memzero(&info, sizeof(pc_info_t));

	info.pszUsername = _GetPCUsername();
	info.iOS = _GetOperatingSystem();
	info.Is64Bit = IsOperatingSystem64Bit();
	info.dwSerialNumber = GetSerialNumber();

	return (LPVOID)&info;
}