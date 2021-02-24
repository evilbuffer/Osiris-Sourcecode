#include "registry.h"
#include "mem.h"
#include "string.h"

extern bot_t bot;

BOOL Registry_OpenKeyEx(const LPWSTR pwzKeyPath, HANDLE* phRegistry, ACCESS_MASK am)
{
	OBJECT_ATTRIBUTES obj;
	UNICODE_STRING us;
	BOOL bSuccess;

	if(!String_ToUnicodeString(&us, pwzKeyPath))
		return FALSE;

	bSuccess = FALSE;

	memzero(&obj, sizeof(OBJECT_ATTRIBUTES));
	obj.Length = sizeof(OBJECT_ATTRIBUTES);
	obj.Attributes = OBJ_CASE_INSENSITIVE;
	obj.ObjectName = &us;

	if(CWA(NtOpenKey)(phRegistry, am, &obj) >= 0)
		bSuccess = TRUE;

	return bSuccess;
}

BOOL Registry_ReadValueEx(const LPWSTR pwzKeyPath, const LPWSTR pwzName, LPWSTR* ppwzValue)
{
	HANDLE hKey;
	UNICODE_STRING us;
	KEY_VALUE_PARTIAL_INFORMATION* kvpi;
	KEY_VALUE_PARTIAL_INFORMATION kvvpi;
	DWORD dwSize = 0;
	BOOL bSuccess = FALSE;

	if(!String_ToUnicodeString(&us, pwzName))
		return FALSE;

	if(Registry_OpenKeyEx(pwzKeyPath, &hKey, KEY_READ))
	{
		memzero(&kvvpi, sizeof(KEY_VALUE_PARTIAL_INFORMATION));

		CWA(NtQueryValueKey)(hKey, &us, KeyValuePartialInformation, &kvvpi, sizeof(KEY_VALUE_PARTIAL_INFORMATION), &dwSize);

		if(dwSize != 0)
		{
			if((kvpi = memalloc(dwSize)) != 0)
			{
				if(CWA(NtQueryValueKey)(hKey, &us, KeyValuePartialInformation, kvpi, dwSize, &dwSize) >= 0)
				{
					if((*ppwzValue = memalloc(kvpi->DataLength + 2)) != 0)
					{
						memcopy(*ppwzValue, kvpi->Data, kvpi->DataLength);
						bSuccess = TRUE;
					}
				}

				memfree(kvpi);
			}
		}

		CWA(NtClose)(hKey);
	}

	return bSuccess;
}

static LPWSTR _GetRegistryStartPath(int iHive)
{
	LPWSTR pwzPath;
	UNICODE_STRING us;

	pwzPath = 0;

	if(iHive == HIVE_HKEY_LOCAL_MACHINE)
	{
		if(!StrConcatW(&pwzPath, L"\\Registry\\Machine\\"))
			return 0;
	}
	else
	{
		memzero(&us, sizeof(UNICODE_STRING));

		if(CWA(RtlFormatCurrentUserKeyPath(&us)) >= 0)
		{
			if(!StrConcatW(&pwzPath, us.Buffer))
				return 0;
		}
	}

	if(!EndsWithSlashW(pwzPath))
	{
		if(!StrConcatW(&pwzPath, L"\\"))
		{
			memfree(pwzPath);
			pwzPath = 0;
		}
	}

	return pwzPath;
}

BOOL Registry_ReadValue(int iHive, const LPWSTR pwzPath, const LPWSTR pwzName, LPWSTR* ppwzValue)
{
	LPWSTR pwzRegistryPath;
	BOOL bSuccess = FALSE;

	if((pwzRegistryPath = _GetRegistryStartPath(iHive)) == 0)
		return FALSE;

	if(StrConcatW(&pwzRegistryPath, pwzPath))
	{
		bSuccess = Registry_ReadValueEx(pwzRegistryPath, pwzName, ppwzValue);	
	}

	memfree(pwzRegistryPath);

	return bSuccess;
}