#pragma once
#include "bot_structs.h"

enum REGISTRY_HIVE
{
	HIVE_HKEY_CURRENT_USER = 0,
	HIVE_HKEY_LOCAL_MACHINE = 1
};

BOOL Registry_OpenKeyEx(const LPWSTR pwzKeyPath, HANDLE* phRegistry, ACCESS_MASK am);
BOOL Registry_ReadValueEx(const LPWSTR pwzKeyPath, const LPWSTR pwzName, LPWSTR* ppwzValue);
BOOL Registry_ReadValue(int iHive, const LPWSTR pwzPath, const LPWSTR pwzName, LPWSTR* ppwzValue);