#pragma once

#define BOT_VERSION 0x1000

//ToDo: Randomize on each build
#define BOT_FILE_NAME_SEED 0x1231231
#define BOT_FOLDER_NAME_SEED 0x41231

DWORD Bot_GenerateSeed(DWORD dwObjectSeed);