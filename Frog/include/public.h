#pragma once
#include <windows.h>
#include <ImageHlp.h>
#include <stdio.h>
#include <shlwapi.h>
#include <subauth.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "ImageHlp.lib")

#include "SymbolShare.h"
#include "Frog.h"
#include "Tools.h"

#define DEVICE_NAME "\\\\.\\HyperFrog"

namespace global
{
    extern HANDLE	hFile;
    extern unsigned long listCount;
    extern HANDLE hProcess;
    extern char	CurrentDirName[MAX_PATH];
}
