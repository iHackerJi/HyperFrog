#pragma once

void	Frog_PrintfEx(char *format, ...);
ULONG RvaToOffset(PIMAGE_NT_HEADERS pnth, ULONG Rva, ULONG FileSize);
#ifdef DEBUG
#define		FrogBreak()		__debugbreak()
#define		FrogPrint(format, ...)	Frog_PrintfEx((format), __VA_ARGS__)  
#endif

#ifdef RELEASE

#define		FrogBreak()			
#define		FrogPrint(...)	

#endif