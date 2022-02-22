#pragma once

void	Frog_PrintfEx(char *format, ...);
ULONG RvaToOffset(PIMAGE_NT_HEADERS pnth, ULONG Rva, ULONG FileSize);
void sleep(LONG milliseconds);
VOID* GetKernelModeLinerAddress(ULONG_PTR cr3, ULONG_PTR user_mode_address, size_t size);
VOID FreeKernelModeLinerAddress(VOID* p, size_t size);
#ifdef DEBUG
#define		FrogBreak()		__debugbreak()
#define		FrogPrint(format, ...)	Frog_PrintfEx((format), __VA_ARGS__)  
#endif

#ifdef RELEASE

#define		FrogBreak()			
#define		FrogPrint(...)	

#endif