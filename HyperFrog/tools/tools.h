#pragma once
#include <ntifs.h>
#include <vadefs.h>
#include <stdarg.h>
#include <ntstrsafe.h>

void	Frog_PrintfEx(char *format, ...);

#ifdef DEBUG
#define		FrogBreak()		__debugbreak()
#define		FrogPrint(format, ...)	Frog_PrintfEx((format), __VA_ARGS__)  
#endif

#ifdef RELEASE

#define		FrogBreak()			
#define		FrogPrint(...)	

#endif