#pragma once
#include <ntifs.h>



#ifdef DEBUG
	#define		FrogBreak()		__debugbreak()
	#define		FrogPrint(...)	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-]Frog : %s \r\n",__VA_ARGS__)
#endif

#ifdef RELEASE

#define		FrogBreak()			
#define		FrogPrint(...)	

#endif


