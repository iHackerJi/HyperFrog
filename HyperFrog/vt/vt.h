#pragma once
#include <intrin.h>
#include "../tools/tools.h"
#include "ia32.h"
#include "../ExportFunction.h"
#include "vt_asm.h"

#define		FrogTag	'Frog'
#define        FrogExitTag  'Exit'
#define		HostStackSize PAGE_SIZE * 6
#define		Frog_SUCCESS(Status) (((FrogRetCode)(Status)) >= 0)
#define		FrogExFreePool(mem) 	ExFreePoolWithTag(mem, FrogTag)

#define		MAKEQWORD(low, hi) ((((ULONGLONG)low) & 0xFFFFFFFF) | ((((ULONGLONG)hi) & 0xFFFFFFFF) << 32))
#define		LODWORD(qword) (((ULONGLONG)(qword)) & 0xFFFFFFFF)
#define		HIDWORD(qword) ((((ULONGLONG)(qword)) >> 32) & 0xFFFFFFFF)

typedef struct _VmxIoBitMap {
	PVOID	BitMap;
	PVOID	BitMapA;
	PVOID	BitMapB;
}VmxIoBitMap,*pVmxIoBitMap;

typedef struct _FrogVmx {
	BOOLEAN			OrigCr4BitVmxeIsSet;
    BOOLEAN             VmxIsEnable;
	
	KPROCESSOR_STATE		HostState;

	pVmControlStructure		VmxOnArea;
	pVmControlStructure		VmxVmcsArea;
	VmxIoBitMap					VmxBitMapArea;
	PVOID								VmxHostStackArea;

	PHYSICAL_ADDRESS		VmxOnAreaPhysicalAddr;
	PHYSICAL_ADDRESS		VmxVmcsAreaPhysicalAddr;

	BOOLEAN			HyperIsEnable;
	ULONG			ProcessorNumber;

	pEptPointer EptPoniter;
}FrogVmx, *pFrogVmx;

typedef struct _FrogCpu {
	ULONG							ProcessOrNumber;
	Ia32FeatureControlMsr	OrigFeatureControlMsr;
	pFrogVmx						pForgVmxEntrys;
    ULONG64						KernelCr3;
    ULONG64                        KernelGsBase;
}FrogCpu,*pFrogCpu;

typedef		enum _FrogRetCode {
	FrogSuccess,
	NoSupportHyper,
	ForgAllocatePoolError,
	ForgVmxOnError,
	ForgVmClearError,
	ForgVmptrldError,
	FrogUnloadError
}FrogRetCode;


typedef struct _Frog_GuestContext
{
	ULONG64 Rax;
	ULONG64 Rcx;
	ULONG64 Rdx;
	ULONG64 Rbx;
    ULONG64 Rsp;
	ULONG64 Rbp;
	ULONG64 Rsi;
	ULONG64 Rdi;
	ULONG64 R8;
	ULONG64 R9;
	ULONG64 R10;
	ULONG64 R11;
	ULONG64 R12;
	ULONG64 R13;
	ULONG64 R14;
	ULONG64 R15;
}Frog_GuestContext, *pFrog_GuestContext;

FrogRetCode 	Frog_EnableHyper();
FrogRetCode Frog_DisableHyper();