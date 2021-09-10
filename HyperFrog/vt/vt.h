#pragma once
#include <intrin.h>
#include "PublicHeader.h"
#include "ia32.h"
#include "ExportFunction.h"
#include "vt_asm.h"


#define		FrogTag	'Frog'
#define		HostStackSize PAGE_SIZE * 6
#define		Frog_SUCCESS(Status) (((FrogRetCode)(Status)) >= 0)
#define		FrogExFreePool(mem) 	ExFreePoolWithTag(mem, FrogTag);

typedef struct _VmxIoBitMap {
	PVOID	BitMap;
	PVOID	BitMapA;
	PVOID	BitMapB;
}VmxIoBitMap,*pVmxIoBitMap;

typedef struct _FrogVmx {


	KPROCESSOR_STATE		HostState;
	ULONG64					HostCr3;

	pVmControlStructure		VmxOnArea;
	pVmControlStructure		VmxVmcsArea;
	VmxIoBitMap				VmxBitMapArea;
	PVOID					VmxHostStackArea;

	PHYSICAL_ADDRESS		VmxOnAreaPhysicalAddr;
	PHYSICAL_ADDRESS		VmxVmcsAreaPhysicalAddr;

	BOOLEAN			HyperIsEnable;
	ULONG			ProcessorNumber;

	pEptPointer EptPoniter;

}FrogVmx, *pFrogVmx;

typedef struct _FrogCpu {
	ULONG	ProcessOrNumber;
	pFrogVmx		pForgVmxEntrys;
}FrogCpu,*pFrogCpu;

typedef		enum _FrogRetCode {
	FrogSuccess,
	NoSupportHyper,
	ForgAllocatePoolError,
	ForgVmxOnError,
	ForgVmClearError,
	ForgVmptrldError
}FrogRetCode;



enum FrogSegment
{
	Frog_ES,
	Frog_CS,
	Frog_SS,
	Frog_DS,
	Frog_FS,
	Frog_GS,
	Frog_LDTR,
	Frog_TR
};


FrogRetCode 	Frog_EnableHyper();
