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

typedef struct _FrogVmx {
	KPROCESSOR_STATE		HostState;
	ULONG64					HostCr3;

	pVmControlStructure		VmxOnArea;
	pVmControlStructure		VmxVmcsArea;
	PVOID		VmxBitMapArea;
	PVOID		VmxHostStackArea;

	PHYSICAL_ADDRESS		VmxOnAreaPhysicalAddr;
	PHYSICAL_ADDRESS		VmxVmcsAreaPhysicalAddr;
	PHYSICAL_ADDRESS		VmxBitMapAreaPhysicalAddr;

	BOOLEAN		HyperIsEnable;
	ULONG			ProcessorNumber;

	pEptPointer EptPoniter;

}FrogVmx, *pFrogVmx;

typedef		enum _FrogRetCode {
	FrogSuccess,
	NoSupportHyper,
	ForgAllocatePoolError,
	ForgVmxOnError,
	ForgVmClearError,
	ForgVmptrldError
}FrogRetCode;



FrogRetCode 	Frog_EnableHyper();
