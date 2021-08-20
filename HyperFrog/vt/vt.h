#pragma once
#include <intrin.h>
#include "PublicHeader.h"
#include "ia32.h"
#include "ExportFunction.h"


#define		FrogTag	'Frog'
#define		HostStackSize PAGE_SIZE * 3

typedef struct _FrogVmx {

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


pFrogVmx		pForgVmxEntrys = NULL;




typedef		enum _FrogRetCode {
	FrogSuccess,
	NoSupportHyper,
	ForgAllocateError,

}FrogRetCode;


