#pragma once

#define		FrogTag	'Frog'
#define     FrogExitTag  'Exit'
#define     FrogHookMsrTag  'HMsr'

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
}VmxIoBitMap, *pVmxIoBitMap;

typedef struct _FrogVmxEptInfo
{
    Eptp		   VmxEptp;
    DECLSPEC_ALIGN(PAGE_SIZE) EPML4E	PML4T[PML4E_ENTRY_COUNT];
    DECLSPEC_ALIGN(PAGE_SIZE) EPDPTE	PDPT[PDPTE_ENTRY_COUNT];
    DECLSPEC_ALIGN(PAGE_SIZE) EPDE_2MB  PDT[PDPTE_ENTRY_COUNT][PDE_ENTRY_COUNT];
}FrogVmxEptInfo, * PFrogVmxEptInfo;

typedef struct _FrogVmx {
    bool			HyperIsEnable;
	KPROCESSOR_STATE		HostState;

	FrogVmxEptInfo				VmxEptInfo;
	pVmControlStructure		VmxOnArea;
	pVmControlStructure		VmxVmcsArea;
	VmxIoBitMap					VmxBitMapArea;
	PVOID								VmxHostStackArea;

	ULONG64		VmxOnAreaPhysicalAddr;
    ULONG64		VmxVmcsAreaPhysicalAddr;
	ULONG			ProcessorNumber;

	ULONG64		VmxExitTime;
}FrogVmx, *pFrogVmx;



typedef struct _FrogMtrrFange
{
    UINT32 Enabled;
    UINT32 Type;
    UINT64 PhysicalAddressMin;
    UINT64 PhysicalAddressMax;
}FrogMtrrFange,*PFrogMtrrFange;

typedef struct _FrogCpu {
	pFrogVmx						pForgVmxEntrys;
	ULONG							ProcessOrNumber;
	Ia32FeatureControlMsr	OrigFeatureControlMsr;
    ULONG64						KernelCr3;
	FrogMtrrFange					MtrrRange[96];
	ULONG							NumberOfEnableMemRangs;
	bool									EnableHookMsr;
	bool									EnableEpt;
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

FrogRetCode Frog_EnableHyper();
FrogRetCode Frog_DisableHyper();
