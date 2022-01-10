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
	ULONG64			OrigCr4;
    ULONG64            OrigCr0;
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
}FrogVmx, *pFrogVmx;



typedef struct _FrogMtrrFange
{
    UINT32 Enabled;
    UINT32 Type;
    UINT64 PhysicalAddressMin;
    UINT64 PhysicalAddressMax;
}FrogMtrrFange,*PFrogMtrrFange;

typedef struct _FrogCpu {
	ULONG							ProcessOrNumber;
	Ia32FeatureControlMsr	OrigFeatureControlMsr;
	pFrogVmx						pForgVmxEntrys;
    ULONG64						KernelCr3;
    bool                        EnableEpt;
	FrogMtrrFange					MtrrRange[96];
	ULONG							NumberOfEnableMemRangs;

	bool						EnableHookMsr;
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

FrogRetCode Frog_EnableHyper();
FrogRetCode Frog_DisableHyper();
