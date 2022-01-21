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
typedef struct _GuestStatus 
{
	ULONG64 Rip;
	FlagReg Eflags;
}GuestStatus,*pGuestStatus;

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
	ULONG Eflags;
    struct _M128A Xmm0;
    struct _M128A Xmm1;
    struct _M128A Xmm2;
    struct _M128A Xmm3;
    struct _M128A Xmm4;
    struct _M128A Xmm5;
    struct _M128A Xmm6;
    struct _M128A Xmm7;
    struct _M128A Xmm8;
    struct _M128A Xmm9;
    struct _M128A Xmm10;
    struct _M128A Xmm11;
    struct _M128A Xmm12;
    struct _M128A Xmm13;
    struct _M128A Xmm14;
    struct _M128A Xmm15;
	ULONG64 Dr0;
	ULONG64 Dr1;
	ULONG64 Dr2;
	ULONG64 Dr3;
	ULONG64 Dr4;
	ULONG64 Dr5;
	ULONG64 Dr6;
	ULONG64 Dr7;
    USHORT SegCs;
    USHORT SegDs;
    USHORT SegEs;
    USHORT SegFs;
    USHORT SegGs;
    USHORT SegSs;
}Frog_GuestContext, *pFrog_GuestContext;

FrogRetCode Frog_EnableHyper();
FrogRetCode Frog_DisableHyper();

