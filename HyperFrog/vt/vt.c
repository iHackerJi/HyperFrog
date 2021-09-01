#include "vt.h"

pFrogVmx		pForgVmxEntrys = NULL;


BOOLEAN		CPUID_VMXIsSupport() {

	int cpuInfo[4];

	//VMX支持
	__cpuid(cpuInfo, 0x1);
	CpuFeaturesEcx info;
	info.all = cpuInfo[EnumECX];
	if (!info.fields.vmx)
		return	FALSE;
	
	return	TRUE;
}

BOOLEAN		MSR_VMXisSupport() {

	Ia32FeatureControlMsr VmxFeatureControl;
	VmxFeatureControl.all = 	__readmsr(kIa32FeatureControl);

	if (	VmxFeatureControl.fields.enable_vmxon)
		return	TRUE;
	

	return	FALSE;
}

BOOLEAN		CR0_VMXisSuppor() {

	Cr0 VmxCr0;
	VmxCr0.all = __readcr0();

	if (
		VmxCr0.fields.pg &&
		VmxCr0.fields.ne &&
		VmxCr0.fields.pe
		)
		return TRUE;

	return FALSE;
}

PVOID  FrogExAllocatePool(ULONG Size) {
	PVOID  ResultAddr = 	ExAllocatePoolWithTag(NonPagedPool, Size, FrogTag);
	if (ResultAddr != NULL) 
		RtlZeroMemory(ResultAddr, Size);
	

	return	ResultAddr;
}	




//创建VMX管理结构
BOOLEAN Forg_AllocateForgVmxRegion() {
	ULONG		CountOfProcessor = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	ULONG		FrogsVmxSize = sizeof(FrogVmx) * CountOfProcessor;

	pForgVmxEntrys = FrogExAllocatePool(FrogsVmxSize);

	if (pForgVmxEntrys == NULL)
		return FALSE;

	return TRUE;
}


void	Frog_FreeHyperRegion(pFrogVmx		pForgVmxEntry) {
	
	if (pForgVmxEntry->VmxOnArea != NULL		&& MmIsAddressValid(pForgVmxEntry->VmxOnArea)		)	FrogExFreePool(pForgVmxEntry->VmxOnArea);
	if (pForgVmxEntry->VmxVmcsArea != NULL		&& MmIsAddressValid(pForgVmxEntry->VmxVmcsArea)		)	FrogExFreePool(pForgVmxEntry->VmxVmcsArea);
	if (pForgVmxEntry->VmxBitMapArea != NULL	&& MmIsAddressValid(pForgVmxEntry->VmxBitMapArea)	)	FrogExFreePool(pForgVmxEntry->VmxBitMapArea);
	if (pForgVmxEntry->VmxHostStackArea != NULL	&& MmIsAddressValid(pForgVmxEntry->VmxHostStackArea))	FrogExFreePool(pForgVmxEntry->VmxHostStackArea);

	return;
}

//创建VMCS、VMXON、BITMAP区域
FrogRetCode Frog_AllocateHyperRegion(pFrogVmx		pForgVmxEntry, ULONG		CpuNumber) {




	pForgVmxEntry->ProcessorNumber = CpuNumber;

	pForgVmxEntry->VmxOnArea = FrogExAllocatePool(PAGE_SIZE);

	pForgVmxEntry->VmxVmcsArea = FrogExAllocatePool(PAGE_SIZE);

	pForgVmxEntry->VmxBitMapArea = FrogExAllocatePool(PAGE_SIZE);

	pForgVmxEntry->VmxHostStackArea = FrogExAllocatePool(HostStackSize);


	if (
		pForgVmxEntry->VmxOnArea == NULL ||
		pForgVmxEntry->VmxVmcsArea == NULL ||
		pForgVmxEntry->VmxBitMapArea == NULL ||
		pForgVmxEntry->VmxHostStackArea == NULL
		)	goto __AllocateHyperFreePoolExit;


	pForgVmxEntry->VmxOnAreaPhysicalAddr = MmGetPhysicalAddress(pForgVmxEntry->VmxOnArea);
	pForgVmxEntry->VmxVmcsAreaPhysicalAddr = MmGetPhysicalAddress(pForgVmxEntry->VmxVmcsArea);
	pForgVmxEntry->VmxBitMapAreaPhysicalAddr = MmGetPhysicalAddress(pForgVmxEntry->VmxBitMapArea);


	return	FrogSuccess;

__AllocateHyperFreePoolExit:

	Frog_FreeHyperRegion(pForgVmxEntry);

	return	ForgAllocatePoolError;
}

//设置 VMXON、VMCS版本号
void	Frog_SetHyperRegionVersion(pFrogVmx		pForgVmxEntry,ULONG		CpuNumber) {

	Ia32VmxBasicMsr	VmxBasicMsr;
	

	VmxBasicMsr.all = __readmsr(kIa32VmxBasic);
	CpuNumber = KeGetCurrentProcessorNumber();

	

	pForgVmxEntry->VmxVmcsArea->revision_identifier = VmxBasicMsr.fields.revision_identifier;
	pForgVmxEntry->VmxOnArea->revision_identifier = VmxBasicMsr.fields.revision_identifier;

}

void	Frog_Vmx_Write(ULONG64 Field, ULONG64	FieldValue) {
	UCHAR	State = 0;
	State = __vmx_vmwrite(Field, FieldValue);
	if (!State)
	{
		//Error
		FrogBreak();
		FrogPrint("FrogVmxWrite 	Error	Field = %x", Field);
	}

	return;
}


// ↑ ToolsFunction--------------------------------------------------------
//--------------------------------------------------------------------------



//设置一些位以支持虚拟化
void		Frog_SetBitToEnableHyper() {

	//此位要置1否则不能执行VMXON
	Ia32FeatureControlMsr VmxFeatureControl;
	VmxFeatureControl.all = __readmsr(kIa32FeatureControl);
	VmxFeatureControl.fields.lock = TRUE;
	__writemsr(kIa32FeatureControl, VmxFeatureControl.all);

	//开启后允许使用VMXON
	Cr4	VmxCr4;
	VmxCr4.all = __readcr4();
	VmxCr4.fields.vmxe = TRUE;
	__writecr4(VmxCr4.all);

}

//检查是否支持虚拟化
BOOLEAN		Frog_IsSupportHyper() {

	if (CPUID_VMXIsSupport() &&
		MSR_VMXisSupport() &&
		CR0_VMXisSuppor()
		)
		return	TRUE;


	return FALSE;

}

#define		SEGMENT_GDT	1
#define		SEGMENT_LDT	0
#define		RPL_MAX_MASK 3

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



BOOLEAN		Frog_FullGuestVmxSelector(PUSHORT Selector, PVOID	GdtBase) {


	for (int i =0 ; i <= 14 ; i+=2)
	{
		SEGMENT_SELECTOR	Segment = { 0 };
		ULONG				uAccessRights = 0;
		PKGDTENTRY64		GdtEntry = NULL;
		ULONG_PTR			Base = 0;
		ULONG			Limit = 0;
		Segment.Flags = Selector[i] & (~RPL_MAX_MASK);


		if (Segment.Table == SEGMENT_LDT)
		{
			return FALSE;
		}
		GdtEntry = (PKGDTENTRY64)(ULONG_PTR)((ULONG64)GdtBase + Segment.Index);
		Base = GdtEntry->BaseLow | GdtEntry->Bytes.BaseMiddle << 16 | GdtEntry->Bytes.BaseHigh << 24;

		Limit = __segmentlimit(Segment.Flags);

		if (!Selector)
			uAccessRights |= 0x10000;
		else
			uAccessRights = GdtEntry->Bytes.Flags1 << 8 | GdtEntry->Bytes.Flags2;

		Frog_Vmx_Write(GUEST_ES_BASE + i, Base);
	
		Frog_Vmx_Write(GUEST_ES_LIMIT + i, Limit);

		Frog_Vmx_Write(GUEST_ES_AR_BYTES + i, uAccessRights);
	

		Frog_Vmx_Write(GUEST_ES_SELECTOR + i, Segment.Flags);


		if (i < 10)		Frog_Vmx_Write(HOST_ES_SELECTOR + i, Segment.Flags);
				
		if (i == 14)	Frog_Vmx_Write(HOST_TR_SELECTOR, Segment.Flags);
		
	}

	return	TRUE;
}


FrogRetCode	Frog_SetupVmcs(pFrogVmx		pForgVmxEntry) {

	FrogRetCode		Status = FrogSuccess;
	KPROCESSOR_STATE HostState = pForgVmxEntry->HostState;
	short	SelectorArry[8] = {0};

	if (__vmx_vmclear((UINT64*)&pForgVmxEntry->VmxVmcsAreaPhysicalAddr))
	{
		FrogBreak();
		FrogPrint("ForgVmClear	Error");
		return ForgVmClearError;
	}

	if (__vmx_vmptrld((UINT64*)&pForgVmxEntry->VmxVmcsAreaPhysicalAddr))
	{
		FrogBreak();
		FrogPrint("ForgVmptrld	Error");
		return ForgVmptrldError;
	}

	//Segment
	SelectorArry[Frog_ES] = HostState.ContextFrame.SegEs;
	SelectorArry[Frog_CS] = HostState.ContextFrame.SegCs;
	SelectorArry[Frog_SS] = HostState.ContextFrame.SegSs;
	SelectorArry[Frog_DS] = HostState.ContextFrame.SegDs;
	SelectorArry[Frog_FS] = HostState.ContextFrame.SegFs;
	SelectorArry[Frog_GS] = HostState.ContextFrame.SegGs;
	SelectorArry[Frog_LDTR] = HostState.SpecialRegisters.Ldtr;
	SelectorArry[Frog_TR] = HostState.SpecialRegisters.Tr;
	Frog_FullGuestVmxSelector(SelectorArry, HostState.SpecialRegisters.Gdtr.Base);

	//gdt
	Frog_Vmx_Write(GUEST_GDTR_BASE, (ULONG64)HostState.SpecialRegisters.Gdtr.Base);
	Frog_Vmx_Write(GUEST_GDTR_LIMIT, HostState.SpecialRegisters.Gdtr.Limit);
	Frog_Vmx_Write(HOST_GDTR_BASE, (ULONG64)HostState.SpecialRegisters.Gdtr.Base);

	//idt
	Frog_Vmx_Write(GUEST_IDTR_BASE, (ULONG64)HostState.SpecialRegisters.Idtr.Base);
	Frog_Vmx_Write(GUEST_IDTR_LIMIT, HostState.SpecialRegisters.Idtr.Limit);
	Frog_Vmx_Write(HOST_IDTR_BASE, (ULONG64)HostState.SpecialRegisters.Idtr.Base);

	// 注意：	这些CRX_GUEST_HOST_MASK ，当某一个位被置上的时候，Guest机读这个位会返回Shadow的值；Guest机写这个位会产生VM-EXIT
	//CR0
	Frog_Vmx_Write(GUEST_CR0, HostState.SpecialRegisters.Cr0);
	Frog_Vmx_Write(HOST_CR0, HostState.SpecialRegisters.Cr0);
	Frog_Vmx_Write(CR0_GUEST_HOST_MASK, HostState.SpecialRegisters.Cr0);		

	//CR3
	Frog_Vmx_Write(GUEST_CR3, HostState.SpecialRegisters.Cr3);
	//因为使用了KeGenericCallDpc函数进行多核同步操作，这个函数会把我们的例程通过DPC投放到别的进程里面，可能CR3会被改变，所以CR3在之前需要保存
	Frog_Vmx_Write(HOST_CR3, pForgVmxEntry->HostCr3);

	//CR4
	Frog_Vmx_Write(GUEST_CR4, HostState.SpecialRegisters.Cr4);
	Frog_Vmx_Write(HOST_CR4, HostState.SpecialRegisters.Cr4);
	Frog_Vmx_Write(CR4_GUEST_HOST_MASK, HostState.SpecialRegisters.Cr4);

	


																			





	
	return Status;
}



VOID	Frog_HyperInit(
	_In_ struct _KDPC *Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
) {

	//初始化VMX区域
	FrogRetCode	Status;
	ULONG		CpuNumber = KeGetCurrentProcessorNumber();
	pFrogVmx		pForgVmxEntry = &pForgVmxEntrys[CpuNumber];

	//保存HOST机上下文
	KeSaveStateForHibernate(&pForgVmxEntry->HostState);
	RtlCaptureContext(&pForgVmxEntry->HostState.ContextFrame);
	pForgVmxEntry->HostCr3 = (ULONG64)DeferredContext;

	//申请VMCS、VMXON、等等区域
	Status = Frog_AllocateHyperRegion(pForgVmxEntry, CpuNumber);

	if (!Frog_SUCCESS(Status))
	{
		FrogBreak();
		FrogPrint("AllocateHyperRegion	Error");
		goto	_HyperInitExit;
	}


	//设置VMCS、VMXON版本号
	Frog_SetHyperRegionVersion(pForgVmxEntry, CpuNumber);

	//VMXON

	if (__vmx_on((UINT64*)&pForgVmxEntry->VmxOnAreaPhysicalAddr))
	{
		FrogBreak();
		FrogPrint("Vmxon	Error");
		goto	_HyperInitExit;
	}

	//VMCS
	Frog_SetupVmcs(pForgVmxEntry);




_HyperInitExit:

	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);

}



FrogRetCode 	Frog_EnableHyper() {

	//查询是否支持虚拟化
	if (!Frog_IsSupportHyper()) {
		FrogBreak();
		FrogPrint("NoSupportHyper");
		return NoSupportHyper;
	} 



	//申请 ForgVmxRegion
	if (!Forg_AllocateForgVmxRegion()) {
		FrogBreak();
		FrogPrint("ForgAllocatePoolError");
		return ForgAllocatePoolError;
	}


	Frog_SetBitToEnableHyper();

	KeGenericCallDpc(Frog_HyperInit, (PVOID)__readcr3());
	return	FrogSuccess;

}


VOID	Frog_HyperUnLoad(
	_In_ struct _KDPC *Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
) {

	ULONG		CpuNumber = KeGetCurrentProcessorNumber();
	pFrogVmx		pForgVmxEntry = &pForgVmxEntrys[CpuNumber];
	Frog_FreeHyperRegion(pForgVmxEntry);


	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}

void Frog_DisableHyper() {

	KeGenericCallDpc(Frog_HyperUnLoad, NULL);

	FrogExFreePool(pForgVmxEntrys);

	//ExFreePoolWithTag(pForgVmxEntrys, FrogTag);

}