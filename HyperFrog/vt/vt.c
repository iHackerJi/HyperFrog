#include "vt.h"
#include "vt_help.h"

pFrogCpu		Frog_Cpu = NULL;


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
			uAccessRights = (UINT16)GdtEntry->Bytes.Flags1 << 8 | GdtEntry->Bytes.Flags2;

		Frog_Vmx_Write(GUEST_ES_BASE + i, Base);
		Frog_Vmx_Write(GUEST_ES_LIMIT + i, Limit);
		Frog_Vmx_Write(GUEST_ES_AR_BYTES + i, uAccessRights);
		Frog_Vmx_Write(GUEST_ES_SELECTOR + i, Segment.Flags);

		if (i < 10)		Frog_Vmx_Write(HOST_ES_SELECTOR + i, Segment.Flags);
				
		if (i == 14)	Frog_Vmx_Write(HOST_TR_SELECTOR, Segment.Flags);
		
	}

	return	TRUE;
}

ULONG 	Frog_VmxAdjustControlValue(Msr	msr , ULONG MapValue) {
	LARGE_INTEGER	MsrValue = { 0 };
	ULONG	AdjustedValue = 0;

	AdjustedValue = MapValue;
	MsrValue.QuadPart = __readmsr(msr);

	//邓志的那本 《处理器虚拟化技术》 说反了
	AdjustedValue |= MsrValue.LowPart;
	AdjustedValue &= MsrValue.HighPart;
	return AdjustedValue;
}

FrogRetCode	Frog_SetupVmcs(pFrogVmx		pForgVmxEntry) {
	BOOLEAN	UseTrueMsr = FALSE;
	FrogRetCode		Status = FrogSuccess;
	KPROCESSOR_STATE HostState = pForgVmxEntry->HostState;

	short	SelectorArry[8] = {0};
	Ia32VmxBasicMsr				VmxBasicMsr = { 0 };
	VmxPinBasedControls			VmPinBasedControls = { 0 };
	VmxProcessorBasedControls	VmProcessorBasedControls = { 0 };

	VmxBasicMsr.all = __readmsr(kIa32VmxBasic);
	UseTrueMsr = VmxBasicMsr.fields.vmx_capability_hint;

	VmPinBasedControls.all = Frog_VmxAdjustControlValue(UseTrueMsr ? __readmsr(kIa32VmxTruePinbasedCtls) : __readmsr(kIa32VmxPinbasedCtls), VmPinBasedControls.all);


	VmProcessorBasedControls.fields.cr3_load_exiting = TRUE;
	VmProcessorBasedControls.fields.cr3_store_exiting = TRUE;
	VmProcessorBasedControls.fields.activate_secondary_control = TRUE;
	VmProcessorBasedControls.all = Frog_VmxAdjustControlValue(UseTrueMsr ? kIa32VmxTrueProcBasedCtls : kIa32VmxProcBasedCtls, VmProcessorBasedControls.all);





	Frog_Vmx_Write(PIN_BASED_VM_EXEC_CONTROL, VmPinBasedControls.all);
	Frog_Vmx_Write(CPU_BASED_VM_EXEC_CONTROL, VmProcessorBasedControls.all);
	Frog_Vmx_Write(IO_BITMAP_A, pForgVmxEntry->VmxBitMapArea->BitMapA);
	Frog_Vmx_Write(IO_BITMAP_B, pForgVmxEntry->VmxBitMapArea->BitMapB);

	// CR3_TARGET_COUNT

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
	Frog_Vmx_Write(CR0_READ_SHADOW, HostState.SpecialRegisters.Cr0);

	//CR3
	Frog_Vmx_Write(GUEST_CR3, HostState.SpecialRegisters.Cr3);
	//因为使用了KeGenericCallDpc函数进行多核同步操作，这个函数会把我们的例程通过DPC投放到别的进程里面，可能CR3会被改变，所以CR3在之前需要保存
	Frog_Vmx_Write(HOST_CR3, pForgVmxEntry->HostCr3);

	//CR4
	Frog_Vmx_Write(GUEST_CR4, HostState.SpecialRegisters.Cr4);
	Frog_Vmx_Write(HOST_CR4, HostState.SpecialRegisters.Cr4);
	Frog_Vmx_Write(CR4_READ_SHADOW, HostState.SpecialRegisters.Cr4);

	//DR7
	Frog_Vmx_Write(GUEST_DR7, HostState.SpecialRegisters.KernelDr7);

	//GUEST RSP RIP RFLAGS
	Frog_Vmx_Write(GUEST_RSP, HostState.ContextFrame.Rsp);
	Frog_Vmx_Write(GUEST_RIP, HostState.ContextFrame.Rip);
	Frog_Vmx_Write(GUEST_RFLAGS, HostState.ContextFrame.EFlags);


	//HOST RIP RSP
	Frog_Vmx_Write(HOST_RSP, (ULONG_PTR)pForgVmxEntry->VmxHostStackArea + HostStackSize - sizeof(CONTEXT));

	Frog_Vmx_Write(HOST_RIP,);

	
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
	pFrogVmx		pForgVmxEntry = &Frog_Cpu->pForgVmxEntrys[CpuNumber];

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
	
	//vmclear
	if (__vmx_vmclear((UINT64*)&pForgVmxEntry->VmxVmcsAreaPhysicalAddr))
	{
		FrogBreak();
		FrogPrint("ForgVmClear	Error");
		return ForgVmClearError;
	}

	//vmptrld
	if (__vmx_vmptrld((UINT64*)&pForgVmxEntry->VmxVmcsAreaPhysicalAddr))
	{
		FrogBreak();
		FrogPrint("ForgVmptrld	Error");
		return ForgVmptrldError;
	}

	//VMCS
	Frog_SetupVmcs(pForgVmxEntry);



_HyperInitExit:

	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);

}



FrogRetCode 	Frog_EnableHyper() {
	NTSTATUS	Status;
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



//--------------------------------------Unload
VOID	Frog_HyperUnLoad(
	_In_ struct _KDPC *Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
) {

	ULONG		CpuNumber = KeGetCurrentProcessorNumber();
	pFrogVmx		pForgVmxEntry = &Frog_Cpu->pForgVmxEntrys[CpuNumber];
	Frog_FreeHyperRegion(pForgVmxEntry);


	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}

void Frog_DisableHyper() {

	KeGenericCallDpc(Frog_HyperUnLoad, NULL);

	if (Frog_Cpu->pForgVmxEntrys)		FrogExFreePool(Frog_Cpu->pForgVmxEntrys);
	if (Frog_Cpu)		FrogExFreePool(Frog_Cpu);

}