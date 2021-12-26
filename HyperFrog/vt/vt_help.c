#include "vt_help.h"
EXTERN_C pFrogCpu		Frog_Cpu;

BOOLEAN
CPUID_VMXIsSupport()
{

	int cpuInfo[4];

	//VMX支持
	__cpuid(cpuInfo, 0x1);
	CpuFeaturesEcx info;
	info.all = cpuInfo[EnumECX];

	if (!info.fields.vmx)
		return	FALSE;

	return	TRUE;
}

BOOLEAN
MSR_VMXIsSupport() 
{

	Ia32FeatureControlMsr VmxFeatureControl;
	VmxFeatureControl.all = __readmsr(kIa32FeatureControl);
	if (VmxFeatureControl.fields.enable_vmxon)
		return	TRUE;

	return	FALSE;
}

BOOLEAN         
EPT_VmxIsSupport()
{
    Ia32VmxEptVpidCapMsr                VpidRegister = { 0 };
    Ia32MtrrDefTypeRegister              MTRRDefType = { 0 };

    if (Frog_Cpu->EnableEpt)
    {
        VpidRegister.all = __readmsr(kIa32VmxEptVpidCap);
        MTRRDefType.Flags = __readmsr(kIa32MtrrDefType);

        if (!VpidRegister.fields.support_page_walk_length4
            || !VpidRegister.fields.support_write_back_memory_type
            || !VpidRegister.fields.support_pde_2mb_pages)
        {
            return FALSE;
        }

        if (!MTRRDefType.MtrrEnable)
        {
            return FALSE;
        }
    }
    return TRUE;

}

BOOLEAN     
CR0_VMXisSuppor()
{

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

PVOID  
FrogExAllocatePool(ULONG Size)
{
	PVOID  ResultAddr = ExAllocatePoolWithTag(NonPagedPool, Size, FrogTag);
	if (ResultAddr != NULL)
		RtlZeroMemory(ResultAddr, Size);


	return	ResultAddr;
}

//创建VMX管理结构
BOOLEAN 
Forg_AllocateForgVmxRegion() 
{
	ULONG		CountOfProcessor = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	ULONG		FrogsVmxSize = sizeof(FrogVmx) * CountOfProcessor;

	Frog_Cpu = FrogExAllocatePool(sizeof(FrogCpu));
	Frog_Cpu->ProcessOrNumber = CountOfProcessor;
	Frog_Cpu->pForgVmxEntrys = FrogExAllocatePool(FrogsVmxSize);

	if (Frog_Cpu->pForgVmxEntrys == NULL)
		return FALSE;

	return TRUE;
}

BOOLEAN
Frog_AllocateFrogEptMem()
{

}

void	
Frog_FreeHyperRegion(pFrogVmx		pForgVmxEntry)
{

	if (pForgVmxEntry->VmxOnArea != NULL && MmIsAddressValid(pForgVmxEntry->VmxOnArea))	FrogExFreePool(pForgVmxEntry->VmxOnArea);
	if (pForgVmxEntry->VmxVmcsArea != NULL && MmIsAddressValid(pForgVmxEntry->VmxVmcsArea))	FrogExFreePool(pForgVmxEntry->VmxVmcsArea);
	if (pForgVmxEntry->VmxBitMapArea.BitMap != NULL && MmIsAddressValid(pForgVmxEntry->VmxBitMapArea.BitMap))	FrogExFreePool(pForgVmxEntry->VmxBitMapArea.BitMap);
	if (pForgVmxEntry->VmxHostStackArea != NULL && MmIsAddressValid(pForgVmxEntry->VmxHostStackArea))	FrogExFreePool(pForgVmxEntry->VmxHostStackArea);

	return;
}

//创建VMCS、VMXON、BITMAP区域
FrogRetCode 
Frog_AllocateHyperRegion(pFrogVmx		pForgVmxEntry, ULONG		CpuNumber) 
{
	pForgVmxEntry->ProcessorNumber = CpuNumber;

	pForgVmxEntry->VmxOnArea = FrogExAllocatePool(PAGE_SIZE);
	pForgVmxEntry->VmxVmcsArea = FrogExAllocatePool(PAGE_SIZE);
	pForgVmxEntry->VmxBitMapArea.BitMap = FrogExAllocatePool(PAGE_SIZE *2);
	pForgVmxEntry->VmxHostStackArea = FrogExAllocatePool(HostStackSize);

	if (
		pForgVmxEntry->VmxOnArea == NULL ||
		pForgVmxEntry->VmxVmcsArea == NULL ||
		pForgVmxEntry->VmxBitMapArea.BitMap == NULL ||
		pForgVmxEntry->VmxHostStackArea == NULL
		)	goto __Exit;

    pForgVmxEntry->VmxBitMapArea.BitMapA = pForgVmxEntry->VmxBitMapArea.BitMap;
    pForgVmxEntry->VmxBitMapArea.BitMapB = (PVOID)((ULONG64)pForgVmxEntry->VmxBitMapArea.BitMap + PAGE_SIZE);
	pForgVmxEntry->VmxOnAreaPhysicalAddr = MmGetPhysicalAddress(pForgVmxEntry->VmxOnArea).QuadPart;
	pForgVmxEntry->VmxVmcsAreaPhysicalAddr = MmGetPhysicalAddress(pForgVmxEntry->VmxVmcsArea).QuadPart;

	return	FrogSuccess;

__Exit:
	FrogBreak();
	Frog_FreeHyperRegion(pForgVmxEntry);

	return	ForgAllocatePoolError;
}

//设置 VMXON、VMCS版本号
void	
Frog_SetHyperRegionVersion(pFrogVmx		pForgVmxEntry, ULONG		CpuNumber)
{

	Ia32VmxBasicMsr	VmxBasicMsr = {0};

	VmxBasicMsr.all = __readmsr(kIa32VmxBasic);
	CpuNumber = KeGetCurrentProcessorNumber();

	pForgVmxEntry->VmxVmcsArea->revision_identifier = VmxBasicMsr.fields.revision_identifier;
	pForgVmxEntry->VmxOnArea->revision_identifier = VmxBasicMsr.fields.revision_identifier;

}

FrogRetCode	
Frog_Vmx_Write(ULONG64 Field, ULONG64	FieldValue) 
{
	UCHAR	 State = 0;
	State = __vmx_vmwrite(Field, FieldValue);
	if (State)
	{
		//Error
		FrogBreak();
		FrogPrint("FrogVmxWrite 	Error	Field = %x", Field);
	}

	return	State;
}

ULONG64		
Frog_Vmx_Read(ULONG64 Field)
{
	ULONG64		FieldValue = 0;
	__vmx_vmread(Field, &FieldValue);
	return FieldValue;
}

//设置CR0寄存器的一些位以支持虚拟化
void		
Frog_SetCr0andCr4BitToEnableHyper(pFrogVmx		pForgVmxEntry)
{
	//开启后允许使用VMXON
	Cr4	VmxCr4;
	VmxCr4.all = __readcr4();
    pForgVmxEntry->OrigCr4 = VmxCr4.all;

	VmxCr4.all &= __readmsr(kIa32VmxCr4Fixed1);
	VmxCr4.all |= __readmsr(kIa32VmxCr4Fixed0);
	__writecr4(VmxCr4.all);

	Cr0 VmxCr0;
	VmxCr0.all = __readcr0();
    pForgVmxEntry->OrigCr0 = VmxCr0.all;
	VmxCr0.all &= __readmsr(kIa32VmxCr0Fixed1);
	VmxCr0.all |= __readmsr(kIa32VmxCr0Fixed0);
	__writecr0(VmxCr0.all);
}

//设置MSR寄存器的一些位以支持虚拟化
void		
Frog_SetMsrBitToEnableHyper() 
{

	//此位要置1否则不能执行VMXON
	Ia32FeatureControlMsr VmxFeatureControl;
	VmxFeatureControl.all = __readmsr(kIa32FeatureControl);
	Frog_Cpu->OrigFeatureControlMsr.all = VmxFeatureControl.all;
	
	VmxFeatureControl.fields.lock = TRUE;
	__writemsr(kIa32FeatureControl, VmxFeatureControl.all);

}

//检查是否支持虚拟化
BOOLEAN		
Frog_IsSupportHyper() 
{

	if (CPUID_VMXIsSupport() &&
		MSR_VMXIsSupport() &&
		CR0_VMXisSuppor()  &&
        EPT_VmxIsSupport()
		)
		return	TRUE;

	return FALSE;

}

ULONG 	
Frog_VmxAdjustControlValue(Msr	msr, ULONG MapValue)
{
	LARGE_INTEGER	MsrValue = { 0 };
	ULONG	AdjustedValue = 0;

	AdjustedValue = MapValue;
	MsrValue.QuadPart = __readmsr(msr);

	//邓志的那本 《处理器虚拟化技术》 说反了
	AdjustedValue |= MsrValue.LowPart;
	AdjustedValue &= MsrValue.HighPart;
	return AdjustedValue;
}

VOID		
Frog_GetSelectInfo(
	PKDESCRIPTOR		pGdtr,
	USHORT					Select,
	PULONG64				pBase,
	PULONG64				pLimit,
	PULONG64				pAccess
)
{
	SEGMENT_SELECTOR			Segment = { 0 };
	PKGDTENTRY64					pGdtEntry = NULL;

	if (!pBase || !pLimit || !pAccess)
		return;

	*pBase = *pLimit = *pAccess = 0;

	Segment.Flags = Select & (~RPL_MAX_MASK);

	if (Select == 0 || Segment.Table == SEGMENT_LDT)
	{
		*pAccess = 0x10000;	// unusable
		return;
	}
    
        //Segment.Index
	pGdtEntry = (PKGDTENTRY64)((ULONG64)pGdtr->Base + (Select & ~RPL_MAX_MASK) );
    *pLimit = __segmentlimit((ULONG32)Select);
	*pBase = ((pGdtEntry->Bytes.BaseHigh << 24) | (pGdtEntry->Bytes.BaseMiddle << 16) | (pGdtEntry->BaseLow)) & 0xFFFFFFFF;
    *pBase |= ((pGdtEntry->Bits.Type & 0x10) == 0) ? ((uintptr_t)pGdtEntry->BaseUpper << 32) : 0;

	*pAccess = (pGdtEntry->Bytes.Flags1) | (pGdtEntry->Bytes.Flags2 << 8);
	*pAccess |= (pGdtEntry->Bits.Present) ? 0 : 0x10000;	//判断在不在内存，即P位
}

FrogRetCode		
Frog_FullVmxSelector(KPROCESSOR_STATE		HostState)
{
	FrogRetCode			Status = FrogSuccess;
	PKDESCRIPTOR		pGdtr = &HostState.SpecialRegisters.Gdtr;
	ULONG64				uBase, uLimit, uAccess;

	//	GUEST
	//ES
	Frog_GetSelectInfo(pGdtr, HostState.ContextFrame.SegEs, &uBase, &uLimit, &uAccess);
	Status |= Frog_Vmx_Write(GUEST_ES_SELECTOR, HostState.ContextFrame.SegEs );
	Status |= Frog_Vmx_Write(GUEST_ES_LIMIT, uLimit);
	Status |= Frog_Vmx_Write(GUEST_ES_BASE, uBase);
	Status |= Frog_Vmx_Write(GUEST_ES_AR_BYTES, uAccess);
	Status |= Frog_Vmx_Write(HOST_ES_SELECTOR, HostState.ContextFrame.SegEs & (~RPL_MAX_MASK));

	//CS
	Frog_GetSelectInfo(pGdtr, HostState.ContextFrame.SegCs, &uBase, &uLimit, &uAccess);
	Status |= Frog_Vmx_Write(GUEST_CS_SELECTOR, HostState.ContextFrame.SegCs );
	Status |= Frog_Vmx_Write(GUEST_CS_LIMIT, uLimit);
	Status |= Frog_Vmx_Write(GUEST_CS_BASE, uBase);
	Status |= Frog_Vmx_Write(GUEST_CS_AR_BYTES, uAccess);

	Status |= Frog_Vmx_Write(HOST_CS_SELECTOR, HostState.ContextFrame.SegCs  & (~RPL_MAX_MASK));
	//SS
	Frog_GetSelectInfo(pGdtr, HostState.ContextFrame.SegSs, &uBase, &uLimit, &uAccess);
	Status |= Frog_Vmx_Write(GUEST_SS_SELECTOR, HostState.ContextFrame.SegSs );
	Status |= Frog_Vmx_Write(GUEST_SS_LIMIT, uLimit);
	Status |= Frog_Vmx_Write(GUEST_SS_BASE, uBase);
	Status |= Frog_Vmx_Write(GUEST_SS_AR_BYTES, uAccess);

	Status |= Frog_Vmx_Write(HOST_SS_SELECTOR, HostState.ContextFrame.SegSs  &  (~RPL_MAX_MASK));
	//DS
	Frog_GetSelectInfo(pGdtr, HostState.ContextFrame.SegDs, &uBase, &uLimit, &uAccess);
	Status |= Frog_Vmx_Write(GUEST_DS_SELECTOR, HostState.ContextFrame.SegDs  );
	Status |= Frog_Vmx_Write(GUEST_DS_LIMIT, uLimit);
	Status |= Frog_Vmx_Write(GUEST_DS_BASE, uBase);
	Status |= Frog_Vmx_Write(GUEST_DS_AR_BYTES, uAccess);

	Status |= Frog_Vmx_Write(HOST_DS_SELECTOR, HostState.ContextFrame.SegDs &  (~RPL_MAX_MASK));
	//FS
	Frog_GetSelectInfo(pGdtr, HostState.ContextFrame.SegFs, &uBase, &uLimit, &uAccess);
	Status |= Frog_Vmx_Write(GUEST_FS_SELECTOR, HostState.ContextFrame.SegFs);
	Status |= Frog_Vmx_Write(GUEST_FS_LIMIT, uLimit);
	Status |= Frog_Vmx_Write(GUEST_FS_BASE, uBase);
	Status |= Frog_Vmx_Write(GUEST_FS_AR_BYTES, uAccess);

	Status |= Frog_Vmx_Write(HOST_FS_BASE, uBase);
	Status |= Frog_Vmx_Write(HOST_FS_SELECTOR, HostState.ContextFrame.SegFs   &  (~RPL_MAX_MASK));

	//GS
	Frog_GetSelectInfo(pGdtr, HostState.ContextFrame.SegGs, &uBase, &uLimit, &uAccess);
    uBase = HostState.SpecialRegisters.MsrGsBase;//这里是个坑，我们使用了递投DPC的方式去开启VT，那么GS_BASE对应的是TEB，所以我们需要用之前保存的GS_BASE
	Status |= Frog_Vmx_Write(GUEST_GS_SELECTOR, HostState.ContextFrame.SegGs );
	Status |= Frog_Vmx_Write(GUEST_GS_LIMIT, uLimit);
	Status |= Frog_Vmx_Write(GUEST_GS_BASE, uBase);
	Status |= Frog_Vmx_Write(GUEST_GS_AR_BYTES, uAccess);

	Status |= Frog_Vmx_Write(HOST_GS_BASE, uBase);
	Status |= Frog_Vmx_Write(HOST_GS_SELECTOR, HostState.ContextFrame.SegGs  &  (~RPL_MAX_MASK));

	//LDTR
	Frog_GetSelectInfo(pGdtr, HostState.SpecialRegisters.Ldtr, &uBase, &uLimit, &uAccess);
	Status |= Frog_Vmx_Write(GUEST_LDTR_SELECTOR, HostState.SpecialRegisters.Ldtr);
	Status |= Frog_Vmx_Write(GUEST_LDTR_LIMIT, uLimit);
	Status |= Frog_Vmx_Write(GUEST_LDTR_BASE, uBase);
	Status |= Frog_Vmx_Write(GUEST_LDTR_AR_BYTES, uAccess);

	//TR
	Frog_GetSelectInfo(pGdtr, HostState.SpecialRegisters.Tr, &uBase, &uLimit, &uAccess);
	Status |= Frog_Vmx_Write(GUEST_TR_SELECTOR, HostState.SpecialRegisters.Tr);
	Status |= Frog_Vmx_Write(GUEST_TR_LIMIT, uLimit);
	Status |= Frog_Vmx_Write(GUEST_TR_BASE, uBase);
	Status |= Frog_Vmx_Write(GUEST_TR_AR_BYTES, uAccess);
	Status |= Frog_Vmx_Write(HOST_TR_BASE, uBase);
	Status |= Frog_Vmx_Write(HOST_TR_SELECTOR, HostState.SpecialRegisters.Tr   &  (~RPL_MAX_MASK));

	return Status;
}

BOOLEAN     
Frog_VmCall(ULONG64    Rcx, ULONG64    Rdx, ULONG64    R8, ULONG64    R9)
{
    CpuId Data = { 0 };

    __cpuid((int*)&Data, FrogTag);
    if (Data.eax != FrogTag) {
        return FALSE;
    }

    Asm_VmxCall(Rcx, Rdx, R8, R9);

    return TRUE;
}