#include "vt/vt_help.h"
EXTERN_C pFrogCpu		Frog_Cpu;



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
	VmxFeatureControl.all = __readmsr(kIa32FeatureControl);

	if (VmxFeatureControl.fields.enable_vmxon)
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
	PVOID  ResultAddr = ExAllocatePoolWithTag(NonPagedPool, Size, FrogTag);
	if (ResultAddr != NULL)
		RtlZeroMemory(ResultAddr, Size);


	return	ResultAddr;
}

//创建VMX管理结构
BOOLEAN Forg_AllocateForgVmxRegion() {
	ULONG		CountOfProcessor = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	ULONG		FrogsVmxSize = sizeof(FrogVmx) * CountOfProcessor;

	Frog_Cpu = FrogExAllocatePool(sizeof(FrogCpu));
	Frog_Cpu->ProcessOrNumber = CountOfProcessor;
	Frog_Cpu->pForgVmxEntrys = FrogExAllocatePool(FrogsVmxSize);

	if (Frog_Cpu->pForgVmxEntrys == NULL)
		return FALSE;

	return TRUE;
}


void	Frog_FreeHyperRegion(pFrogVmx		pForgVmxEntry) {

	if (pForgVmxEntry->VmxOnArea != NULL && MmIsAddressValid(pForgVmxEntry->VmxOnArea))	FrogExFreePool(pForgVmxEntry->VmxOnArea);
	if (pForgVmxEntry->VmxVmcsArea != NULL && MmIsAddressValid(pForgVmxEntry->VmxVmcsArea))	FrogExFreePool(pForgVmxEntry->VmxVmcsArea);
	if (pForgVmxEntry->VmxBitMapArea.BitMap != NULL && MmIsAddressValid(pForgVmxEntry->VmxBitMapArea.BitMap))	FrogExFreePool(pForgVmxEntry->VmxBitMapArea.BitMap);
	if (pForgVmxEntry->VmxHostStackArea != NULL && MmIsAddressValid(pForgVmxEntry->VmxHostStackArea))	FrogExFreePool(pForgVmxEntry->VmxHostStackArea);

	return;
}

//创建VMCS、VMXON、BITMAP区域
FrogRetCode Frog_AllocateHyperRegion(pFrogVmx		pForgVmxEntry, ULONG		CpuNumber) {

	pForgVmxEntry->ProcessorNumber = CpuNumber;

	pForgVmxEntry->VmxOnArea = FrogExAllocatePool(PAGE_SIZE);

	pForgVmxEntry->VmxVmcsArea = FrogExAllocatePool(PAGE_SIZE);

	FrogBreak();

	pForgVmxEntry->VmxBitMapArea.BitMap = FrogExAllocatePool(PAGE_SIZE * 2);

	if (pForgVmxEntry->VmxBitMapArea.BitMap == NULL)	goto __AllocateHyperFreePoolExit;
	pForgVmxEntry->VmxBitMapArea.BitMapA = pForgVmxEntry->VmxBitMapArea.BitMap;
	pForgVmxEntry->VmxBitMapArea.BitMapB = (PVOID)((ULONG_PTR)pForgVmxEntry->VmxBitMapArea.BitMap + PAGE_SIZE);

	pForgVmxEntry->VmxHostStackArea = FrogExAllocatePool(HostStackSize);


	if (
		pForgVmxEntry->VmxOnArea == NULL ||
		pForgVmxEntry->VmxVmcsArea == NULL ||
		pForgVmxEntry->VmxBitMapArea.BitMap == NULL ||
		pForgVmxEntry->VmxHostStackArea == NULL
		)	goto __AllocateHyperFreePoolExit;


	pForgVmxEntry->VmxOnAreaPhysicalAddr = MmGetPhysicalAddress(pForgVmxEntry->VmxOnArea);
	pForgVmxEntry->VmxVmcsAreaPhysicalAddr = MmGetPhysicalAddress(pForgVmxEntry->VmxVmcsArea);


	return	FrogSuccess;

__AllocateHyperFreePoolExit:
	FrogBreak();
	Frog_FreeHyperRegion(pForgVmxEntry);

	return	ForgAllocatePoolError;
}

//设置 VMXON、VMCS版本号
void	Frog_SetHyperRegionVersion(pFrogVmx		pForgVmxEntry, ULONG		CpuNumber) {

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
