#include "vt.h"

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



// ↑ ToolsFunction--------------------------------------------------------
//--------------------------------------------------------------------------


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

BOOLEAN		Frog_IsSupportHyper() {

	if (		CPUID_VMXIsSupport()		&&
			MSR_VMXisSupport()		&&
			CR0_VMXisSuppor()
		)
		return	TRUE;
	

	return FALSE;

}

void Frog_AllocateHyperRegion() {



}



VOID	Frog_HyperInit(
	_In_ struct _KDPC *Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
) {
	//初始化VMX区域


	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}

void Frog_ExecuteForEachProcessor() {

	KeGenericCallDpc(Frog_HyperInit,NULL);
}

void 	Frog_EnableHyper() {


}