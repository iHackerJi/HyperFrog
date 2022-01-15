#include "public.h"

bool
CPUID_VmxIsSupport()
{

	int cpuInfo[4];

	//VMX支持
	__cpuid(cpuInfo, 0x1);
	CpuFeaturesEcx info;
	info.all = cpuInfo[EnumECX];

	if (!info.fields.vmx)
		return	false;

	return	true;
}

bool
MSR_VmxIsSupport() 
{

	Ia32FeatureControlMsr VmxFeatureControl;
	VmxFeatureControl.all = __readmsr(kIa32FeatureControl);
	if (VmxFeatureControl.fields.enable_vmxon)
		return	true;

	return	false;
}

bool         
EPT_VmxIsSupport()
{
    Ia32VmxEptVpidCapMsr                VpidRegister = { 0 };
    Ia32MtrrDefTypeRegister              MTRRDefType = { 0 };

    if (g_FrogCpu->EnableEpt)
    {
        VpidRegister.all = __readmsr(kIa32VmxEptVpidCap);
        MTRRDefType.Flags = __readmsr(kIa32MtrrDefType);

        if (!VpidRegister.fields.support_page_walk_length4
            || !VpidRegister.fields.support_write_back_memory_type
            || !VpidRegister.fields.support_pde_2mb_pages)
        {
            return false;
        }

        if (!MTRRDefType.MtrrEnable)
        {
            return false;
        }
    }
    return true;

}

bool     
CR0_VmxIsSuppor()
{

	Cr0 VmxCr0;
	VmxCr0.all = __readcr0();

	if (
		VmxCr0.fields.pg &&
		VmxCr0.fields.ne &&
		VmxCr0.fields.pe
		)
		return true;

	return false;
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
bool 
Forg_AllocateForgVmxRegion() 
{
	ULONG		CountOfProcessor = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	ULONG		FrogsVmxSize = sizeof(FrogVmx) * CountOfProcessor;

	g_FrogCpu = FrogExAllocatePool(sizeof(FrogCpu));
	g_FrogCpu->ProcessOrNumber = CountOfProcessor;
	g_FrogCpu->pForgVmxEntrys = FrogExAllocatePool(FrogsVmxSize);

	if (g_FrogCpu == NULL && g_FrogCpu->pForgVmxEntrys == NULL)
	{
		if (g_FrogCpu) FrogExFreePool(g_FrogCpu);
		if (g_FrogCpu->pForgVmxEntrys) FrogExFreePool(g_FrogCpu->pForgVmxEntrys);
		return false;
	}

	return true;
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
Frog_SetCrxToEnableHyper()
{
	//开启后允许使用VMXON
	Cr4	VmxCr4;
	VmxCr4.all = __readcr4();

	VmxCr4.all &= __readmsr(kIa32VmxCr4Fixed1);
	VmxCr4.all |= __readmsr(kIa32VmxCr4Fixed0);
	__writecr4(VmxCr4.all);

	Cr0 VmxCr0;
	VmxCr0.all = __readcr0();
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
	g_FrogCpu->OrigFeatureControlMsr.all = VmxFeatureControl.all;
	
	VmxFeatureControl.fields.lock = true;
	__writemsr(kIa32FeatureControl, VmxFeatureControl.all);

}

//检查是否支持虚拟化
bool		
Frog_IsSupportHyper() 
{

	if (CPUID_VmxIsSupport() &&
		MSR_VmxIsSupport() &&
		CR0_VmxIsSuppor()  &&
        EPT_VmxIsSupport()
		)
		return	true;

	return false;

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

bool     
Frog_VmCall(ULONG64    Rcx, ULONG64    Rdx, ULONG64    R8, ULONG64    R9)
{
    CpuId Data = { 0 };

    __cpuid((int*)&Data, FrogTag);
    if (Data.eax != FrogTag) {
        return false;
    }

    Asm_VmxCall(Rcx, Rdx, R8, R9);

    return true;
}

void
SetEptMemoryByMttrInfo(
    pFrogVmx pForgVmxEntry,
    int i,
    int j
)
{
    ULONG_PTR LargePageAddress = 0;
    ULONG_PTR CandidateMemoryType = 0;

    LargePageAddress = pForgVmxEntry->VmxEptInfo.PDT[i][j].PageFrameNumber * _2MB;
    /* 默认WB内存类型 */
    CandidateMemoryType = MTRR_TYPE_WB;

    for (ULONG k = 0; k < g_FrogCpu->NumberOfEnableMemRangs; k++)
    {
        ///See: 11.11.9 Large Page Size Considerations
        // 第一个页面设置为UC类型(因为其有可能为MMIO所需要)
        // 预留4KB地址I/O (UC)
        if (pForgVmxEntry->VmxEptInfo.PDT[i][j].PageFrameNumber == 0) {
            CandidateMemoryType = MTRR_TYPE_UC;
            break;
        }

        // 检测内存是否启用
        if (g_FrogCpu->MtrrRange[k].Enabled != false)
        {
            ///See: 11.11.4 Range Size and Alignment Requirement
            // 检查大页面物理地址的边界,如果单物理页面为4KB,则改写入口为2MB的MemType
            // If this page's address is below or equal to the max physical address of the range
            if ((LargePageAddress <= g_FrogCpu->MtrrRange[k].PhysicalAddressMax) &&
                // And this page's last address is above or equal to the base physical address of the range
                ((LargePageAddress + _2MB - 1) >= g_FrogCpu->MtrrRange[k].PhysicalAddressMin))
            {
                ///See:11.11.4.1 MTRR Precedences
                // 改写备选内存类型
                CandidateMemoryType = g_FrogCpu->MtrrRange[k].Type;
                // UC类型优先
                if (CandidateMemoryType == MTRR_TYPE_UC) {
                    break;
                }
            }
        }
    }
    pForgVmxEntry->VmxEptInfo.PDT[i][j].MemoryType = CandidateMemoryType;

}

void
Frog_BuildEpt(pFrogVmx pForgVmxEntry)
{
    //只是映射了一个PML4页，一个PML4 = 512GB，完全足够了
    pForgVmxEntry->VmxEptInfo.PML4T[0].ReadAccess = 1;
    pForgVmxEntry->VmxEptInfo.PML4T[0].WriteAccess = 1;
    pForgVmxEntry->VmxEptInfo.PML4T[0].ExecuteAccess = 1;
    pForgVmxEntry->VmxEptInfo.PML4T[0].PageFrameNumber = MmGetPhysicalAddress(&pForgVmxEntry->VmxEptInfo.PDPT).QuadPart / PAGE_SIZE; // 获取 PFN

    for (int i = 0; i < PDPTE_ENTRY_COUNT; i++)
    {
        // 设置PDPT的页面数量
        pForgVmxEntry->VmxEptInfo.PDPT[i].Flags = 0;
        pForgVmxEntry->VmxEptInfo.PDPT[i].ReadAccess = 1;
        pForgVmxEntry->VmxEptInfo.PDPT[i].WriteAccess = 1;
        pForgVmxEntry->VmxEptInfo.PDPT[i].ExecuteAccess = 1;
        pForgVmxEntry->VmxEptInfo.PDPT[i].PageFrameNumber = MmGetPhysicalAddress(&pForgVmxEntry->VmxEptInfo.PDT[i][0]).QuadPart / PAGE_SIZE; // 获取 PFN
    }

    for (int i = 0; i < PDPTE_ENTRY_COUNT; i++)
    {
        // 构建PDT的每2M为一个页面
        for (int j = 0; j < PDE_ENTRY_COUNT; j++)
        {
            pForgVmxEntry->VmxEptInfo.PDT[i][j].Flags = 0;
            pForgVmxEntry->VmxEptInfo.PDT[i][j].ReadAccess = 1;
            pForgVmxEntry->VmxEptInfo.PDT[i][j].WriteAccess = 1;
            pForgVmxEntry->VmxEptInfo.PDT[i][j].ExecuteAccess = 1;
            pForgVmxEntry->VmxEptInfo.PDT[i][j].LargePage = 1;
            pForgVmxEntry->VmxEptInfo.PDT[i][j].PageFrameNumber = ((uintptr_t)i * 512) + j;

            //根据MTRR设置内存类型
            SetEptMemoryByMttrInfo(pForgVmxEntry, i, j);
        }
    }
}

void
Frog_SetEptp(pFrogVmx pForgVmxEntry)
{
    Ia32VmxEptVpidCapMsr ia32Eptinfo = { __readmsr(kIa32VmxEptVpidCap) };


    if (ia32Eptinfo.fields.support_page_walk_length4)
    {
        pForgVmxEntry->VmxEptInfo.VmxEptp.PageWalkLength = 3; // 设置为 4 级页表
    }

    if (ia32Eptinfo.fields.support_uncacheble_memory_type)
    {
        pForgVmxEntry->VmxEptInfo.VmxEptp.MemoryType = MEMORY_TYPE_UNCACHEABLE; // UC(无缓存类型的内存)
    }

    if (ia32Eptinfo.fields.support_write_back_memory_type)
    {
        pForgVmxEntry->VmxEptInfo.VmxEptp.MemoryType = MEMORY_TYPE_WRITE_BACK;  // WB(可回写类型的内存, 支持则优先设置)
    }

    if (ia32Eptinfo.fields.support_accessed_and_dirty_flag) // Ept dirty 标志位是否有效
    {
        pForgVmxEntry->VmxEptInfo.VmxEptp.EnableAccessAndDirtyFlags = true;
    }
    else
    {
        pForgVmxEntry->VmxEptInfo.VmxEptp.EnableAccessAndDirtyFlags = false;
    }

    pForgVmxEntry->VmxEptInfo.VmxEptp.PageFrameNumber = MmGetPhysicalAddress(&(pForgVmxEntry->VmxEptInfo.PML4T[0])).QuadPart / PAGE_SIZE;

}

void
Frog_GetMtrrInfo()
{
    MTRR_CAPABILITIES MtrrCapabilities = { 0 };
    MTRR_VARIABLE_BASE MtrrBase = { 0 };
    MTRR_VARIABLE_MASK MtrrMask = { 0 };
    unsigned long bit = 0;

    MtrrCapabilities.AsUlonglong = __readmsr(kIa32MtrrCap); /* 获取MTRR相关信息 */
    for (int i = 0; i < MtrrCapabilities.u.VarCnt; i++)
    {
        MtrrBase.AsUlonglong = __readmsr(kIa32MtrrPhysBaseN + i * 2);
        MtrrMask.AsUlonglong = __readmsr(kIa32MtrrPhysMaskN + i * 2);

        //检查是否启用
        if (MtrrMask.u.Enabled) /*mtrrData[i].Enabled != false && */
        {
            PFrogMtrrFange   MtrrDesciptor = &g_FrogCpu->MtrrRange[g_FrogCpu->NumberOfEnableMemRangs++];
            MtrrDesciptor->Type = (UINT32)MtrrBase.u.Type;
            MtrrDesciptor->Enabled = (UINT32)MtrrMask.u.Enabled;

            //设置基地址
            MtrrDesciptor->PhysicalAddressMin = MtrrBase.u.PhysBase * PAGE_SIZE;

            _BitScanForward64(&bit, MtrrMask.u.PhysMask * PAGE_SIZE);
            MtrrDesciptor->PhysicalAddressMax = MtrrDesciptor->PhysicalAddressMin + ((1ULL << bit) - 1);

            if (g_FrogCpu->MtrrRange[i].Type == MTRR_TYPE_WB) {
				g_FrogCpu->NumberOfEnableMemRangs--;
            }
        }

    }

}


void
Frog_Hook()
{
    if (g_FrogCpu->EnableHookMsr)
    {
        Frog_MsrHookEnable();
    }
}

void
Frog_UnHook()
{
    if (g_FrogCpu->EnableHookMsr)
    {
        Frog_MsrHookDisable();
    }
}

void Frog_RunEachProcessor(PFN_FrogRunEachProcessor Routine)
{
    ULONG       NumberOfProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (ULONG ProcessIndex = 0; ProcessIndex < NumberOfProcessors; ProcessIndex++)
    {
        PROCESSOR_NUMBER          ProcessNumber = { 0 };
        GROUP_AFFINITY                  affinity;
        GROUP_AFFINITY                  Origaffinity;

        KeGetProcessorNumberFromIndex(ProcessIndex, &ProcessNumber);
        RtlSecureZeroMemory(&affinity, sizeof(GROUP_AFFINITY));
        affinity.Group = ProcessNumber.Group;
        affinity.Mask = (KAFFINITY)1ull << ProcessNumber.Number;
        KeSetSystemGroupAffinityThread(&affinity, &Origaffinity);

        Routine(ProcessIndex);

        KeRevertToUserGroupAffinityThread(&Origaffinity);
    }
}
