#include "public.h"

void	Frog_PrintfEx(char *format, ...) {
	NTSTATUS	Status = STATUS_SUCCESS;
	char buf[1024] = { 0 };
	va_list args = NULL;

	va_start(args, format);
	Status = RtlStringCchVPrintfA(buf, RTL_NUMBER_OF(buf), format,args);
	va_end(args);

	if (!NT_SUCCESS(Status))
	{
		FrogBreak();
		return;
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-]Frog : %s \r\n", buf);
}

ULONG RvaToOffset(PIMAGE_NT_HEADERS pnth, ULONG Rva, ULONG FileSize)
{
    PIMAGE_SECTION_HEADER psh = IMAGE_FIRST_SECTION(pnth);
    USHORT NumberOfSections = pnth->FileHeader.NumberOfSections;
    for (int i = 0; i < NumberOfSections; i++)
    {
        if (psh->VirtualAddress <= Rva)
        {
            if ((psh->VirtualAddress + psh->Misc.VirtualSize) > Rva)
            {
                Rva -= psh->VirtualAddress;
                Rva += psh->PointerToRawData;
                return Rva < FileSize ? Rva : 0;
            }
        }
        psh++;
    }
    return 0;
}

void sleep(LONG milliseconds)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -10000ll * milliseconds;

    KeDelayExecutionThread(KernelMode, FALSE, &interval);
}


// 修改Cr0寄存器, 去除写保护（内存保护机制）
KIRQL RemovWP()
{
    KIRQL irQl;
    //DbgPrint("RemovWP\n");
    // (PASSIVE_LEVEL)提升 IRQL 等级为DISPATCH_LEVEL，并返回旧的 IRQL
    // 需要一个高的IRQL才能修改
    irQl = KeRaiseIrqlToDpcLevel();
    ULONG_PTR cr0 = __readcr0(); // 内联函数：读取Cr0寄存器的值, 相当于: mov eax,  cr0;

    // 将第16位（WP位）清0，消除写保护
    cr0 &= ~0x10000; // ~ 按位取反
    _disable(); // 清除中断标记, 相当于 cli 指令，修改 IF标志位
    __writecr0(cr0); // 将cr0变量数据重新写入Cr0寄存器中，相当于: mov cr0, eax
    //DbgPrint("退出RemovWP\n");
    return irQl;
}

// 复原Cr0寄存器
KIRQL UnRemovWP(KIRQL irQl)
{

    //DbgPrint("UndoWP\n");
    ULONG_PTR cr0 = __readcr0();
    cr0 |= 0x10000; // WP复原为1
    _disable(); // 清除中断标记, 相当于 cli 指令，清空 IF标志位
    __writecr0(cr0); // 将cr0变量数据重新写入Cr0寄存器中，相当于: mov cr0, eax

    // 恢复IRQL等级
    KeLowerIrql(irQl);
    //DbgPrint("退出UndoWP\n");
    return irQl;
}


// 获取物理地址对应的Pte
// 将 ring3 的内存映射到 ring0 并返回一个内核 LinerAddress
VOID* GetKernelModeLinerAddress(ULONG_PTR cr3, ULONG_PTR user_mode_address,size_t size)
{
    PHYSICAL_ADDRESS cr3_phy = { 0 };
    cr3_phy.QuadPart = cr3;
    ULONG_PTR current_cr3 = 0;
    PVOID cr3_liner_address = NULL;

    PHYSICAL_ADDRESS user_phy = { 0 };
    PVOID kernel_mode_liner_address = NULL;

    // 判断cr3是否真确	
    cr3_liner_address = MmGetVirtualForPhysical(cr3_phy);
    if (!MmIsAddressValid(cr3_liner_address)) {
        return NULL;
    }
    // 判断是否为 rin3 的地址 以及 地址是否可读取
    else if (user_mode_address >= 0xFFFFF80000000000) {
        // 如果为内核地址, 不需要映射
        return (void*)user_mode_address;
    }
    // 如果地址不可读
    else if (!MmIsAddressValid((void*)user_mode_address)) {
        return NULL;
    }

    current_cr3 = __readcr3();
    // 关闭写保护，切换Cr3
    KIRQL Irql = RemovWP();
    __writecr3(cr3_phy.QuadPart);

    // 映射 user mode 内存	
    user_phy = MmGetPhysicalAddress((void*)user_mode_address);
    //PVOID kernel_mode_liner_address = MmGetVirtualForPhysical(user_phy); //(直接分解PTE的形式获取对应的虚拟地址)
    kernel_mode_liner_address = MmMapIoSpace(user_phy, size, MmNonCached); // 映射rin3内存到rin0

    // 恢复
    __writecr3(current_cr3);
    UnRemovWP(Irql);

    if (kernel_mode_liner_address) {
        return kernel_mode_liner_address;
    }
    else
        return NULL;
}

VOID FreeKernelModeLinerAddress(VOID* p, size_t size)
{
    if ((ULONG_PTR)p < 0xFFFFF80000000000) {
        if (p && size) {
            MmUnmapIoSpace(p, size);
        }
    }
}