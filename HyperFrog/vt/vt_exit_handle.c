#include "public.h"
void    vmexit_exception_handle(pGuestStatus     Guest_Status, PCONTEXT	Context);
void    vmexit_readmsr_handle(PCONTEXT	Context);
void    vmexit_cpuid_handle(PCONTEXT	    Context);
void    vmexit_craccess_handle(PCONTEXT	Context);
void    vmexit_vmcall_handle(PCONTEXT	Context);
void    vmexit_writemsr_handle(PCONTEXT	Context);

extern void	vmexit_handle(PCONTEXT	Context)
{
   //KIRQL irql = KeGetCurrentIrql();
   //if (irql < DISPATCH_LEVEL) {
   //    KeRaiseIrqlToDpcLevel(); // 提升 IRQL 等级为 DPC_LEVEL
   //}

    Context->Rcx = *(PULONG64)((ULONG_PTR)Context - sizeof(Context->Rcx));
    VmxExitInfo		ExitInfo = { 0 };
    GuestStatus     Guest_Status = { 0 };
    Guest_Status.Rip = Frog_Vmx_Read(GUEST_RIP) + Frog_Vmx_Read(VM_EXIT_INSTRUCTION_LEN);
    Guest_Status.Eflags.all = Frog_Vmx_Read(GUEST_RFLAGS);
    ExitInfo.all = (ULONG32)Frog_Vmx_Read(VM_EXIT_REASON);

    switch (ExitInfo.fields.reason)
    {
    case ExitExceptionOrNmi: //NMI中断
        vmexit_exception_handle(&Guest_Status, Context);
        goto __Exit;
        break;
    case ExitExternalInterrupt:
        //vmexit_exception_handle(&Guest_Status,Context);
        break;
    case	ExitCpuid:
        vmexit_cpuid_handle(Context);
        break;
    case ExitInvd:
        __wbinvd();
        break;
    case ExitGetSec://暂时不处理
        break;
    case ExitXsetbv:
        _xsetbv((ULONG32)Context->Rcx, MAKEQWORD(Context->Rax, Context->Rdx));
        break;
    case ExitMsrRead:
        vmexit_readmsr_handle(Context);
        break;
    case ExitMsrWrite:
        vmexit_writemsr_handle(Context);
        break;
    case ExitCrAccess:
        vmexit_craccess_handle(Context);
        break;
    case ExitVmcall:
        vmexit_vmcall_handle(Context);
        break;
    case ExitInvept:
    case ExitInvvpid:
    case  ExitVmclear:
    case  ExitVmlaunch:
    case  ExitVmptrld:
    case  ExitVmptrst:
    case  ExitVmread:
    case  ExitVmresume:
    case  ExitVmwrite:
    case  ExitVmoff:
    case  ExitVmon:
    {
        Guest_Status.Eflags.fields.cf = 1;//拒绝嵌套
        break;
    }
    default:
        break;
    }

    //正常处理流程
    Context->Rsp += sizeof(Context->Rcx);
    Context->Rip = (ULONG64)Asm_resume;
    Frog_Vmx_Write(GUEST_RIP, Guest_Status.Rip);
    Frog_Vmx_Write(GUEST_RFLAGS, Guest_Status.Eflags.all);
    Asm_restore_context(Context);
__Exit:

   //if (irql < DISPATCH_LEVEL) {
   //    KeLowerIrql(irql);
   //}
    return;
}
PULONG64 GetPteAddress(PVOID addr)
{
    // 1个 PTE 对应 4KB
    return (PULONG64)(((((ULONG64)addr & 0xFFFFFFFFFFFF) >> 12) << 3) + 0xFFFFF90000000000);
}

void    inject_event(ULONG32 vector, ULONG32 type, bool deliver, ULONG32 error_code) {
    INTERRUPTION_INFORMATION _exception = {0};
    _exception.fields.valid = true;
    _exception.fields.vector = vector;
    _exception.fields.interruption_type = type;
    _exception.fields.error_code_valid = deliver;
    if (deliver == true) {

        Frog_Vmx_Write(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
    }
    Frog_Vmx_Write(VM_ENTRY_INTR_INFO, _exception.all);
}
void    vmexit_readmsr_handle(PCONTEXT	Context)
{
    __int64 msrValue = 0;
    switch (Context->Rcx)
    {
    case kIa32Lstar:
    {
        msrValue = Frog_getOrigKisystemcall64();//防止PG
        break;
    }
        default:
        {
            msrValue = (__int64)__readmsr((unsigned long)Context->Rcx);
            break;
        }
    }
    Context->Rax = LODWORD(msrValue);
    Context->Rdx = HIDWORD(msrValue);
}
void    vmexit_writemsr_handle(PCONTEXT	Context)
{
    __int64 msrValue = MAKEQWORD(Context->Rax, Context->Rdx);
    __writemsr((unsigned long)Context->Rcx, msrValue);
}
void    vmexit_cpuid_handle(PCONTEXT	    Context)
{
    CpuId		CpuidInfo = { 0 };
    switch (Context->Rax)
    {
        case FrogTag:
        {
            Context->Rax = FrogTag;
         break;
        }
        default:
        {
            __cpuidex((int *)&CpuidInfo, (int)Context->Rax, (int)Context->Rcx);
            Context->Rax = (ULONG64)CpuidInfo.eax;
            Context->Rbx = (ULONG64)CpuidInfo.ebx;
            Context->Rcx = (ULONG64)CpuidInfo.ecx;
            Context->Rdx = (ULONG64)CpuidInfo.edx;
            break;
        }
    }
	return;
}
void    vmexit_craccess_handle(PCONTEXT	Context)
{
    CrxVmExitQualification          CrxQualification = { 0 };
    PULONG64                            RegContext = (PULONG64)Context;
    ULONG64                             Register = 0;

    CrxQualification.all = Frog_Vmx_Read(EXIT_QUALIFICATION);
    Register = RegContext[CrxQualification.Bits.gp_register];

    if (CrxQualification.Bits.access_type == kMoveToCr)
    {
        switch (CrxQualification.Bits.crn)
        {
        case 0:
            {
                Frog_Vmx_Write(GUEST_CR0, Register);
                break;
            }
        case 3:
            {
            Frog_Vmx_Write(GUEST_CR3, Register);
            break;
            }
        case 4:
            {
                Frog_Vmx_Write(GUEST_CR4, Register);
                break;
            } 
        }

    }


}
void    vmexit_vmcall_handle(PCONTEXT	Context)
{
    switch (Context->Rcx)
    {
        case    FrogExitTag:
        {
            ULONG	        CurrentProcessor = 0;
            pFrogVmx		pForgVmxEntry = NULL;
            ULONG64		Rip = 0;
            ULONG64		Rsp = 0;
            ULONG64		ExitinstructionsLength = 0;
            ULONG64        Guest_Cr3 = 0;
            ULONG64        Guest_Gs_Base = 0;
            ULONG64        Guest_Fs_Base = 0;

            CurrentProcessor = KeGetCurrentProcessorNumber();
            pForgVmxEntry = &g_FrogCpu->pForgVmxEntrys[CurrentProcessor];

            Rip = Frog_Vmx_Read(GUEST_RIP);
            Rsp = Frog_Vmx_Read(GUEST_RSP);
            ExitinstructionsLength = Frog_Vmx_Read(VM_EXIT_INSTRUCTION_LEN);
            Rip += ExitinstructionsLength;

            Guest_Cr3 = Frog_Vmx_Read(GUEST_CR3);
            Guest_Gs_Base = Frog_Vmx_Read(GUEST_GS_BASE);
            Guest_Fs_Base = Frog_Vmx_Read(GUEST_FS_BASE);

            __writecr3(Guest_Cr3);
            __writemsr(kIa32FsBase, Guest_Fs_Base);
            __writemsr(kIa32GsBase, Guest_Gs_Base);

            _lgdt(&pForgVmxEntry->HostState.SpecialRegisters.Gdtr.Limit);//还原GDT边界
            __lidt(&pForgVmxEntry->HostState.SpecialRegisters.Idtr.Limit);//还原IDT边界

            __vmx_vmclear(&pForgVmxEntry->VmxVmcsAreaPhysicalAddr);
            __vmx_off();
            pForgVmxEntry->HyperIsEnable = false;
            Asm_Jmp(Rip, Rsp);
            break;
        }
        case FrogEferHookTag:
        {
            FrogBreak();
            Frog_EferHookEnable();
            break;
        }
    }
}
void    vmexit_exception_handle(pGuestStatus     Guest_Status,PCONTEXT	Context)
{
    INTERRUPTION_INFORMATION ExceptionInfo = { 0 };
    ExceptionInfo.all =  (ULONG32)Frog_Vmx_Read(VM_EXIT_INTR_INFO);
    unsigned long type = ExceptionInfo.fields.interruption_type;
    unsigned long vector = ExceptionInfo.fields.vector;
    unsigned long error_code_valid =  ExceptionInfo.fields.error_code_valid;
    FrogBreak();
    if (type == ia32_hardware_exception)//硬件异常
    {
        switch (vector) 
        {
            case ia32_page_fault:// #PF
            {
               unsigned long error_code =  (unsigned long)Frog_Vmx_Read(VM_EXIT_INTR_ERROR_CODE);
               inject_event(vector, type, true, error_code);//不处理，直接注入

               __int64 fault_addreee = Frog_Vmx_Read(EXIT_QUALIFICATION);
                __writecr2(fault_addreee);

                Frog_Vmx_Write(VM_ENTRY_INTR_INFO, ExceptionInfo.all);
                if (error_code_valid)
                {
                    Frog_Vmx_Write(VM_ENTRY_EXCEPTION_ERROR_CODE,Frog_Vmx_Read(VM_EXIT_INTR_ERROR_CODE));
                }
                break;
            }
            case ia32_general_protection://#GP
            {
                unsigned long error_code = (unsigned long)Frog_Vmx_Read(VM_EXIT_INTR_ERROR_CODE);
                inject_event(vector, type, true, error_code);//不处理，直接注入
                break;
            }
            case ia32_invalid_opcode://#UD
            {
                PNT_KPROCESS   pKprocess = (PNT_KPROCESS)PsGetCurrentProcess();
                unsigned __int64 Rip = Frog_Vmx_Read(GUEST_RIP);
                unsigned __int64 Guest_Cr3 = Frog_Vmx_Read(GUEST_CR3);
                unsigned __int64 OrigCr3 = __readcr3();
                unsigned __int64 exitInstructionLength = Frog_Vmx_Read(VM_EXIT_INSTRUCTION_LEN); // 退出的指令长度
                __int64 KernelCr3 = pKprocess->DirectoryTableBase;
                FrogBreak();

                __writecr3(KernelCr3);

                if (!MmIsAddressValid((void*)Rip))
                {
                    __writecr2(Rip);
                    unsigned long error_code = 0;
                    inject_event(vector, type, true, error_code);
                    break;
                }

                void * user_liner_adderss = GetKernelModeLinerAddress(KernelCr3,Rip,10);

                if (exitInstructionLength == 0x2 || exitInstructionLength == 0x3)
                {
                    if (IS_SYSCALL_INSTRUCTION(user_liner_adderss))
                    {
                        Frog_EmulateSyscall(Context);
                    }else if (IS_SYSRET_INSTRUCTION(user_liner_adderss))
                    {
                        Frog_EmulateSysret(Context);
                    }
                    else
                    {
                        inject_event(vector, type, false, 0);//不处理，直接注入
                    }
                }
                else
                {
                    inject_event(vector, type, false, 0);//不处理，直接注入
                }

                FreeKernelModeLinerAddress(user_liner_adderss,10);
                __writecr3(OrigCr3);
                break;
            }
        }
    }else if (type == ia32_software_exception)//软件异常
    {
        inject_event(vector, type, false, 0);
        Frog_Vmx_Write(VM_ENTRY_INSTRUCTION_LEN, Frog_Vmx_Read(VM_EXIT_INSTRUCTION_LEN));
    }
    else//其他异常
    {
        Frog_Vmx_Write(VM_ENTRY_INTR_INFO, ExceptionInfo.all);
        if (error_code_valid) 
        {
            Frog_Vmx_Write(VM_ENTRY_EXCEPTION_ERROR_CODE, Frog_Vmx_Read(VM_EXIT_INTR_ERROR_CODE));
        }
    }

    //if (vector == ia32_debug_exception)
    //{
    //    if (type == ia32_prisw_exception) 
    //    {
    //        FrogBreak();
    //        /*
    //        KiErrata361Present
    //        */
    //        if (Guest_Status->Eflags.fields.tf)
    //        {
    //            Dr6 dr6 = { 0 };
    //            dr6.flags = (ULONG)Context->Dr6;
    //            dr6.single_instruction = 1;
    //            Context->Dr6 = dr6.flags;
    //            inject_event(ia32_debug_exception, type, false, 0);
    //            Guest_Status->Rip = g_origKisystemcall64;
    //            return;
    //        }
    //    }
    //
    //    if (type == ia32_hardware_exception) 
    //    {
    //        FrogBreak();
    //        if (Frog_Vmx_Read(GUEST_RIP) == (uintptr_t)g_origKisystemcall64) {
    //            /*
    //                KiErrataSkx55Present
    //            */
    //            Guest_Status->Eflags.fields.tf = 0;
    //            Guest_Status->Rip = g_origKisystemcall64;
    //            return;
    //        }
    //        inject_event(vector, type, false, 0);
    //        Frog_Vmx_Write(VM_ENTRY_INSTRUCTION_LEN, Frog_Vmx_Read(VM_EXIT_INSTRUCTION_LEN));
    //    }
    //}
}
