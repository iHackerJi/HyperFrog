#include "public.h"
void    vmexit_exception_handle(PCONTEXT Context);
void    vmexit_readmsr_handle(PCONTEXT	 Context);
void    vmexit_cpuid_handle(PCONTEXT	 Context);
void    vmexit_craccess_handle(PCONTEXT	Context);
void    vmexit_vmcall_handle(pFrogVmx pForgVmxEntry, PCONTEXT Context);

extern void vmexit_handle(PCONTEXT Context)
{
    Context->Rcx = *(PULONG64)((ULONG_PTR)Context - sizeof(Context->Rcx));
    //这些地方有问题的可能性比较大
    ULONG			CpuNumber = KeGetCurrentProcessorNumber();
    pFrogVmx		pForgVmxEntry = &g_FrogCpu->pForgVmxEntrys[CpuNumber];
    pForgVmxEntry->VmxExitTime = __rdtsc();

    VmxExitInfo		ExitInfo = { 0 };
    ULONG64		Rip = 0;
    ULONG64		Rsp = 0;
    ULONG64		ExitinstructionsLength = 0;
    FlagReg           GuestRflag = { 0 };

    ExitInfo.all = (ULONG32)Frog_Vmx_Read(VM_EXIT_REASON);

    switch (ExitInfo.fields.reason)
    {
    case ExitExternalInterrupt:
        vmexit_exception_handle(Context);
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
    case ExitCrAccess:
        vmexit_craccess_handle(Context);
        break;
    case ExitVmcall:
        vmexit_vmcall_handle(pForgVmxEntry,Context);
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
        GuestRflag.all = Frog_Vmx_Read(GUEST_RFLAGS);
        GuestRflag.fields.cf = 1;//拒绝嵌套
        Frog_Vmx_Write(GUEST_RFLAGS, GuestRflag.all);
        break;
    }
    default:
        break;
    }

    if (pForgVmxEntry->HyperIsEnable == false)
    {
        FrogBreak();
        ULONG64		Rip = Frog_Vmx_Read(GUEST_RIP);
        ULONG64		Rsp = Frog_Vmx_Read(GUEST_RSP);
        ULONG64		ExitinstructionsLength = 0;
        ULONG64        Guest_Cr3 = 0;
        ULONG64        Guest_Gs_Base = 0;
        ULONG64        Guest_Fs_Base = 0;

        ExitinstructionsLength = Frog_Vmx_Read(VM_EXIT_INSTRUCTION_LEN);
        Rip += ExitinstructionsLength;

        Context->Rip = Rip;
        Context->Rsp = Rsp;
        //我们的回调程序可能中断了一个任意的用户进程，
        //因此不是一个运行在系统级页面目录下的线程。
        //我们要写回
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
    }
    else
    {
        ULONG64		Rip = Frog_Vmx_Read(GUEST_RIP);
        ULONG64		ExitinstructionsLength = Frog_Vmx_Read(VM_EXIT_INSTRUCTION_LEN);
        Rip += ExitinstructionsLength;
        Frog_Vmx_Write(GUEST_RIP, Rip);

        pForgVmxEntry->VmxExitTime = __rdtsc() - pForgVmxEntry->VmxExitTime;
        Frog_Vmx_Write(TSC_OFFSET, pForgVmxEntry->VmxExitTime);//bypass rdtsc
        Context->Rsp += sizeof(Context->Rcx);
        Context->Rip = (ULONG64)Asm_resume;
    }

    Asm_restore_context(Context);
    return;
}

void inject_event(unsigned long  vector, unsigned long type, bool error_code_valid, unsigned long  error_code)
{
    INTERRUPTION_INFORMATION Exception = { 0 };
    Exception.fields.valid = true;
    Exception.fields.vector = vector;
    Exception.fields.interruption_type = type;
    Exception.fields.error_code_valid = error_code_valid;
    if (error_code_valid == 1) {
        Frog_Vmx_Write(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
    }
    Frog_Vmx_Write(VM_ENTRY_INTR_INFO, Exception.all);
}

void    vmexit_readmsr_handle(PCONTEXT Context)
{
    __int64 marValue = 0;
    switch (Context->Rcx)
    {
    case kIa32Lstar:
    {
        if (g_FrogCpu->EnableHookMsr)
        {
            marValue = Frog_getOrigKisystemcall64();//防止PG
        }
        marValue = (__int64)__readmsr((unsigned long)Context->Rcx);
        break;
    }
        default:
        {
            marValue = (__int64)__readmsr((unsigned long)Context->Rcx);
            break;
        }
    }
    Context->Rax = LODWORD(marValue);
    Context->Rdx = HIDWORD(marValue);

}
void    vmexit_cpuid_handle(PCONTEXT Context)
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
void    vmexit_craccess_handle(PCONTEXT Context)
{
    FrogBreak();
    CrxVmExitQualification         CrxQualification = { 0 };
    PULONG64                           RegContext = (PULONG64)&Context->Rax;
    ULONG64                             Register = 0;
    FrogBreak();
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
void    vmexit_vmcall_handle(pFrogVmx		pForgVmxEntry,PCONTEXT Context)
{
    switch (Context->Rcx)
    {
        case    FrogExitTag:
        {
            pForgVmxEntry->HyperIsEnable = false;
            break;
        }
    }

}


void    vmexit_exception_handle(PCONTEXT	Context)
{
    FrogBreak();
    INTERRUPTION_INFORMATION ExceptionInfo = { 0 };
    ExceptionInfo.all =  (ULONG)Frog_Vmx_Read(VM_EXIT_INTR_INFO);
    unsigned long type = ExceptionInfo.fields.interruption_type;
    unsigned long vector = ExceptionInfo.fields.vector;
    if (vector == ia32_debug_exception)
    {
        if (type== ia32_prisw_exception)
        {
            /*
            KiErrata361Present
            */
            FrogBreak();
            DR6 dr6 = { 0 };
            EFLAGS Eflags = { 0 };
            dr6.flags = Context->Dr6;
            Eflags.All = Context->EFlags;
            if (Eflags.Fields.TF)
            {
                dr6.single_instruction = 1;
                Context->Dr6 = dr6.flags;
                inject_event(ia32_debug_exception, type, false, 0);
                return;
            }

        }

        if (type == ia32_hardware_exception)
        {
            if (Context->Rip == (ULONG64)FakeKiSystemCall64)
            {
                /*
                    KiErrataSkx55Present
                */
                FrogBreak();
                EFLAGS Eflags = { 0 };
                Eflags.All = Context->EFlags;
                Eflags.Fields.TF = 0;

                Context->Rip = g_origKisystemcall64;
                Context->EFlags = Eflags.All;
                Frog_Vmx_Write(GUEST_RIP, Context->Rip);
                return;
            }
            inject_event( vector,type, false, 0);
            Frog_Vmx_Write(VM_ENTRY_INSTRUCTION_LEN, Frog_Vmx_Read(VM_EXIT_INSTRUCTION_LEN));
        }
    }

}
