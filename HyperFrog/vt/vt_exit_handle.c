#include "vt.h"
#include "vt_help.h"
EXTERN_C	pFrogCpu		Frog_Cpu;

void			vmexit_readmsr_handle(pFrog_GuestContext	Context)
{
	ULONG64		MsrValue = 0;

	MsrValue = (ULONG64)__readmsr((ULONG)Context->Rcx);

	Context->Rax = LODWORD(MsrValue);
	Context->Rdx = HIDWORD(MsrValue);

}
void			vmexit_cpuid_handle(pFrog_GuestContext	Context)
{
	int		CpuidInfo[4] = { 0 };
	__cpuidex(CpuidInfo, (int)Context->Rax,(int)Context->Rcx);
	Context->Rax = (ULONG64)CpuidInfo[0];
	Context->Rbx = (ULONG64)CpuidInfo[1];
	Context->Rcx = (ULONG64)CpuidInfo[2];
	Context->Rdx = (ULONG64)CpuidInfo[3];

	return;
}

EXTERN_C VOID		vmexit_handle(pFrog_GuestContext	Context)
{
	KIRQL				Irql = 0;
	VmxExitInfo		ExitInfo = { 0 };
	ULONG64		Rip = 0;
	ULONG64		Rsp = 0;
	ULONG64		ExitinstructionsLength = 0;

	Irql = KeGetCurrentIrql();
	if (Irql < DISPATCH_LEVEL) Irql = KeRaiseIrqlToDpcLevel();

	ExitInfo.all = 	(ULONG32)Frog_Vmx_Read(VM_EXIT_REASON);

	switch (ExitInfo.fields.reason)
	{
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
		case ExitInvept:
		case ExitInvvpid:
		case ExitVmcall:
		case  ExitVmclear:
		case  ExitVmlaunch:
		case  ExitVmptrld:
		case  ExitVmptrst:
		case  ExitVmread:
		case  ExitVmresume:
		case  ExitVmwrite:
		case  ExitVmoff:
		case  ExitVmon:
			break;
		default:
			break;

	}

	Rip =	Frog_Vmx_Read(GUEST_RIP);
	Rsp =   Frog_Vmx_Read(GUEST_RSP);
	ExitinstructionsLength = Frog_Vmx_Read(VM_EXIT_INSTRUCTION_LEN);

	Rip += ExitinstructionsLength;

	Frog_Vmx_Write(GUEST_RIP, Rip);
	Frog_Vmx_Write(GUEST_RSP, Rsp);

	KeLowerIrql(Irql);

}