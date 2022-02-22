#include "public.h"

bool Frog_EferHookEnable()
{
	Ia32VmxBasicMsr VmxBasicMsr = { 0 };
	ULONG UsetrueMsrs = 0;
    VmxBasicMsr.all = __readmsr(kIa32VmxBasic);
    UsetrueMsrs = (bool)VmxBasicMsr.fields.vmx_capability_hint;

	VmxVmentryControls	VmVmentryControls = { 0 };
	VmxmexitControls		VmExitControls = { 0 };
	Efer efer = { 0 };
    efer.all = __readmsr(kIa32Efer);
    efer.Bits.sce = false;
	VmVmentryControls.all = (unsigned int)Frog_Vmx_Read(VM_ENTRY_CONTROLS);
	VmExitControls.all = (unsigned int)Frog_Vmx_Read(VM_EXIT_CONTROLS);

    //   1. Enable VMX
    //   2. 设置 VM - entry 中的 load_ia32_efer 字段
    //   3. 设置 VM - exit 中的 save_ia32_efer 与 load_ia32_efer 字段
    //   4. 设置 MSR - bitmap 让其在, 写入和读取EFER MSR时退出 ？？
    //   5. 设置 Exception - bitmap 拦截 #UD 异常
    //   7. 清除 sce 位
    //   8. 处理 SysCall 与 SysRet 指令导致的 #UD 异常


	VmVmentryControls.fields.load_ia32_efer = true;
    VmExitControls.fields.load_ia32_efer = true;
    VmExitControls.fields.save_ia32_efer = true;

    ULONG ExceptionBitmap = 0;
    ExceptionBitmap |= 1 << VECTOR_INVALID_OPCODE_EXCEPTION;//拦截UD异常
    Frog_Vmx_Write(EXCEPTION_BITMAP, ExceptionBitmap);

	Frog_Vmx_Write(VM_ENTRY_CONTROLS, VmVmentryControls.all);
	Frog_Vmx_Write(VM_EXIT_CONTROLS, VmExitControls.all);
	Frog_Vmx_Write(GUEST_EFER, efer.all);

    return true;
}

bool Frog_EmulateSyscall(PCONTEXT Context)
{
	// 获取基本信息
	PNT_KPROCESS current_process = (PNT_KPROCESS)PsGetCurrentProcess();
	ULONG_PTR MsrValue = 0;
	FrogRetCode Status = FrogSuccess;
	ULONG_PTR guestRip = Frog_Vmx_Read(GUEST_RIP);
	//ULONG_PTR guestRsp = VtBase::VmCsRead(GUEST_RSP);
	ULONG_PTR GuestRflags = Frog_Vmx_Read(GUEST_RFLAGS);
	//ULONG_PTR guest_r3_cr3 = VtBase::VmCsRead(GUEST_CR3);
	ULONG_PTR exitInstructionLength = Frog_Vmx_Read(VM_EXIT_INSTRUCTION_LEN); // 退出的指令长度

	// 参考白皮书 SYSCALL—Fast System Call

	/*
		a.	SysCall loading Rip From the IA32_LSTA MSR
		b.	SysCall 加载 IA32_LSTA MSR 的值到 Rip 中
	*/
	//MsrValue = __readmsr(MSR_LSTAR);
	// 走我们的流程
	MsrValue = (ULONG_PTR)FakeKiSystemCall64;
	Status |= Frog_Vmx_Write(GUEST_RIP, MsrValue);

	/*
		a.	After Saving the Adress of the instruction following SysCall into Rcx
		b.	SysCall 会将下一行指令地址保存到 Rcx 中
	*/
	ULONG_PTR next_instruction = exitInstructionLength + guestRip;
    Context->Rcx = next_instruction;
	/*
		a. Save RFLAGS into R11 and then mask RFLAGS using MSR_FMASK.
		b. 保存 RFLAGS 到 R11 寄存器中, 并且使用 MSR_FMASK 清除 RFLAGS 对应的每一位
	*/
    
	MsrValue = __readmsr(kIa32Fmask);
	Context ->R11= GuestRflags;
	GuestRflags &= ~(MsrValue | X86_FLAGS_RF);
	Frog_Vmx_Write(GUEST_RFLAGS, GuestRflags);

	/*
		a. SYSCALL loads the CS and SS selectors with values derived from bits 47:32 of the IA32_STAR MSR.
		b. SysCall 加载 CS、SS 段寄存器的值来自于 IA32_STAR MSR 寄存器的 32:47 位
	*/
    MsrValue = __readmsr(kIa32Star);
	ULONG_PTR Cs = (UINT16)((MsrValue >> 32) & ~3);
    Status |= Frog_Vmx_Write(GUEST_CS_SELECTOR, Cs);
    Status |= Frog_Vmx_Write(GUEST_CS_LIMIT, (UINT32)~0);
    Status |= Frog_Vmx_Write(GUEST_CS_AR_BYTES, 0xA09B);
    Status |= Frog_Vmx_Write(GUEST_CS_BASE, 0);

	ULONG_PTR Ss = Cs + 0x8;
    Status |= Frog_Vmx_Write(GUEST_SS_SELECTOR, Ss);
    Status |= Frog_Vmx_Write(GUEST_SS_LIMIT, (UINT32)~0);
    Status |= Frog_Vmx_Write(GUEST_SS_AR_BYTES, 0xC093);
    Status |= Frog_Vmx_Write(GUEST_SS_BASE, 0);

	Status |= Frog_Vmx_Write(GUEST_CR3, current_process->DirectoryTableBase);
	
	if (!Frog_SUCCESS(Status))
		return false;
	
	return true;
}

bool Frog_EmulateSysret(PCONTEXT Context)
{
	// 获取基本信息
	//PNT_KPROCESS current_process = (PNT_KPROCESS)PsGetCurrentProcess();
	FrogRetCode Status = FrogSuccess;
	ULONG_PTR MsrValue = 0;
	ULONG_PTR GuestRflags =
		(Context->R11 & ~(X86_FLAGS_RF | X86_FLAGS_VM | X86_FLAGS_RESERVED_BITS)) | X86_FLAGS_FIXED;

	// 参考白皮书 SYSRET—Return From Fast System Call
	/*
		a. It does so by loading RIP from RCX and loading RFLAGS from R11
		b. 它将 RCX 值加载到 RIP , 将 R11 的值加载到 RFLAGS 来做到这一点
	*/

	Status |= Frog_Vmx_Write(GUEST_RIP, Context->Rcx);
	Status |= Frog_Vmx_Write(GUEST_RFLAGS, GuestRflags);

	/*
		a. SYSRET loads the CS and SS selectors with values derived from bits 63:48 of the IA32_STAR MSR.
		b. SysRet 加载 CS、SS 段寄存器的值来自于 IA32_STAR MSR 寄存器的 48:63 位
	*/
	
    MsrValue = __readmsr(kIa32Star);
	ULONG_PTR Cs = (UINT16)(((MsrValue >> 48) + 16) | 3);
	Status |= Frog_Vmx_Write(GUEST_CS_SELECTOR, Cs);
	Status |= Frog_Vmx_Write(GUEST_CS_LIMIT, (UINT32)~0);
	Status |= Frog_Vmx_Write(GUEST_CS_AR_BYTES, 0xA0FB);
	Status |= Frog_Vmx_Write(GUEST_CS_BASE, 0);

	ULONG_PTR Ss = (UINT16)(((MsrValue >> 48) + 8) | 3);
    Status |= Frog_Vmx_Write(GUEST_SS_SELECTOR, Ss);
    Status |= Frog_Vmx_Write(GUEST_SS_LIMIT, (UINT32)~0);
    Status |= Frog_Vmx_Write(GUEST_SS_AR_BYTES, 0xC0F3);
    Status |= Frog_Vmx_Write(GUEST_SS_BASE, 0);

    if (!Frog_SUCCESS(Status))
        return false;

    return true;
}