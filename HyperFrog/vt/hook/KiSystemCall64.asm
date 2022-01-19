FakeKiSystemCall64	PROTO

extern g_MsrHookEnableTable:DB
extern g_MsrHookFunctionTable:DQ
extern g_MsrHookArgUpCodeTable:DB
extern g_KiSystemServiceCopyEnd:DQ 
extern g_origKisystemcall64:DQ
extern g_KiSaveDebugRegisterState:DQ
extern g_KiUmsCallEntry:DQ;
extern g_majorVersion:DD
extern MmUserProbeAddress:DQ
extern Frog_getOrigKisystemcall64 : proc

extern offset_Kthread_TrapFrame:DQ
extern offset_Kthread_SystemCallNumber:DQ
extern offset_Kthread_FirstArgument:DQ
extern offset_Kthread_ThreadFlags:DQ
extern offset_Kthread_CombinedApcDisable:DQ
extern offset_Kthread_MiscFlags:DQ
extern offset_Kthread_Ucb:DQ
extern offset_Kthread_TebMappedLowVa:DQ
extern offset_Kthread_Teb:DQ

USERMD_STACK_GS = 10h
KERNEL_STACK_GS = 1A8h
MAX_SYSCALL_INDEX = 1000h

.data
origKisystemcall64 DQ 0;

.code

; *********************************************************
;
; Determine if the specific syscall should be hooked
;
; if (SyscallHookEnabled[EAX & 0xFFF] == TRUE)
;     jmp KiSystemCall64_Emulate
; else (fall-through)
;     jmp KiSystemCall64
;
; *********************************************************
FakeKiSystemCall64 PROC
    ;cli                                    ; Disable interrupts
    swapgs                                  ; swap GS base to kernel PCR
    mov         gs:[USERMD_STACK_GS], rsp   ; save user stack pointer
    cmp         rax, MAX_SYSCALL_INDEX      ; Is the index larger than the array size?
    jge         KiSystemCall64              ;

    lea         rsp, offset g_MsrHookEnableTable     ; RSP = &SyscallHookEnabled
    cmp         byte ptr [rsp + rax], 0     ; Is hooking enabled for this index?
    jne         KiSystemCall64_Emulate      ; NE = index is hooked
FakeKiSystemCall64 ENDP

; *********************************************************
;
; Return to the original NTOSKRNL syscall handler
; (Restore all old registers first)
;
; *********************************************************
KiSystemCall64 PROC
    ;int 3
   ;push rax
   ;push rcx
   ;call Frog_getOrigKisystemcall64
   ;mov origKisystemcall64,rax
   ;pop rcx
   ;pop rax
	mov         rsp, gs:[USERMD_STACK_GS]   ; Usermode RSP
	swapgs                                  ; Switch to usermode GS
    jmp         [g_origKisystemcall64]
	;jmp         [origKisystemcall64]         ; Jump back to the old syscall handler
KiSystemCall64 ENDP

; *********************************************************
;
; Emulated routine executed directly after a SYSCALL
; (See: MSR_LSTAR)
;
; *********************************************************
KiSystemCall64_Emulate PROC
    ; NOTE:
    ; First 2 lines are included in SyscallEntryPoint
    mov         rsp, gs:[KERNEL_STACK_GS]   ; set kernel stack pointer
    push        2Bh                         ; push dummy SS selector
    push        qword ptr gs:[10h]          ; push user stack pointer
    push        r11                         ; push previous EFLAGS
    push        33h                         ; push dummy 64-bit CS selector
    push        rcx                         ; push return address
    mov         rcx, r10                    ; set first argument value

    sub         rsp, 8h                     ; allocate dummy error code
    push        rbp                         ; save standard register
    sub         rsp, 158h                   ; allocate fixed frame
    lea         rbp, [rsp+80h]              ; set frame pointer
    mov         [rbp+0C0h], rbx             ; save nonvolatile registers
    mov         [rbp+0C8h], rdi             ;
    mov         [rbp+0D0h], rsi             ;
     mov        [rbp-50h], rax              ; save service argument registers
    mov         [rbp-48h], rcx              ;
    mov         [rbp-40h], rdx              ;
    mov         byte ptr [rbp-55h], 2h      ; set service active
    mov         rbx, gs:[188h]              ; get current thread 

    mov        r11,rbx
    add         r11,[offset_Kthread_TrapFrame]
    prefetchw   byte ptr [r11]         ;prefetchw   byte ptr [rbx+offset_Kthread_TrapFrame]          ; 预取 KTHREAD.TrapFrame 

    stmxcsr     dword ptr [rbp-54h]         ; save current MXCSR
    ldmxcsr     dword ptr gs:[180h]         ; set default MXCSR
    cmp         byte ptr [rbx+3], 0         ; _KTHREAD.Header.___u0.__s5.DpcActive 判断是否下了硬件断点
    mov         word ptr [rbp+80h], 0       ; assume debug not enabled
    jz          by_pass_save_debug        ; if z, debug not enabled

    test    byte ptr [rbx+3], 3h        ;判断  DebugActive  AltSyscall Reserved4 这两个位
    mov         [rbp-38h], r8               ;
    mov         [rbp-30h], r9               ;
     jz          pass_KiSaveDebugRegisterState
    call [g_KiSaveDebugRegisterState];保存调试寄存器
    ;int         3                           ; FIXME (Syscall with debug registers active)
    ;align       10h
pass_KiSaveDebugRegisterState:
    test    byte ptr [rbx+3], 80h ;check kthread.DebugActive Instrumented & Reserved2[bit 2]
    jz set_thread_UmsPerformingSyscall
    mov     ecx, 0C0000102h ; IA32_KERNEL_GS_BASE
    rdmsr
    shl     rdx, 20h
    or      rax, rdx
    cmp     rax, [MmUserProbeAddress]
    cmovnb  rax, [MmUserProbeAddress] ; 判断GS BASE 是否 低于用户空间，如果不低于则存到RAX

     mov     r11,rbx
     add      r11,[offset_Kthread_Teb]
     cmp     [r11], rax ;    cmp     [rbx+offset_Kthread_Teb], rax ; 判断是不是当前线程TEB
    jz set_thread_UmsPerformingSyscall
     mov     r11,rbx
     add      r11,[offset_Kthread_TebMappedLowVa]
     cmp     [r11], rax        ; cmp     [rbx+offset_Kthread_TebMappedLowVa], rax ;KTHREAD.TebMappedLowVa 
    jz set_thread_UmsPerformingSyscall
     mov     r11,rbx
     add      r11,[offset_Kthread_Ucb]
     mov     rdx, [r11] ; mov     rdx, [rbx+offset_Kthread_Ucb] ;KTHREAD.Ucb

     mov     r11,rbx
     add      r11,[offset_Kthread_MiscFlags]
     bts     dword ptr [r11], 0Bh   ;    bts     dword ptr [rbx+offset_Kthread_MiscFlags], 0Bh 

     mov     r11,rbx
     add      r11,[offset_Kthread_CombinedApcDisable]
     dec     word ptr [r11]         ;    dec     word ptr [rbx+offset_Kthread_CombinedApcDisable] ; KTHREAD.CombinedApcDisable
    mov     [rdx+80h], rax
    ;sti
    call    [g_KiUmsCallEntry]
    jmp debug_restore_reg

 set_thread_UmsPerformingSyscall:
    test    byte ptr [rbx+3], 40h
    jz debug_restore_reg
    mov     r11,rbx
    add      r11,[offset_Kthread_ThreadFlags]
    lock bts dword ptr [r11], 8 ;    lock bts dword ptr [rbx+offset_Kthread_ThreadFlags], 8

debug_restore_reg:
    mov     r8, [rbp-38h]   ; R8
    mov     r9, [rbp-30h]   ; R9

by_pass_save_debug:
    ;sti                                    ; enable interrupts
     mov     rax, [rbp-50h]  ; RAX
     mov     rcx, [rbp-48h]  ; RCX
     mov     rdx, [rbp-40h]  ; RDX 拿到参数，与调用号

    mov     r11,rbx
    add      r11,[offset_Kthread_FirstArgument]
    mov     [r11], rcx      ;    mov     [rbx+offset_Kthread_FirstArgument], rcx 

    mov     r11,rbx
    add      r11,[offset_Kthread_SystemCallNumber]
    mov     [r11], eax      ; mov         [rbx+offset_Kthread_SystemCallNumber], eax 
KiSystemCall64_Emulate ENDP

KiSystemServiceStart_Emulate PROC
    ; _KTHREAD.TrapFrame 求索引号
    mov     r11,rbx       
    add      r11,[offset_Kthread_TrapFrame]
    mov     [r11], rsp          ; mov         [rbx+offset_Kthread_TrapFrame], rsp 

    mov         edi, eax
    shr         edi, 7
    and         edi, 20h
    and         eax, 0FFFh
KiSystemServiceStart_Emulate ENDP

KiSystemServiceRepeat_Emulate PROC
    ; RAX = [IN ] syscall index
    ; RAX = [OUT] number of parameters
    ; R10 = [OUT] function address
    ; R11 = [I/O] trashed
    int 3;

   ;对栈的处理，HyperBone没有处理这部分所以只能HOOK 4个参数一下的函数
   lea     rsp, [rsp-70h]  ; 分配新的栈空间存放，使用 用户栈复制来的参数
   lea     rdi, [rsp+18h]
   mov     rsi, [rbp+100h] ; TRAP_FRAME.RSP
   lea     rsi, [rsi+20h]  ; 忽略用户栈中的返回值
                                  ; 忽略为寄存器参数预留的栈空间

    lea         r11, offset g_MsrHookFunctionTable
    mov       r10, qword ptr [r11 + rax * 8h]

    lea         r11, offset g_MsrHookArgUpCodeTable
    movzx       rax, byte ptr [r11 + rax * 4h]   ; RAX = paramter count

     test    byte ptr [rbp+0F0h], 1 ; TRAP_FRAME.SegCs判断SYSCALL是否为用户模式
     jz       KiSystemServiceCopyEnd
     cmp     rsi, [MmUserProbeAddress]
     cmovnb  rsi, [MmUserProbeAddress]
     nop     dword ptr [rax+00000000h]
KiSystemServiceCopyEnd:

     mov r11,qword ptr [g_KiSystemServiceCopyEnd]
     sub r11,rax

     jmp r11

    ;lea         r11, offset ArgTble
    ;movzx       rax, byte ptr [r11 + rax]   ; RAX = paramter count

KiSystemServiceRepeat_Emulate ENDP


end