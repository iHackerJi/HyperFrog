VmxEntryPointer	PROTO
Asm_VmxCall PROTO
extern vmexit_handle:proc
extern RtlCaptureContext:proc

.CODE
Asm_Jmp Proc
	mov rsp,rdx
	jmp rcx
	ret
Asm_Jmp Endp

Asm_VmxCall Proc
	push rax
	push rcx
	push rdx
	push rbx
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15 
	pushfq

	vmcall ; µ÷ÓÃ VMCALL
	
	popfq
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbx
	pop rdx
	pop rcx
	pop rax 
	ret
Asm_VmxCall Endp

Asm_resume PROC 
    vmresume
    ret
Asm_resume ENDP

Asm_restore_context PROC

	push rbp
	push rsi
	push rdi
	sub rsp, 30h
	mov rbp, rsp
	movaps  xmm0, xmmword ptr [rcx+1A0h]
	movaps  xmm1, xmmword ptr [rcx+1B0h]
	movaps  xmm2, xmmword ptr [rcx+1C0h]
	movaps  xmm3, xmmword ptr [rcx+1D0h]
	movaps  xmm4, xmmword ptr [rcx+1E0h]
	movaps  xmm5, xmmword ptr [rcx+1F0h]
	movaps  xmm6, xmmword ptr [rcx+200h]
	movaps  xmm7, xmmword ptr [rcx+210h]
	movaps  xmm8, xmmword ptr [rcx+220h]
	movaps  xmm9, xmmword ptr [rcx+230h]
	movaps  xmm10, xmmword ptr [rcx+240h]
	movaps  xmm11, xmmword ptr [rcx+250h]
	movaps  xmm12, xmmword ptr [rcx+260h]
	movaps  xmm13, xmmword ptr [rcx+270h]
	movaps  xmm14, xmmword ptr [rcx+280h]
	movaps  xmm15, xmmword ptr [rcx+290h]
	ldmxcsr dword ptr [rcx+34h]

	mov     ax, [rcx+42h]
	mov     [rsp+20h], ax;ss
	mov     rax, [rcx+98h] ; RSP
	mov     [rsp+18h], rax
	mov     eax, [rcx+44h];Eflags
	mov     [rsp+10h], eax
	mov     ax, [rcx+38h];cs
	mov     [rsp+08h], ax
	mov     rax, [rcx+0F8h] ; RIP
	mov     [rsp+00h], rax ; set RIP as return address (for iretq instruction).

	mov     rax, [rcx+78h]
	mov     rdx, [rcx+88h]
	mov     r8, [rcx+0B8h]
	mov     r9, [rcx+0C0h]
	mov     r10, [rcx+0C8h]
	mov     r11, [rcx+0D0h]

	mov     rbx, [rcx+90h]
	mov     rsi, [rcx+0A8h]
	mov     rdi, [rcx+0B0h]
	mov     rbp, [rcx+0A0h]
	mov     r12, [rcx+0D8h]
	mov     r13, [rcx+0E0h]
	mov     r14, [rcx+0E8h]
	mov     r15, [rcx+0F0h]
	mov     rcx, [rcx+80h]
	sti
	iretq

Asm_restore_context ENDP

VmxEntryPointer	Proc
	cli
	;int 3;
	;sub rsp,4d0h
	push  rcx
    lea     rcx, [rsp+8h]
	call    RtlCaptureContext
	jmp	 vmexit_handle
VmxEntryPointer Endp
END