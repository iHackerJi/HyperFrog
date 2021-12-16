VmxEntryPointer	PROTO
extern vmexit_handle:proc

.CODE


VmxEntryPointer	Proc
	cli

 int 3
 push r15
 mov r15,rsp
 add rsp,8
 push r14
 push r13
 push r12
 push r11
 push r10
 push r9
 push r8
 push rdi
 push rsi
 push rbp
 push r15;rsp
 push rbx
 push rdx
 push rcx
 push rax
 
 mov rcx,rsp
 sub   rsp,0100h
 call		vmexit_handle
 add   rsp,0100h

 pop rax
 pop rcx
 pop rdx
 pop rbx
 add rsp, 8
 pop rbp
 pop rsi
 pop rdi
 pop r8
 pop r9
 pop r10
 pop r11
 pop r12
 pop r13
 pop r14
 pop r15
 sti

 vmresume;   返回到VM non-root(返回到Guest环境里继续执行)
 ret
VmxEntryPointer Endp
END