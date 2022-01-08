#pragma once

void	VmxEntryPointer();
void  Asm_VmxCall(ULONG64    Rcx, ULONG64    Rdx, ULONG64    R8, ULONG64    R9);
void Asm_Jmp(ULONG64    Rip, ULONG64    Rsp);