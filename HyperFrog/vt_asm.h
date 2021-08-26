#pragma once
#include "PublicHeader.h"


EXTERN_C	UCHAR		__asm_vmxon(PHYSICAL_ADDRESS p1);
EXTERN_C	UCHAR		__asm_vmclear(LONGLONG p1); 
EXTERN_C	UCHAR		__asm_vmptrld(LONGLONG p1);
EXTERN_C	UCHAR		__asm_vmwrite(LONGLONG p1, LONGLONG p2);
EXTERN_C	LONGLONG	__asm_vmread(LONGLONG p1);