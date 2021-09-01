.code

;∑µªÿ1‘Ú ß∞‹


;__asm_vmxon proc
;	vmxon qword ptr[rcx]
;	setc al
;	setz cl
;	adc al,cl
;	ret
;__asm_vmxon endp
;
;
;
;__asm_vmclear proc
;	vmclear qword ptr[rcx]
;	setc al
;	setz cl
;	adc al,cl
;	ret
;__asm_vmclear endp
;
;
;__asm_vmptrld proc
;	vmptrld qword ptr[rcx]
;	setc al
;	setz cl
;	adc al,cl
;	ret
;__asm_vmptrld endp
;
;__asm_vmwrite proc
;	vmwrite rcx,rdx
;	setc al
;	setz cl
;	adc al,cl
;	ret
;__asm_vmwrite endp
;
;
;__asm_vmread  proc
;	vmread qword ptr[rax],rcx
;	ret
;__asm_vmread endp
;



END