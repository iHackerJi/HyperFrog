extern RtlCaptureContext:proc
extern vmexit_handle:proc

.code

VmxEntryPointer	Proc
	int 3
	push rcx
	lea rcx,[rsp + 8h] ;这里 + 8 是因为上面push了rcx
    call    RtlCaptureContext
	jmp		vmexit_handle


VmxEntryPointer endp

END