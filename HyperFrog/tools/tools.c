#include "public.h"

void	Frog_PrintfEx(char *format, ...) {
	NTSTATUS	Status = STATUS_SUCCESS;
	char buf[1024] = { 0 };
	va_list args = NULL;

	va_start(args, format);
	Status = RtlStringCchVPrintfA(buf, RTL_NUMBER_OF(buf), format,args);
	va_end(args);

	if (!NT_SUCCESS(Status))
	{
		FrogBreak();
		return;
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-]Frog : %s \r\n", buf);
}