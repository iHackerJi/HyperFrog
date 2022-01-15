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

ULONG RvaToOffset(PIMAGE_NT_HEADERS pnth, ULONG Rva, ULONG FileSize)
{
    PIMAGE_SECTION_HEADER psh = IMAGE_FIRST_SECTION(pnth);
    USHORT NumberOfSections = pnth->FileHeader.NumberOfSections;
    for (int i = 0; i < NumberOfSections; i++)
    {
        if (psh->VirtualAddress <= Rva)
        {
            if ((psh->VirtualAddress + psh->Misc.VirtualSize) > Rva)
            {
                Rva -= psh->VirtualAddress;
                Rva += psh->PointerToRawData;
                return Rva < FileSize ? Rva : 0;
            }
        }
        psh++;
    }
    return 0;
}

void sleep(LONG milliseconds)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -(10000ll * milliseconds);

    KeDelayExecutionThread(KernelMode, FALSE, &interval);
}