#include "public.h"

void	UnloadDriver(PDRIVER_OBJECT DriverObject) {
	FrogRetCode	Status;
	FrogBreak();
	Status = Frog_DisableHyper();
	if (!Frog_SUCCESS(Status))
	{
		FrogBreak();
		FrogPrint("HyperUnload Error");
	}
}

NTSTATUS	DriverEntry(PDRIVER_OBJECT	pDriverObj,PUNICODE_STRING	pReg) {
	pDriverObj->DriverUnload = UnloadDriver;
	FrogRetCode	fStatus = FrogSuccess;
	NTSTATUS		nStatus = STATUS_SUCCESS;
	
	nStatus = InitComm(pDriverObj);
	if (!NT_SUCCESS(nStatus))
	{
        FrogBreak();
        FrogPrint("InitComm Error");
        return STATUS_UNSUCCESSFUL;
	}
    //ÉêÇë ForgVmxRegion
    if (!Forg_AllocateForgVmxRegion()) {
        FrogBreak();
        FrogPrint("ForgAllocatePool Error");
        return STATUS_UNSUCCESSFUL;
    }

    g_FrogCpu->EnableEpt = TRUE;
    g_FrogCpu->EnableHookMsr = FALSE;

	fStatus = Frog_EnableHyper();

	return	STATUS_SUCCESS;
}