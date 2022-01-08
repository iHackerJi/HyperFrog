#include "PublicHeader.h"

void	UnloadDriver(PDRIVER_OBJECT DriverObject) {
	FrogRetCode	Status;
	Status = Frog_DisableHyper();
	if (!Frog_SUCCESS(Status))
	{
		FrogBreak();
		FrogPrint("HyperUnload Error");
	}
}

NTSTATUS	DriverEntry(PDRIVER_OBJECT	pDriverObj,PUNICODE_STRING	pReg) {
	pDriverObj->DriverUnload = UnloadDriver;
	FrogRetCode	Status = FrogSuccess;

    //ÉêÇë ForgVmxRegion
    if (!Forg_AllocateForgVmxRegion()) {
        FrogBreak();
        FrogPrint("ForgAllocatePoolError");
        return STATUS_UNSUCCESSFUL;
    }

    g_FrogCpu->EnableEpt = TRUE;
    g_FrogCpu->EnableHookMsr = FALSE;

    Status = Frog_EnableHyper();

	return	STATUS_SUCCESS;
}