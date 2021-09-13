#include "tools/tools.h"
#include "vt/vt.h"


void	UnloadDriver(PDRIVER_OBJECT DriverObject) {

	FrogBreak();


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

	FrogRetCode	Code;

	Code = Frog_EnableHyper();


	

	return	STATUS_SUCCESS;
}