#include "PublicHeader.h"
#include "vt/vt.h"

NTSTATUS	DriverEntry(PDRIVER_OBJECT	pDriverObj,PUNICODE_STRING	pReg) {

	FrogRetCode	Code;

	Code = Frog_EnableHyper();

	

	return	STATUS_SUCCESS;
}