#include <ntifs.h>


NTSTATUS	DriverEntry(PDRIVER_OBJECT	pDriverObj,PUNICODE_STRING	pReg) {


	DbgPrint("1");
	return	STATUS_SUCCESS;
}