#include "vt.h"
#include "vt_help.h"
EXTERN_C	pFrogCpu		Frog_Cpu;

EXTERN_C VOID		vmexit_handle(pFrog_GuestContext	Context)
{
	KIRQL	Irql = 0;
	VmxExitInfo ExitInfo = { 0 };

	__debugbreak();
	Irql = KeGetCurrentIrql();
	if (Irql < DISPATCH_LEVEL) Irql = KeRaiseIrqlToDpcLevel();

	ExitInfo.all = 	(ULONG32)Frog_Vmx_Read(VM_EXIT_REASON);

	switch (ExitInfo.fields.reason)
	{



	}





	KeLowerIrql(Irql);

}