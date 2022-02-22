#include "public.h"

void	UnloadDriver(PDRIVER_OBJECT DriverObject) {
    FrogRetCode	Status;
	Status = Frog_DisableHyper();
	CommUnload();
	if (!Frog_SUCCESS(Status))
	{
		FrogBreak();
		FrogPrint("HyperUnload Error");
	}
}

//当VT与符号都加载成功后会调用这个函数
void Frog_CallRoutine(PDRIVER_OBJECT pObj)
{
    FrogPrint("Run CallRoutine");
    for (ULONG i = 0; i < sizeof(g_GetFunctionInfoList) / sizeof(SymbolGetFunctionInfoList); i++)
    {
        for (ULONG j = 0; j < Symbol_InfoListMax; j++)
        {
            if (strcmp(g_GetFunctionInfoList[i].InfoList[j].Name, Frog_MaxListFlag) == 0)
            {
                break;
            }
            if ((*g_GetFunctionInfoList[i].InfoList[j].ReceiveFunction) == NULL)
            {
                FrogBreak();
                FrogPrint("Symbol Do not Get %s", g_GetFunctionInfoList[i].InfoList[j].Name);
                return;
            }
        }
    }

    Frog_Init();
	Frog_Hook();
}

NTSTATUS	DriverEntry(PDRIVER_OBJECT	pDriverObj,PUNICODE_STRING	pReg) 
{
    FrogPrint("Start~");
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
    FrogPrint("InitComm Success~");

    //申请 ForgVmxRegion
    if (!Forg_AllocateForgVmxRegion()) {
        FrogBreak();
        FrogPrint("ForgAllocatePool Error");
        return STATUS_UNSUCCESSFUL;
    }

    g_FrogCpu->EnableEpt = true;
    g_FrogCpu->EnableHookMsr = false;
    g_FrogCpu->EnableHookEfer = true;

	fStatus = Frog_EnableHyper();

	return	STATUS_SUCCESS;
}