#include "public.h"

PDRIVER_OBJECT g_pDriverObj = NULL;;
UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
UNICODE_STRING g_SymbolName = RTL_CONSTANT_STRING(SYMBOL_NAME);
bool g_DeviceAndSymbolLinkDelete = false;

ULONG64 Offset_Ethread_TrapFrame = 0;
ULONG64 Offset_Ethread_SystemCallNumber = 0;
ULONG64 Offset_Ethread_FirstArgument = 0;
ULONG64 Offset_Ethread_ThreadFlags = 0;
ULONG64 Offset_Ethread_CombinedApcDisable = 0;
ULONG64 Offset_Ethread_MiscFlags = 0;
ULONG64 Offset_Ethread_Ucb = 0;
ULONG64 Offset_Ethread_TebMappedLowVa = 0;
ULONG64 Offset_Ethread_Teb = 0;

NTSTATUS DispatchCommon(PDEVICE_OBJECT pObject, PIRP pIrp)
{
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchIoctrl(PDEVICE_OBJECT pObject, PIRP pIrp)
{

    ULONG					uIoctrlCode = 0;
    PVOID					pInputBuff = NULL;
    PVOID					pOutputBuff = NULL;

    ULONG					uInputLength = 0;
    ULONG					uOutputLength = 0;
    PIO_STACK_LOCATION		pStack = NULL;
    NTSTATUS				Status = STATUS_SUCCESS;
    ULONG_PTR				Info = 0;


    pInputBuff = pOutputBuff = pIrp->AssociatedIrp.SystemBuffer;

    pStack = IoGetCurrentIrpStackLocation(pIrp);
    uInputLength = pStack->Parameters.DeviceIoControl.InputBufferLength;
    uOutputLength = pStack->Parameters.DeviceIoControl.OutputBufferLength;
    uIoctrlCode = pStack->Parameters.DeviceIoControl.IoControlCode;


    switch (uIoctrlCode)
    {
    case CTL_GetFunListSize:
    {
        InfoOfSizeList InfoOfsize = { 0 };
        InfoOfsize.StructSize = sizeof(g_GetFunctionInfoList);
        InfoOfsize.ListCount = sizeof(g_GetFunctionInfoList) / sizeof(SymbolGetFunctionInfoList);
        memcpy(pOutputBuff, &InfoOfsize, sizeof(InfoOfsize));
        Info = sizeof(InfoOfsize);
        break;
    }
    case CTL_GetFunListInfo:
    {
        memcpy(pOutputBuff, &g_GetFunctionInfoList, sizeof(g_GetFunctionInfoList));
        Info = sizeof(g_GetFunctionInfoList);

        break;
    }
    case CTL_SendFunListInfo:
    {
        PSymbolGetFunctionInfoList		GetFunctionInfoList = (PSymbolGetFunctionInfoList)pInputBuff;
        ULONG	ListCount = sizeof(g_GetFunctionInfoList) / sizeof(SymbolGetFunctionInfoList);

        for (ULONG i = 0; i < ListCount; i++)
        {
            for (ULONG j = 0; j < Symbol_InfoListMax; j++)
            {
                if (strcmp(GetFunctionInfoList[i].InfoList[j].Name, Frog_MaxListFlag) == 0)
                {
                    break;
                }
                *g_GetFunctionInfoList[i].InfoList[j].ReceiveFunction = GetFunctionInfoList[i].InfoList[j].ReceiveFunction;
            }
        }
        break;
    }
    case CTL_GetTypeListSize:
    {
        InfoOfSizeList InfoOfsize = { 0 };
        InfoOfsize.StructSize = sizeof(g_GetTypeOffsetInfoList);
        InfoOfsize.ListCount = sizeof(g_GetTypeOffsetInfoList) / sizeof(SymbolGetTypeOffsetList);
        memcpy(pOutputBuff, &InfoOfsize, sizeof(InfoOfsize));
        Info = sizeof(InfoOfsize);
        break;
    }
    case CTL_GetTypeListInfo:
    {
        memcpy(pOutputBuff, &g_GetTypeOffsetInfoList, sizeof(g_GetTypeOffsetInfoList));
        Info = sizeof(g_GetTypeOffsetInfoList);
        break;
    }
    case CTL_SendTypeListInfo:
    {
        PSymbolGetTypeOffsetList		GetTypeInfoList = (PSymbolGetTypeOffsetList)pInputBuff;
        ULONG	ListCount = sizeof(g_GetTypeOffsetInfoList) / sizeof(SymbolGetTypeOffsetList);
        for (ULONG i = 0; i < ListCount; i++)
        {
            for (ULONG j = 0; j < Symbol_InfoListMax; j++)
            {
                if (strcmp(GetTypeInfoList[i].InfoList[j].ParentName, Frog_MaxListFlag) == 0)
                {
                    break;
                }
                (*g_GetTypeOffsetInfoList[i].InfoList[j].Offset) = (ULONG64)GetTypeInfoList[i].InfoList[j].Offset;
            }
        }
        break;
    }
    case CTL_SymbolIsSuccess:
    {
        CpuId Data = { 0 };
        NTSTATUS Status = STATUS_UNSUCCESSFUL;
        __cpuid((int*)&Data, FrogTag);
        if (Data.eax == FrogTag) {
            //ÒÑ¿ªÆôÐéÄâ»¯
            Status = STATUS_SUCCESS;
            Frog_CallRoutine(g_pDriverObj);
        }
        memcpy(pOutputBuff, &Status, sizeof(Status));
        Info = sizeof(Status);
        break;
    }
    default:
        Frog_PrintfEx("Unknown iocontrol\n");
        break;
    }

    pIrp->IoStatus.Status = Status;
    pIrp->IoStatus.Information = Info;

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return Status;
}


NTSTATUS	InitComm(PDRIVER_OBJECT pDriverObj)
{

    NTSTATUS			Status = STATUS_SUCCESS;
    PDEVICE_OBJECT		pDeviceObject = NULL;
    OBJECT_ATTRIBUTES	 ObjectAttributes = { 0 };

    g_pDriverObj = pDriverObj;
    Status = IoCreateDevice(pDriverObj, 0, &g_DeviceName, FILE_DEVICE_UNKNOWN, 0, false, &pDeviceObject);

    if (!NT_SUCCESS(Status))
    {
        Frog_PrintfEx("IoCreateDevice failed:%x", Status);
        return Status;
    }

    pDeviceObject->Flags |= DO_BUFFERED_IO;

    Status = IoCreateSymbolicLink(&g_SymbolName, &g_DeviceName);
    if (!NT_SUCCESS(Status))
    {
        IoDeleteDevice(pDeviceObject);
        Frog_PrintfEx("IoCreateSymbolicLink failed:%x\n", Status);
        return Status;
    }

    for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
    {
        pDriverObj->MajorFunction[i] = DispatchCommon;
    }

    pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctrl;

    return Status;
}

void CommUnload()
{
    if (g_pDriverObj) IoDeleteDevice(g_pDriverObj->DeviceObject);
    IoDeleteSymbolicLink(&g_SymbolName);
}
