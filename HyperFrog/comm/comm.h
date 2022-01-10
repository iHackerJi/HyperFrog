#pragma once

NTSTATUS	InitComm(PDRIVER_OBJECT pDriverObj);
void CommUnload();

typedef void	(*ObKillProcessType)(
    PEPROCESS Process
    );

PVOID Pfn_NtMapUserPhysicalPagesScatter;
PVOID Pfn_NtCallbackReturn;
PVOID Pfn_NtSuspendThread;
PVOID Pfn_IopInvalidDeviceRequest;
PVOID Pfn_NtUserGetThreadState;
PVOID Pfn_NtUserPeekMessage;
ObKillProcessType		NONO_ObKillProcess;


//���֧�� Symbol_InfoListMax ����ȡ����Ϣ

//����б����˿��Ի�ȡ����֮�⻹���Ի�ȡȫ�ֱ���
static	SymbolGetFunctionInfoList	g_GetFunctionInfoList[] =
{
    {
        "ntoskrnl.exe",
        {
            {"NtMapUserPhysicalPagesScatter",&Pfn_NtMapUserPhysicalPagesScatter},
            {"NtCallbackReturn",&Pfn_NtCallbackReturn},
            {"NtSuspendThread",&Pfn_NtSuspendThread},
            {"IopInvalidDeviceRequest",&Pfn_IopInvalidDeviceRequest},
            {"ObKillProcess",(PVOID*)&NONO_ObKillProcess},
            {Symbol_MaxListFlag,0}
        }
    },
    {
        "win32k.sys",
        {
            {"NtUserGetThreadState",&Pfn_NtUserGetThreadState},
            {"NtUserPeekMessage",&Pfn_NtUserPeekMessage},
            {Symbol_MaxListFlag,0}
        }
    }
};


ULONG64	Offset_Ethread_CreateTime;
ULONG64	Offset_Ethread_ThreadLock;
ULONG64	Offset_Ethread_RundownProtect;

static	 SymbolGetTypeOffsetList	g_GetTypeOffsetInfoList[] =
{
    {
        "ntoskrnl.exe",
        {
            {"_ETHREAD","CreateTime",&Offset_Ethread_CreateTime},
            {"_ETHREAD","ThreadLock",&Offset_Ethread_ThreadLock},
            {"_ETHREAD","RundownProtect",&Offset_Ethread_RundownProtect},
            {Symbol_MaxListFlag,Symbol_MaxListFlag,0}
        }
    }
};