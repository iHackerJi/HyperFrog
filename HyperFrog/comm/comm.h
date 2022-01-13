#pragma once

NTSTATUS	InitComm(PDRIVER_OBJECT pDriverObj);
void CommUnload();


PVOID Pfn_NtMapUserPhysicalPagesScatter;
PVOID Pfn_NtCallbackReturn;
PVOID Pfn_NtSuspendThread;
PVOID Pfn_IopInvalidDeviceRequest;
PVOID Pfn_NtUserGetThreadState;
PVOID Pfn_NtUserPeekMessage;
ObKillProcessType Pfn_ObKillProcess;
PVOID g_KiSystemServiceCopyEnd;

//最多支持 Symbol_InfoListMax 个获取的信息

//这个列表除了可以获取函数之外还可以获取全局变量
static	SymbolGetFunctionInfoList	g_GetFunctionInfoList[] =
{
    {
        "ntoskrnl.exe",
        {
            {"NtMapUserPhysicalPagesScatter",&Pfn_NtMapUserPhysicalPagesScatter},
            {"NtCallbackReturn",&Pfn_NtCallbackReturn},
            {"NtSuspendThread",&Pfn_NtSuspendThread},
            {"IopInvalidDeviceRequest",&Pfn_IopInvalidDeviceRequest},
            {"ObKillProcess",(PVOID*)&Pfn_ObKillProcess},
            {"KiSystemServiceCopyEnd",(PVOID*)&g_KiSystemServiceCopyEnd},
            {Frog_MaxListFlag,0}
        }
    },
    {
        "win32k.sys",
        {
            {"NtUserGetThreadState",&Pfn_NtUserGetThreadState},
            {"NtUserPeekMessage",&Pfn_NtUserPeekMessage},
            {Frog_MaxListFlag,0}
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
            {Frog_MaxListFlag,Frog_MaxListFlag,0}
        }
    }
};