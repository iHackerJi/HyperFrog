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
PKSERVICE_TABLE_DESCRIPTOR g_KeServiceDescriptorTable[NUMBER_SERVICE_TABLES];
__int64 g_KiSaveDebugRegisterState;
__int64 g_KiUmsCallEntry;
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
            {"KeServiceDescriptorTable",(PVOID*)&g_KeServiceDescriptorTable},
            {"KiSaveDebugRegisterState",(PVOID*)&g_KiSaveDebugRegisterState},
            {"KiUmsCallEntry",(PVOID*)&g_KiUmsCallEntry},
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

ULONG64 offset_Kthread_TrapFrame;
ULONG64 offset_Kthread_SystemCallNumber;
ULONG64 offset_Kthread_FirstArgument;
ULONG64 offset_Kthread_ThreadFlags;
ULONG64 offset_Kthread_CombinedApcDisable;
ULONG64 offset_Kthread_MiscFlags;
ULONG64 offset_Kthread_Ucb;
ULONG64 offset_Kthread_TebMappedLowVa;
ULONG64 offset_Kthread_Teb;

static	 SymbolGetTypeOffsetList	g_GetTypeOffsetInfoList[] =
{
    {
        "ntoskrnl.exe",
        {
            {"_KTHREAD","TrapFrame",&offset_Kthread_TrapFrame},
            {"_KTHREAD","SystemCallNumber",&offset_Kthread_SystemCallNumber},
            {"_KTHREAD","FirstArgument",&offset_Kthread_FirstArgument},
            {"_KTHREAD","ThreadFlags",&offset_Kthread_ThreadFlags},
            {"_KTHREAD","CombinedApcDisable",&offset_Kthread_CombinedApcDisable},
            {"_KTHREAD","MiscFlags",&offset_Kthread_MiscFlags},
            {"_KTHREAD","Ucb",&offset_Kthread_Ucb},
            {"_KTHREAD","TebMappedLowVa",&offset_Kthread_TebMappedLowVa},
            {"_KTHREAD","Teb",&offset_Kthread_Teb},
            {Frog_MaxListFlag,Frog_MaxListFlag,0}
        }
    }
};