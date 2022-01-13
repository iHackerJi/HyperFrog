#pragma once

typedef struct _MsrHookTable
{
    char functionName[256];
    PVOID hookFunction;
}MsrHookTable, * pMsrHookTable;

PFN_NtOpenProcess orgNtOpenProcess;
static bool g_MsrHookEnableTable[MAX_SYSCALL_INDEX] = { 0 };
static PVOID g_MsrHookFunctionTable[MAX_SYSCALL_INDEX] = { 0 };

static MsrHookTable g_MsrHookTable[] =
{
    {
        "NtOpenProcess",
        (PVOID)HookNtOpenProcess,
    }
};
