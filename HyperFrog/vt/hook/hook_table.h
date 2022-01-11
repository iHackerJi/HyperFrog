#pragma once

typedef struct _MsrHookTable
{
    char functionName[256];
    PVOID hookFunction;
    PVOID* orgFunctionAddr;
}MsrHookTable, * pMsrHookTable;

PFN_NtOpenProcess orgNtOpenProcess;
static bool g_MsrHookEnableTable[MAX_SYSCALL_INDEX] = { 0 };
DECLSPEC_CACHEALIGN KSERVICE_TABLE_DESCRIPTOR g_KeServiceDescriptorTable[NUMBER_SERVICE_TABLES];
static MsrHookTable g_MsrHookTable[] =
{
    {
        "NtOpenProcess",
        (PVOID)HookNtOpenProcess,
        (PVOID*)&orgNtOpenProcess
    }
};
