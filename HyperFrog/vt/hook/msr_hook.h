#pragma once
bool Frog_MsrHookEnable();
void Frog_MsrHookDisable();
void FakeKiSystemCall64();

NTSTATUS HookNtOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
);


extern PFN_NtOpenProcess orgNtOpenProcess;

typedef struct _MsrHookTable
{
    char functionName[256];
    PVOID hookFunction;
    PVOID* orgFunctionAddr;
    ULONG Index;
}MsrHookTable, *pMsrHookTable;

static	 MsrHookTable	g_MsrHookTable[] =
{
    {
        "NtOpenProcess",
        (PVOID)HookNtOpenProcess,
        (PVOID*)&orgNtOpenProcess
    }
};
