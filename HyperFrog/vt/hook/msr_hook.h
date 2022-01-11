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


