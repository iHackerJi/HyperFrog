#pragma once

NTSTATUS HookNtOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
);

NTSTATUS HookNtReadFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
);

NTSTATUS HookNtQueryKey(
    HANDLE                KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID                 KeyInformation,
    ULONG                 Length,
    PULONG                ResultLength
);