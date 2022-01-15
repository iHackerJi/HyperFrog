#include "public.h"

NTSTATUS HookNtOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
)
{
    FrogPrint("HookNtOpenProcess");
    return NtOpenProcess
    (
        ProcessHandle,
        DesiredAccess,
        ObjectAttributes,
        ClientId
    );
}

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
)
{
    FrogPrint("NtReadFile");
    return NtReadFile
    (
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        Buffer,
        Length,
        ByteOffset,
        Key
    );
}

NTSTATUS HookNtQueryKey(
    HANDLE                KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID                 KeyInformation,
    ULONG                 Length,
    PULONG                ResultLength
)
{
    FrogPrint("ZwQueryKey");
    return ZwQueryKey
    (
        KeyHandle,
        KeyInformationClass,
        KeyInformation,
        Length,
        ResultLength
    );
}