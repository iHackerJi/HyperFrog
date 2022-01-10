#include "public.h"

ULONG64 g_orgKisystemcall64 = 0;

void Frog_MsrHookEnable()
{
    g_orgKisystemcall64 = __readmsr(kIa32Lstar);
     __writemsr(kIa32Lstar, (ULONG64)FakeKiSystemCall64);

     UNICODE_STRING uFileName = {0};
     HANDLE hFileHandle = NULL;
     OBJECT_ATTRIBUTES ObjectAttributes = {0};
     IO_STATUS_BLOCK IoStatusBlock = {0};
     NTSTATUS nStatus = NULL;
     char* pNtdll = NULL;
     ULONG NtdllSize = 0;

     RtlInitUnicodeString(&uFileName, L"\\SystemRoot\\system32\\ntdll.dll");
     InitializeObjectAttributes(&ObjectAttributes, &uFileName,
         OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
         NULL, NULL);

     nStatus = ZwCreateFile(&hFileHandle,
         GENERIC_READ,
         &ObjectAttributes,
         &IoStatusBlock, NULL,
         FILE_ATTRIBUTE_NORMAL,
         FILE_SHARE_READ,
         FILE_OPEN,
         FILE_SYNCHRONOUS_IO_NONALERT,
         NULL, 0);
     if (NT_SUCCESS(nStatus))
     {
         FILE_STANDARD_INFORMATION StandardInformation = { 0 };
         nStatus = ZwQueryInformationFile(hFileHandle, &IoStatusBlock, &StandardInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
         if (NT_SUCCESS(nStatus))
         {
             NtdllSize = StandardInformation.EndOfFile.LowPart;
             pNtdll = FrogExAllocatePool(NtdllSize);

             LARGE_INTEGER ByteOffset;
             ByteOffset.LowPart = ByteOffset.HighPart = 0;
             nStatus = ZwReadFile(
                 hFileHandle,
                 NULL, NULL, NULL,
                 &IoStatusBlock,
                 pNtdll,
                 NtdllSize,
                 &ByteOffset, NULL);

             if (!NT_SUCCESS(nStatus))
             {
                 FrogExFreePool(pNtdll);
             }
         }
     }



}

void Frog_MsrHookDisable()
{
    if (g_orgKisystemcall64)
    {
        __writemsr(kIa32Lstar, g_orgKisystemcall64);
    }
}

NTSTATUS HookNtOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
)
{


    //return orgNtOpenProcess
    //(
    //    ProcessHandle,
    //    DesiredAccess,
    //    ObjectAttributes,
    //    ClientId
    //);
}

