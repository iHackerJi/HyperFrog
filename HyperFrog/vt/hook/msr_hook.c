#include "public.h"
ULONG64 g_origKisystemcall64 = 0;
bool g_MsrHookEnableTable[MAX_SYSCALL_INDEX];
unsigned long g_MsrHookArgUpCodeTable[MAX_SYSCALL_INDEX];
void* g_MsrHookFunctionTable[MAX_SYSCALL_INDEX];


int Frog_SearchIndex(unsigned char* ExportData)
{
    for (int i = 0; i < 32 ; i++)
    {
        if (ExportData[i] == 0xC2 || ExportData[i] == 0xC3)  //RET
            break;

        if (ExportData[i] == 0xB8)  //mov eax,X
        {
            int index = *(int*)(ExportData + i + 1);
            if (index > MAX_SYSCALL_INDEX)
            {
                FrogBreak();
                FrogPrint("Hook的函数不在SSDT");
                break;
            }
            return index;
            break;
        }
    }
    return 0;
}

unsigned char Frog_GetFunctionArgCount(int index)
{
    return ((*g_KeServiceDescriptorTable)[0].Base[index] & 0xf) * 8;
}

void Frog_InitMsrHookTable(char * pNtdll, ULONG NtdllSize)
{
    PIMAGE_DOS_HEADER  pDos = (PIMAGE_DOS_HEADER)pNtdll;
    PIMAGE_NT_HEADERS64  pNts = (PIMAGE_NT_HEADERS)((char*)pDos + pDos->e_lfanew);
    PIMAGE_DATA_DIRECTORY  pDataDir = pNts->OptionalHeader.DataDirectory;
    ULONG ExportDirRva = pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ULONG ExportDirSize = pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    ULONG ExportDirOffset = RvaToOffset(pNts, ExportDirRva, NtdllSize);

    PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)(pNtdll + ExportDirOffset);
    ULONG NumberOfNames = ExportDir->NumberOfNames;
    ULONG AddressOfFunctionsOffset = RvaToOffset(pNts, ExportDir->AddressOfFunctions, NtdllSize);
    ULONG AddressOfNameOrdinalsOffset = RvaToOffset(pNts, ExportDir->AddressOfNameOrdinals, NtdllSize);
    ULONG AddressOfNamesOffset = RvaToOffset(pNts, ExportDir->AddressOfNames, NtdllSize);

    ULONG* AddressOfFunctions = (ULONG*)(pNtdll + AddressOfFunctionsOffset);
    USHORT* AddressOfNameOrdinals = (USHORT*)(pNtdll + AddressOfNameOrdinalsOffset);
    ULONG* AddressOfNames = (ULONG*)(pNtdll + AddressOfNamesOffset);

    for (ULONG i = 0; i < NumberOfNames; i++)
    {
        ULONG CurrentNameOffset = RvaToOffset(pNts, AddressOfNames[i], NtdllSize);
        if (CurrentNameOffset == 0)
            continue;
        const char* CurrentName = (const char*)((char*)pDos + CurrentNameOffset);
        ULONG CurrentFunctionRva = AddressOfFunctions[AddressOfNameOrdinals[i]];
        if (CurrentFunctionRva >= ExportDirRva && CurrentFunctionRva < ExportDirRva + ExportDirSize)
            continue; //we ignore forwarded exports

        for (int j = 0 ; j < sizeof(g_MsrHookTable) / sizeof(MsrHookTable) ; j++)
        {
            if (strcmp(CurrentName, g_MsrHookTable[j].functionName) == 0)  //compare the export name to the requested export
            {
                ULONG  ExportOffset = RvaToOffset(pNts, CurrentFunctionRva, NtdllSize);
                unsigned char* ExportData = ExportOffset + pNtdll;
                int index = Frog_SearchIndex(ExportData);
                if (index != 0)
                {
                    InterlockedExchange8(&g_MsrHookEnableTable[index], true);
                    InterlockedExchange(&g_MsrHookArgUpCodeTable[index], Frog_GetFunctionArgCount(index));
                    InterlockedExchange64((PLONG64)&g_MsrHookFunctionTable[index], (LONG64)g_MsrHookTable[j].hookFunction);
                }
            }
        }
    }
}

bool  Frog_MsrHookEnable()
{
     UNICODE_STRING uFileName = {0};
     HANDLE hFileHandle = NULL;
     OBJECT_ATTRIBUTES ObjectAttributes = {0};
     IO_STATUS_BLOCK IoStatusBlock = {0};
     NTSTATUS nStatus = STATUS_SUCCESS;
     char* pNtdll = NULL;
     ULONG NtdllSize = 0;
     bool result = false;

     RtlInitUnicodeString(&uFileName, L"\\SystemRoot\\system32\\ntdll.dll");
     InitializeObjectAttributes(&ObjectAttributes, &uFileName,
         OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
         NULL, NULL);

     do 
     {
         nStatus = ZwCreateFile(&hFileHandle,
             GENERIC_READ,
             &ObjectAttributes,
             &IoStatusBlock, NULL,
             FILE_ATTRIBUTE_NORMAL,
             FILE_SHARE_READ,
             FILE_OPEN,
             FILE_SYNCHRONOUS_IO_NONALERT,
             NULL, 0);

         if (!NT_SUCCESS(nStatus))  break;

         FILE_STANDARD_INFORMATION StandardInformation = { 0 };
         nStatus = ZwQueryInformationFile(hFileHandle, &IoStatusBlock, &StandardInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
         if (!NT_SUCCESS(nStatus))  break;

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

         if (!NT_SUCCESS(nStatus))       break;
         Frog_InitMsrHookTable(pNtdll, NtdllSize);
         result = true;
     } while (false);

     g_origKisystemcall64 = __readmsr(kIa32Lstar);
     __writemsr(kIa32Lstar, (ULONG64)FakeKiSystemCall64);

     if (pNtdll)    FrogExFreePool(pNtdll);
     return result;

}

bool Frog_MsrHookDisable()
{
    KIRQL kIrql=0;
    bool result = false;
    kIrql = KeRaiseIrqlToDpcLevel();
    if (g_origKisystemcall64)
    {
        __writemsr(kIa32Lstar, g_origKisystemcall64);
        result = true;
        goto _Exit;
    }
_Exit:
    KeLowerIrql(kIrql);
    return result;
}

