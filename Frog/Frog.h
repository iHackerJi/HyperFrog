#pragma once

typedef NTSTATUS(*PFN_ZwQuerySystemInformation)(
    __in       ULONG SystemInformationClass,
    __inout    PVOID SystemInformation,
    __in       ULONG SystemInformationLength,
    __out_opt  PULONG ReturnLength
    );


namespace symbol
{
    bool	InitSymbolFunctionList();
    bool EnumSymbols(char* ModuleName, EnumSymbolType	Type, PVOID  NeedList);
    bool	InitSymbols(char* SymbolDownloadPath);
    BOOL CALLBACK EnumSymTypeRoutine(
        _In_ PSYMBOL_INFO pSymInfo,
        _In_ ULONG SymbolSize,
        _In_opt_ PVOID UserContext
    );
    BOOL CALLBACK EnumSymFunctionRoutine(
        PSYMBOL_INFO pSymInfo,
        unsigned long SymbolSize,
        PVOID UserContext
    );
    bool	InitSymbolTypeList();
}

namespace comm
{
    bool	initComm();
    bool	SendSuccessSignal();
}

namespace global
{
    extern HANDLE	hFile;
    extern unsigned long listCount;
    extern HANDLE hProcess;
    extern char	CurrentDirName[MAX_PATH];
}

namespace exportFun
{
    extern PFN_ZwQuerySystemInformation	ZwQuerySystemInformation;
}

namespace driver
{
    extern SC_HANDLE hService;
    bool LoadDriver(char* ServiceName, char* DriverName);
    bool UnLoadDriver();
}


#define  SystemModuleInformation 11
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;                 // Not filled in
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;



