#include "public.h"

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
}

namespace global
{
    HANDLE	hFile;
    unsigned long listCount;
    HANDLE hProcess;
    char	CurrentDirName[MAX_PATH];
}

namespace exportFun 
{
    PFN_ZwQuerySystemInformation	ZwQuerySystemInformation;
}

namespace driver
{
    SC_HANDLE hService;
    bool LoadDriver(char* ServiceName, char* DriverName);
    bool UnLoadDriver();
}

bool	comm::initComm()
{
    global::hFile = CreateFileA(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (global::hFile == INVALID_HANDLE_VALUE)
    {
        tools::FrogPrintfEx("%s CreateFileA Error %d \r\n", __FUNCTION__, GetLastError());
        return	false;
    }
    return true;
}

bool	comm::SendSuccessSignal()
{
    DWORD outLeng = 0;
    NTSTATUS Status;
    if (DeviceIoControl(global::hFile, CTL_SymbolIsSuccess, NULL, 0, &Status, sizeof(Status), &outLeng, NULL))
    {
        if (Status==STATUS_SUCCESS)
        {
            return true;
        }
    }
    return false;
}

BOOL CALLBACK symbol::EnumSymFunctionRoutine(
    PSYMBOL_INFO pSymInfo,
    unsigned long SymbolSize,
    PVOID UserContext
) {
    PSymbolGetFunction		Info = (PSymbolGetFunction)UserContext;

    unsigned long					ListNumber = 0;
    for (unsigned long i = 0; i < global::listCount; i++)
    {

        if (strcmp(pSymInfo->Name, Info[i].Name) == 0)
        {
            Info[i].ReceiveFunction = (PVOID*)pSymInfo->Address;
            tools::FrogPrintfEx("解析到 %s %p \r\n ", pSymInfo->Name, (PVOID)pSymInfo->Address);
        }
    }

    return	true;
}


BOOL CALLBACK symbol::EnumSymTypeRoutine(
    _In_ PSYMBOL_INFO pSymInfo,
    _In_ ULONG SymbolSize,
    _In_opt_ PVOID UserContext
)
{

    PSymbolGetTypeOffset Info = (PSymbolGetTypeOffset)UserContext;
    bool IsFlags = false;

    for (unsigned long K = 0; K < global::listCount; K++)
    {
        if (strcmp(pSymInfo->Name, Info[K].ParentName) == 0)
        {
            IsFlags = true;
        }
    }

    if (IsFlags == false)	return true;

    PVOID						ModuleBase = (PVOID)pSymInfo->ModBase;
    WCHAR						SonName[Symbol_NameLength] = { 0 };

    for (unsigned long K = 0; K < global::listCount; K++)
    {

        if (strcmp(pSymInfo->Name, Info[K].ParentName) == 0)
        {
            TI_FINDCHILDREN_PARAMS* SonList = NULL;

            unsigned long SonListSize = 0;
            unsigned long SonCount = 0;
            bool result = true;
            wchar_t* TempName = NULL;
            unsigned long long Offset = 0;
            do 
            {
                result = SymGetTypeInfo(global::hProcess, (unsigned long long)ModuleBase, pSymInfo->Index, TI_GET_CHILDRENCOUNT, &SonCount);
                if (!result)
                {
                    tools::FrogPrintfEx("SymGetTypeInfo Erro =%d \r\n", GetLastError());
                    break;
                }
                SonListSize = sizeof(TI_FINDCHILDREN_PARAMS) + sizeof(unsigned long) * SonCount;
                SonList = (TI_FINDCHILDREN_PARAMS*)malloc(SonListSize);
                ZeroMemory(SonList, SonListSize);
                SonList->Count = SonCount;	//一定要设置数量，否则拿不到

                result = SymGetTypeInfo(global::hProcess, (unsigned long long)ModuleBase, pSymInfo->Index, TI_FINDCHILDREN, SonList);
                if (!result)
                {
                    tools::FrogPrintfEx("SymGetTypeInfo Erro =%d \r\n", GetLastError());
                    break;
                }

                for (unsigned long i = 0; i < SonCount; i++)
                {
                    swprintf(SonName, Symbol_NameLength, L"%hs", Info[K].SonName);
                    SymGetTypeInfo(global::hProcess, (unsigned long long)ModuleBase, SonList->ChildId[i], TI_GET_SYMNAME, &TempName);

                    if (wcscmp(TempName, SonName) == 0)
                    {
                        result = SymGetTypeInfo(global::hProcess, (unsigned long long)ModuleBase, SonList->ChildId[i], TI_GET_OFFSET, &Offset);
                        if (!result)
                        {
                            tools::FrogPrintfEx("SymGetTypeInfo Erro =%d \r\n", GetLastError());
                            VirtualFree(TempName, 0, MEM_RELEASE);
                            break;
                        }
                        Info[K].Offset = (unsigned long long*)Offset;
                        tools::FrogPrintfEx("解析到 结构 %s %s %x \r\n", Info[K].ParentName, Info[K].SonName, (UINT)Offset);
                    }
                    VirtualFree(TempName, 0, MEM_RELEASE);
                }
            } while (false);
            if (SonList)	free(SonList);
        }
    }
    return true;
}


bool tools::EnableDebugPriv(void)
{
    HANDLE hToken;

    LUID sedebugnameValue;

    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(global::hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return false;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
    {
        CloseHandle(hToken);

        return false;
    }
    tkp.PrivilegeCount = 1;

    tkp.Privileges[0].Luid = sedebugnameValue;

    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL))
    {
        CloseHandle(hToken);

        return false;
    }
    return true;
}

bool	symbol::InitSymbols(char* SymbolDownloadPath)
{
    char	SymbolPath[MAX_PATH] = { 0 };
    int		result = 0;
    char	SymsrvYesName[MAX_PATH] = { 0 };


    global::hProcess = GetCurrentProcess();

    //提升调试权限
    if (!tools::EnableDebugPriv())
    {
        tools::FrogPrintfEx("%s EnableDebugPriv Error %d \r\n", __FUNCTION__, GetLastError());
        return	false;
    }


    //设置调试选项
    SymSetOptions(SYMOPT_CASE_INSENSITIVE | SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);

    //清除调试句柄
    SymCleanup(global::hProcess);

    if (-1 == sprintf_s(SymbolPath,sizeof(SymbolPath), "SRV*%s*http://msdl.microsoft.com/download/symbols", SymbolDownloadPath))
    {
        tools::FrogPrintfEx("%s sprintf Error %d \r\n", __FUNCTION__, GetLastError());
        return	false;
    }

    if (!SymInitialize(global::hProcess, SymbolPath, false))
    {
        tools::FrogPrintfEx("%s SymInitialize Error %d \r\n", __FUNCTION__, GetLastError());
        return	false;
    }


    //创建这个文件是为了防止提示一个对话框

    if (-1 == sprintf_s(SymsrvYesName,sizeof(SymsrvYesName), "%s\\symsrv.yes", global::CurrentDirName))
    {
        tools::FrogPrintfEx("%s sprintf Error %d \r\n", __FUNCTION__, GetLastError());
        return false;
    }

    if (!PathFileExistsA(SymsrvYesName))
    {
        if (INVALID_HANDLE_VALUE == CreateFileA(SymsrvYesName, FILE_ALL_ACCESS, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL))
        {
            tools::FrogPrintfEx("%s CreateFileA Error %d \r\n", __FUNCTION__, GetLastError());
            return	false;
        }
    }
    return	 true;
}

bool symbol::EnumSymbols(char* ModuleName, EnumSymbolType	Type, PVOID  NeedList)
{

    char SymFileName[MAX_PATH] = { 0 };
    char ModuleNamePath[MAX_PATH] = { 0 };

    char SystemDir[MAX_PATH] = { 0 };
    char SymbolPath[MAX_PATH] = { 0 };
    char Symbol[MAX_PATH] = SYMBOL_NAME;

    PRTL_PROCESS_MODULES	pModule = NULL;
    bool result;
    unsigned long resultLeng = 0;
    NTSTATUS Status = STATUS_SUCCESS;

    PVOID ModuleBase = NULL;
    unsigned long ModuleSize = 0;
    PLOADED_IMAGE	 pImage = NULL;

    //取出系统模块地址
    if (!GetSystemDirectoryA(SystemDir, MAX_PATH))
    {
        tools::FrogPrintfEx("%s GetSystemDirectoryA Error %d \r\n", __FUNCTION__, GetLastError());
        return false;
    }

    if (-1 == sprintf_s(ModuleNamePath, sizeof(ModuleNamePath),"%s\\%s", SystemDir, ModuleName))
    {
        tools::FrogPrintfEx("%s sprintf Error %d \r\n", __FUNCTION__, GetLastError());
        return false;
    }

    if (-1 == sprintf_s(SymbolPath, sizeof(SymbolPath),"%s\\%s", global::CurrentDirName, Symbol))
    {
        tools::FrogPrintfEx("%s sprintf Error %d \r\n", __FUNCTION__, GetLastError());
        return false;
    }

    //初始化符号路径
    if (!InitSymbols(SymbolPath))
    {
        return false;
    }

    if (!PathFileExistsA(ModuleNamePath))
    {
        tools::FrogPrintfEx("%s PathFileExistsA Error %d \r\n", __FUNCTION__, GetLastError());
        return false;
    }

    //下载符号文件
    if (!SymGetSymbolFile(global::hProcess, NULL, ModuleNamePath, sfPdb, SymFileName, MAX_PATH, SymFileName, MAX_PATH))
    {
        tools::FrogPrintfEx("%s SymGetSymbolFile Error %d \r\n", __FUNCTION__, GetLastError());
        return false;
    }

    exportFun::ZwQuerySystemInformation = (PFN_ZwQuerySystemInformation)GetProcAddress(LoadLibraryA("ntdll.dll"), "ZwQuerySystemInformation");
    if (exportFun::ZwQuerySystemInformation == NULL)
    {
        tools::FrogPrintfEx("%s GetZwQuerySystemInformation Error %d \r\n", __FUNCTION__, GetLastError());
        return false;
    }

    //取出系统模块的地址
    Status = exportFun::ZwQuerySystemInformation(SystemModuleInformation, pModule, 0, &resultLeng);
    if (Status != STATUS_INFO_LENGTH_MISMATCH)
    {
        tools::FrogPrintfEx("%s ZwQuerySystemInformation Error %d \r\n", __FUNCTION__, GetLastError());
        return false;
    }

    pModule = (PRTL_PROCESS_MODULES)malloc(resultLeng);
    memset(pModule, 0, resultLeng);
    Status = exportFun::ZwQuerySystemInformation(SystemModuleInformation, pModule, resultLeng, &resultLeng);
    if (Status != STATUS_SUCCESS)
    {
        tools::FrogPrintfEx("%s ZwQuerySystemInformation Error %d \r\n", __FUNCTION__, GetLastError());
        goto _Exit;
    }

    for (unsigned long i = 0; i < pModule->NumberOfModules; i++)
    {
        //循环从链表对比
        if (strstr((char*)pModule->Modules[i].FullPathName, ModuleName))
        {
            ModuleBase = pModule->Modules[i].ImageBase;
            ModuleSize = pModule->Modules[i].ImageSize;
            break;
        }
    }

    if (ModuleBase == NULL && ModuleSize == 0)
    {
        tools::FrogPrintfEx("%s GetModule Error %d \r\n", __FUNCTION__, GetLastError());
        goto _Exit;
    }


    pImage = ImageLoad(ModuleNamePath, NULL);
    if (pImage == NULL)
    {
        tools::FrogPrintfEx("%s ImageLoad Error %d \r\n", __FUNCTION__, GetLastError());
        goto _Exit;
    }


    //加载符号并解析
    if (!SymLoadModule64(global::hProcess, pImage->hFile, pImage->ModuleName, NULL, (unsigned long long)ModuleBase, ModuleSize))
    {
        tools::FrogPrintfEx("%s SymLoadModule64 Error %d \r\n", __FUNCTION__, GetLastError());
        goto _Exit;
    }

    //枚举符号

    switch (Type)
    {
    case Symbol_Function:
    {
        PSymbolGetFunction		Info = (PSymbolGetFunction)NeedList;
        global::listCount = 0;
        for (int i = 0; i < Symbol_InfoListMax; i++)
        {
            if (strcmp(Info[i].Name, Symbol_MaxListFlag) == 0)
            {
                global::listCount = i;
                break;
            }
        }

        if (!SymEnumSymbols(global::hProcess, (unsigned long long)ModuleBase, NULL, EnumSymFunctionRoutine, NeedList))
        {
            tools::FrogPrintfEx("%s SymEnumSymbols Error %d \r\n", __FUNCTION__, GetLastError());
            goto _Exit;
        }
        break;
    }
    case Symbol_Type:
    {
        PSymbolGetTypeOffset		Info = (PSymbolGetTypeOffset)NeedList;
        global::listCount = 0;
        for (int i = 0; i < Symbol_InfoListMax; i++)
        {
            if (strcmp(Info[i].ParentName, Symbol_MaxListFlag) == 0)
            {
                global::listCount = i;
                break;
            }
        }
        SymEnumTypes(global::hProcess, (unsigned long long)ModuleBase, EnumSymTypeRoutine, NeedList);
        break;
    }
    default:	goto _Exit;
    }

    result = true;

_Exit:
    if (pModule)	free(pModule);
    if (pImage)	ImageUnload(pImage);

    return result;
}

bool	symbol::InitSymbolFunctionList()
{
    unsigned long outLeng = 0;
    InfoOfSizeList InfoOfSize = { 0 };
    PSymbolGetFunctionInfoList pfunInfo = NULL;
    bool result = false;

    do 
    {
        if (!DeviceIoControl(global::hFile, CTL_GetFunListSize, NULL, 0, &InfoOfSize, sizeof(InfoOfSize), &outLeng, NULL))
        {
            tools::FrogPrintfEx("%s DeviceIoControl CTL_GetFunListSize Error %d \r\n", __FUNCTION__, GetLastError());
            break;
        }
        pfunInfo = (PSymbolGetFunctionInfoList)malloc(InfoOfSize.StructSize);

        if (!pfunInfo)
        {
            tools::FrogPrintfEx("%s malloc  FunInfo Error  \r\n", __FUNCTION__);
            break;
        }

        if (!DeviceIoControl(global::hFile, CTL_GetFunListInfo, NULL, 0, pfunInfo, InfoOfSize.StructSize, &outLeng, NULL))
        {
            tools::FrogPrintfEx("%s DeviceIoControl  CTL_GetFunListInfo Error %d \r\n", __FUNCTION__, GetLastError());
            break;
        }

        tools::FrogPrintfEx("准备解析符号表\r\n");
        for (unsigned long i = 0; i < InfoOfSize.ListCount; i++)
        {
            if (!EnumSymbols(pfunInfo[i].ModuleName, Symbol_Function, pfunInfo[i].InfoList))
            {
                tools::FrogPrintfEx("%s EnumSymbols Error %d \r\n", __FUNCTION__, GetLastError());
                break;
            }

        }

        if (!DeviceIoControl(global::hFile, CTL_SendFunListInfo, pfunInfo, InfoOfSize.StructSize, NULL, 0, &outLeng, NULL))
        {
            tools::FrogPrintfEx("%s DeviceIoControl  CTL_GetFunListInfo Error %d \r\n", __FUNCTION__, GetLastError());
            break;
        }
        result = true;
    } while (false);

    if (pfunInfo) free(pfunInfo);

    return result;
}

bool	symbol::InitSymbolTypeList()
{
    unsigned long outLeng = 0;
    InfoOfSizeList InfoOfSize = { 0 };
    PSymbolGetTypeOffsetList pTypeinfo = NULL;
    bool result = false;

    do 
    {
        if (!DeviceIoControl(global::hFile, CTL_GetTypeListSize, NULL, 0, &InfoOfSize, sizeof(InfoOfSize), &outLeng, NULL))
        {
            tools::FrogPrintfEx("%s DeviceIoControl CTL_GetFunListSize Error %d \r\n", __FUNCTION__, GetLastError());
           break;
        }
        pTypeinfo = (PSymbolGetTypeOffsetList)malloc(InfoOfSize.StructSize);
        if (!pTypeinfo)
        {
            tools::FrogPrintfEx("%s malloc  FunInfo Error  \r\n", __FUNCTION__);
            break;
        }

        if (!DeviceIoControl(global::hFile, CTL_GetTypeListInfo, NULL, 0, pTypeinfo, InfoOfSize.StructSize, &outLeng, NULL))
        {
            tools::FrogPrintfEx("%s DeviceIoControl  CTL_GetFunListInfo Error %d \r\n", __FUNCTION__, GetLastError());
            break;
        }


        tools::FrogPrintfEx("准备解析符号表\r\n");
        for (ULONG i = 0; i < InfoOfSize.ListCount; i++)
        {
            if (!symbol::EnumSymbols(pTypeinfo[i].ModuleName, Symbol_Type, pTypeinfo[i].InfoList))
            {
                printf("%s EnumSymbols Error %d \r\n", __FUNCTION__, GetLastError());
                break;
            }

        }
        if (!DeviceIoControl(global::hFile, CTL_SendTypeListInfo, pTypeinfo, InfoOfSize.StructSize, NULL, 0, &outLeng, NULL))
        {
            tools::FrogPrintfEx("%s DeviceIoControl  CTL_GetFunListInfo Error %d \r\n", __FUNCTION__, GetLastError());
            break;
        }
        result = true;

    } while (false);

    if (pTypeinfo) free(pTypeinfo);

    return result;
}

bool	driver::LoadDriver(char* ServiceName, char* DriverName)
{
    bool result = false;
    SC_HANDLE hSCManager = NULL;
    char	DriverPath[MAX_PATH] = { 0 };

    if (0 == GetCurrentDirectoryA(MAX_PATH, global::CurrentDirName))
    {
        tools::FrogPrintfEx("%s GetCurrentDirectoryA Error %d \r\n", __FUNCTION__, GetLastError());
        return	FALSE;
    }

    if (-1 == sprintf_s(DriverPath,sizeof(DriverPath), "%s\\%s", global::CurrentDirName, DriverName))
    {
        tools::FrogPrintfEx("%s sprintf Error %d \r\n", __FUNCTION__, GetLastError());
        return FALSE;
    }
    do 
    {
        hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (hSCManager)
        {
            hService = CreateServiceA(
                hSCManager, 
                ServiceName,
                ServiceName, 
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER, 
                SERVICE_DEMAND_START,
                SERVICE_ERROR_IGNORE,
                DriverPath,
                NULL, NULL, NULL, NULL, NULL
            ); 
            if (!hService)
            {
                hService = OpenServiceA(hSCManager, ServiceName, SERVICE_ALL_ACCESS);
                if (!hService)
                {
                    CloseServiceHandle(hSCManager);
                    tools::FrogPrintfEx("CloseServiceHandle Error = %d", GetLastError());
                    break;
                }
            }

            if (!StartServiceA(hService, 0, NULL))
            {
                tools::FrogPrintfEx("%s StartServiceA Error %d \r\n", __FUNCTION__, GetLastError());
                break;
            }
            result = true;
        }

    } while (false);

    if (hSCManager)	CloseServiceHandle(hSCManager);

    return result;
}

bool	driver::UnLoadDriver() {

    SERVICE_STATUS ServiceStatus = { 0 };
    if (!ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus))
    {
        tools::FrogPrintfEx("%s ControlService Error %d \r\n", __FUNCTION__, GetLastError());
        return	false;
    }
    if (!DeleteService(hService))
    {
        tools::FrogPrintfEx("%s DeleteService Error %d \r\n", __FUNCTION__, GetLastError());
        return	false;
    }
    if (hService)	        CloseServiceHandle(hService);

    tools::FrogPrintfEx("DriverUnload Success \r\n");
    return true;

}