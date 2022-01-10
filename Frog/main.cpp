#include "public.h"
BOOL WINAPI HandlerRoutine(
    _In_ DWORD dwCtrlType
)
{
    if (CTRL_CLOSE_EVENT == dwCtrlType)
    {
        driver::UnLoadDriver();
    }
    return true;
}

DWORD WINAPI CheckHyperEnable(
    _In_ LPVOID lpParameter
)
{
    while (true)
    {
        if (comm::SendSuccessSignal())
        {
            break;
        }
        Sleep(1000);
    }
    return 0;
}
int main()
{
    bool result = false;
    char	ServiceName[] = "HyperFrog";
    char	DriverName[] = "HyperFrog.sys";
    HANDLE hThread = NULL;
    SetConsoleCtrlHandler(HandlerRoutine, true);
    do 
    {
        if (!driver::LoadDriver(ServiceName, DriverName))	
            break;


        tools::FrogPrintfEx("Driverload Success \r\n");
        if (comm::initComm())
        {
            if (!symbol::InitSymbolFunctionList())
                break;

            if (!symbol::InitSymbolTypeList())
                break;
        }

        result = true;
    } while (false);

    hThread = CreateThread(NULL, 0, CheckHyperEnable, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    tools::FrogPrintfEx("HyperFrog is Init! \r\n");
    system("pause");
    return 0;
}