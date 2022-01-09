#include "public.h"

int main()
{
    bool result = false;
    char	ServiceName[] = "HyperFrog";
    char	DriverName[] = "HyperFrog.sys";

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
    SERVICE_STATUS ServiceStatus = { 0 };
    if (global::hFile)	CloseHandle(global::hFile);
    if (driver::hService) 
    {
        if (!ControlService(driver::hService, SERVICE_CONTROL_STOP, &ServiceStatus))
        {
            tools::FrogPrintfEx("%s ControlService Error %d \r\n", __FUNCTION__, GetLastError());
        }
        DeleteService(driver::hService);
        CloseServiceHandle(driver::hService);
    }
   
    system("pause");

    return 0;
}