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

    Sleep(1000);
    driver::UnLoadDriver();

    system("pause");

    return 0;
}