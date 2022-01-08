#include "public.h"


void	tools::FrogPrintfEx(const char* format, ...) {

    char buf[1024] = { 0 };
    va_list args = NULL;
    va_start(args, format);
    vsprintf_s(buf,sizeof(buf) , format,args);
    va_end(args);
    printf(buf);
}