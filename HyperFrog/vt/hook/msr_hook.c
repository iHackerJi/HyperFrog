#include "public.h"

ULONG64 g_orgKisystemcall64 = 0;

void Frog_MsrHookEnable()
{
    g_orgKisystemcall64 = __readmsr(kIa32Lstar);
     __writemsr(kIa32Lstar, (ULONG64)FakeKiSystemCall64);
}

void Frog_MsrHookDisable()
{
    if (g_orgKisystemcall64)
    {
        __writemsr(kIa32Lstar, g_orgKisystemcall64);
    }
}
