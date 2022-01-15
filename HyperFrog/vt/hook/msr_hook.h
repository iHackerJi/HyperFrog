#pragma once
bool  Frog_MsrHookInit();
bool Frog_MsrHookEnable();
bool Frog_MsrHookDisable();
void FakeKiSystemCall64();
__int64 Frog_getOrigKisystemcall64();

bool g_MsrHookEnableTable[MAX_SYSCALL_INDEX];
void* g_MsrHookFunctionTable[MAX_SYSCALL_INDEX];
unsigned long g_MsrHookArgUpCodeTable[MAX_SYSCALL_INDEX];
__int64 g_origKisystemcall64;



