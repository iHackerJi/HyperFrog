#pragma once
bool Frog_MsrHookEnable();
bool Frog_MsrHookDisable();
void FakeKiSystemCall64();

bool g_MsrHookEnableTable[MAX_SYSCALL_INDEX];
void* g_MsrHookFunctionTable[MAX_SYSCALL_INDEX];
unsigned long g_MsrHookArgUpCodeTable[MAX_SYSCALL_INDEX];
ULONG64 g_origKisystemcall64;



