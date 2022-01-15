#pragma once

extern bool g_MsrHookEnableTable[MAX_SYSCALL_INDEX];
extern void* g_MsrHookFunctionTable[MAX_SYSCALL_INDEX];
unsigned long g_MsrHookArgUpCodeTable[MAX_SYSCALL_INDEX];
extern PVOID g_KiSystemServiceCopyEnd;
extern __int64 Frog_getOrigKisystemcall64();
extern __int64 g_origKisystemcall64;
