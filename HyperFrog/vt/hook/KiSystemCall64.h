#pragma once

extern bool g_MsrHookEnableTable[MAX_SYSCALL_INDEX];
extern void* g_MsrHookFunctionTable[MAX_SYSCALL_INDEX];
extern ULONG64 g_origKisystemcall64;
extern PVOID g_KiSystemServiceCopyEnd;