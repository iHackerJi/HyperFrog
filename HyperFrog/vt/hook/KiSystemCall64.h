#pragma once

extern bool g_MsrHookEnableTable[MAX_SYSCALL_INDEX];
extern void* g_MsrHookFunctionTable[MAX_SYSCALL_INDEX];
unsigned long g_MsrHookArgUpCodeTable[MAX_SYSCALL_INDEX];
extern PVOID g_KiSystemServiceCopyEnd;
extern __int64 Frog_getOrigKisystemcall64();
extern __int64 g_origKisystemcall64;
extern __int64 g_KiSaveDebugRegisterState;

extern ULONG64 offset_Kthread_TrapFrame;
extern ULONG64 offset_Kthread_SystemCallNumber;
extern ULONG64 offset_Kthread_FirstArgument;
extern ULONG64 offset_Kthread_ThreadFlags;
extern ULONG64 offset_Kthread_CombinedApcDisable;
extern ULONG64 offset_Kthread_MiscFlags;
extern ULONG64 offset_Kthread_Ucb;
extern ULONG64 offset_Kthread_TebMappedLowVa;
extern ULONG64 offset_Kthread_Teb;