#pragma once
#include <ntifs.h>
#include <vadefs.h>
#include <stdarg.h>
#include <ntstrsafe.h>
#include <intrin.h>

#define Frog_MaxListFlag		"_MaxList"


#include "ExportFunction.h"
#include "tools.h"
#include "ia32.h"
#include "vt_asm.h"
#include "vt.h"
#include "vt_help.h"
#include "SymbolShare.h"
#include "comm.h"
#include "msr_hook.h"

extern	pFrogCpu g_FrogCpu;
extern ULONG64 g_orgKisystemcall64;

#define DEVICE_NAME L"\\Device\\HyperFrog"		
#define SYMBOL_NAME L"\\??\\HyperFrog"

void Frog_CallRoutine(PDRIVER_OBJECT pObj);
