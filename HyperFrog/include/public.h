#pragma once
#include <ntifs.h>
#include <vadefs.h>
#include <stdarg.h>
#include <ntstrsafe.h>
#include <intrin.h>
#include <ntimage.h>

#define Frog_MaxListFlag		"_MaxList"
#define MAX_SYSCALL_INDEX  0x1000
#define NUMBER_SERVICE_TABLES 2

#define  bool BOOLEAN
#define  true TRUE
#define  false FALSE

#include "ExportStruct.h"
#include "ExportFunction.h"
#include "tools.h"
#include "ia32.h"
#include "vt_asm.h"
#include "vt.h"
#include "vt_help.h"
#include "SymbolShare.h"
#include "comm.h"
#include "msr_hook.h"
#include "hook_table.h"
#include "KiSystemCall64.h"

extern	pFrogCpu g_FrogCpu;

#define DEVICE_NAME L"\\Device\\HyperFrog"		
#define SYMBOL_NAME L"\\??\\HyperFrog"

void Frog_CallRoutine(PDRIVER_OBJECT pObj);
