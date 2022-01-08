#pragma once
#include <ntifs.h>
#include <vadefs.h>
#include <stdarg.h>
#include <ntstrsafe.h>
#include <intrin.h>

#include "ExportFunction.h"
#include "tools.h"
#include "ia32.h"
#include "vt_asm.h"
#include "vt.h"
#include "vt_help.h"
#include "msr_hook.h"

extern	pFrogCpu g_FrogCpu;
extern ULONG64 g_orgKisystemcall64;