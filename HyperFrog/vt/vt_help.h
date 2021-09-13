#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "vt.h"


BOOLEAN		CPUID_VMXIsSupport();
BOOLEAN		MSR_VMXisSupport();
BOOLEAN		CR0_VMXisSuppor();
PVOID  FrogExAllocatePool(ULONG Size);
BOOLEAN Forg_AllocateForgVmxRegion();
void	Frog_FreeHyperRegion(pFrogVmx		pForgVmxEntry);
FrogRetCode Frog_AllocateHyperRegion(pFrogVmx		pForgVmxEntry, ULONG		CpuNumber);
void	Frog_SetHyperRegionVersion(pFrogVmx		pForgVmxEntry, ULONG		CpuNumber);
FrogRetCode		Frog_Vmx_Write(ULONG64 Field, ULONG64	FieldValue);
BOOLEAN		Frog_IsSupportHyper();

void		Frog_SetCr0andCr4BitToEnableHyper(pFrogVmx		pForgVmxEntry);
void		Frog_SetMsrBitToEnableHyper();