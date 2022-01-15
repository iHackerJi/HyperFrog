#pragma once

bool CPUID_VmxIsSupport();
bool MSR_VmxIsSupport();
bool CR0_VmxIsSuppor();
bool Frog_IsSupportHyper();

PVOID FrogExAllocatePool(ULONG Size);
bool Forg_AllocateForgVmxRegion();
void Frog_FreeHyperRegion(pFrogVmx		pForgVmxEntry);
FrogRetCode Frog_AllocateHyperRegion(pFrogVmx		pForgVmxEntry, ULONG		CpuNumber);
void Frog_SetHyperRegionVersion(pFrogVmx		pForgVmxEntry, ULONG		CpuNumber);
FrogRetCode Frog_Vmx_Write(ULONG64 Field, ULONG64	FieldValue);
ULONG64 Frog_Vmx_Read(ULONG64 Field);

ULONG  Frog_VmxAdjustControlValue(Msr	msr, ULONG MapValue);
VOID Frog_GetSelectInfo(PKDESCRIPTOR		pGdtr, USHORT					Select, PULONG64				pBase, PULONG64				pLimit, PULONG64				pAccess);

void Frog_SetCrxToEnableHyper();
void Frog_SetCrxToDisableHyper();
void Frog_SetMsrBitToEnableHyper();
FrogRetCode Frog_FullVmxSelector(KPROCESSOR_STATE		HostState);

bool Frog_VmCall(ULONG64    Rcx, ULONG64    Rdx, ULONG64    R8, ULONG64    R9);

void Frog_GetMtrrInfo();
void Frog_SetEptp(pFrogVmx pForgVmxEntry);
void Frog_BuildEpt(pFrogVmx pForgVmxEntry);
void SetEptMemoryByMttrInfo(pFrogVmx pForgVmxEntry, int i,int j);
void Frog_Hook();
void Frog_UnHook();