#pragma once
#include <ntifs.h>

//-------------Enum

typedef		enum _CpuidIndex
{
	EnumEAX,
	EnumEBX,
	EnumECX,
	EnumEDX
}CpuidIndex,*pCpuidIndex;


enum Msr {
	kIa32ApicBase = 0x01B,

	kIa32FeatureControl = 0x03A,

	kIa32SysenterCs = 0x174,
	kIa32SysenterEsp = 0x175,
	kIa32SysenterEip = 0x176,

	kIa32Debugctl = 0x1D9,

	kIa32MtrrCap = 0xFE,
	kIa32MtrrDefType = 0x2FF,
	kIa32MtrrPhysBaseN = 0x200,
	kIa32MtrrPhysMaskN = 0x201,
	kIa32MtrrFix64k00000 = 0x250,
	kIa32MtrrFix16k80000 = 0x258,
	kIa32MtrrFix16kA0000 = 0x259,
	kIa32MtrrFix4kC0000 = 0x268,
	kIa32MtrrFix4kC8000 = 0x269,
	kIa32MtrrFix4kD0000 = 0x26A,
	kIa32MtrrFix4kD8000 = 0x26B,
	kIa32MtrrFix4kE0000 = 0x26C,
	kIa32MtrrFix4kE8000 = 0x26D,
	kIa32MtrrFix4kF0000 = 0x26E,
	kIa32MtrrFix4kF8000 = 0x26F,

	kIa32VmxBasic = 0x480,
	kIa32VmxPinbasedCtls = 0x481,
	kIa32VmxProcBasedCtls = 0x482,
	kIa32VmxExitCtls = 0x483,
	kIa32VmxEntryCtls = 0x484,
	kIa32VmxMisc = 0x485,
	kIa32VmxCr0Fixed0 = 0x486,
	kIa32VmxCr0Fixed1 = 0x487,
	kIa32VmxCr4Fixed0 = 0x488,
	kIa32VmxCr4Fixed1 = 0x489,
	kIa32VmxVmcsEnum = 0x48A,
	kIa32VmxProcBasedCtls2 = 0x48B,
	kIa32VmxEptVpidCap = 0x48C,
	kIa32VmxTruePinbasedCtls = 0x48D,
	kIa32VmxTrueProcBasedCtls = 0x48E,
	kIa32VmxTrueExitCtls = 0x48F,
	kIa32VmxTrueEntryCtls = 0x490,
	kIa32VmxVmfunc = 0x491,

	kIa32Efer = 0xC0000080,
	kIa32Star = 0xC0000081,
	kIa32Lstar = 0xC0000082,

	kIa32Fmask = 0xC0000084,

	kIa32FsBase = 0xC0000100,
	kIa32GsBase = 0xC0000101,
	kIa32KernelGsBase = 0xC0000102,
	kIa32TscAux = 0xC0000103,
};



//------------------------------


//union----------------------------------

typedef union _CpuFeaturesEcx {
	ULONG32 all;
	struct {
		ULONG32 sse3 : 1;       //!< [0] Streaming SIMD Extensions 3 (SSE3)
		ULONG32 pclmulqdq : 1;  //!< [1] PCLMULQDQ
		ULONG32 dtes64 : 1;     //!< [2] 64-bit DS Area
		ULONG32 monitor : 1;    //!< [3] MONITOR/WAIT
		ULONG32 ds_cpl : 1;     //!< [4] CPL qualified Debug Store
		ULONG32 vmx : 1;        //!< [5] Virtual Machine Technology
		ULONG32 smx : 1;        //!< [6] Safer Mode Extensions
		ULONG32 est : 1;        //!< [7] Enhanced Intel Speedstep Technology
		ULONG32 tm2 : 1;        //!< [8] Thermal monitor 2
		ULONG32 ssse3 : 1;      //!< [9] Supplemental Streaming SIMD Extensions 3
		ULONG32 cid : 1;        //!< [10] L1 context ID
		ULONG32 sdbg : 1;       //!< [11] IA32_DEBUG_INTERFACE MSR
		ULONG32 fma : 1;        //!< [12] FMA extensions using YMM state
		ULONG32 cx16 : 1;       //!< [13] CMPXCHG16B
		ULONG32 xtpr : 1;       //!< [14] xTPR Update Control
		ULONG32 pdcm : 1;       //!< [15] Performance/Debug capability MSR
		ULONG32 reserved : 1;   //!< [16] Reserved
		ULONG32 pcid : 1;       //!< [17] Process-context identifiers
		ULONG32 dca : 1;        //!< [18] prefetch from a memory mapped device
		ULONG32 sse4_1 : 1;     //!< [19] SSE4.1
		ULONG32 sse4_2 : 1;     //!< [20] SSE4.2
		ULONG32 x2_apic : 1;    //!< [21] x2APIC feature
		ULONG32 movbe : 1;      //!< [22] MOVBE instruction
		ULONG32 popcnt : 1;     //!< [23] POPCNT instruction
		ULONG32 reserved3 : 1;  //!< [24] one-shot operation using a TSC deadline
		ULONG32 aes : 1;        //!< [25] AESNI instruction
		ULONG32 xsave : 1;      //!< [26] XSAVE/XRSTOR feature
		ULONG32 osxsave : 1;    //!< [27] enable XSETBV/XGETBV instructions
		ULONG32 avx : 1;        //!< [28] AVX instruction extensions
		ULONG32 f16c : 1;       //!< [29] 16-bit floating-point conversion
		ULONG32 rdrand : 1;     //!< [30] RDRAND instruction
		ULONG32 not_used : 1;   //!< [31] Always 0 (a.k.a. HypervisorPresent)
	} fields;
}CpuFeaturesEcx,*pCpuFeaturesEcx;


typedef union _Cr4 {
	ULONG_PTR all;
	struct {
		unsigned vme : 1;         //!< [0] Virtual Mode Extensions
		unsigned pvi : 1;         //!< [1] Protected-Mode Virtual Interrupts
		unsigned tsd : 1;         //!< [2] Time Stamp Disable
		unsigned de : 1;          //!< [3] Debugging Extensions
		unsigned pse : 1;         //!< [4] Page Size Extensions
		unsigned pae : 1;         //!< [5] Physical Address Extension
		unsigned mce : 1;         //!< [6] Machine-Check Enable
		unsigned pge : 1;         //!< [7] Page Global Enable
		unsigned pce : 1;         //!< [8] Performance-Monitoring Counter Enable
		unsigned osfxsr : 1;      //!< [9] OS Support for FXSAVE/FXRSTOR
		unsigned osxmmexcpt : 1;  //!< [10] OS Support for Unmasked SIMD Exceptions
		unsigned reserved1 : 2;   //!< [11:12]
		unsigned vmxe : 1;        //!< [13] Virtual Machine Extensions Enabled
		unsigned smxe : 1;        //!< [14] SMX-Enable Bit
		unsigned reserved2 : 2;   //!< [15:16]
		unsigned pcide : 1;       //!< [17] PCID Enable
		unsigned osxsave : 1;  //!< [18] XSAVE and Processor Extended States-Enable
		unsigned reserved3 : 1;  //!< [19]
		unsigned smep : 1;  //!< [20] Supervisor Mode Execution Protection Enable
		unsigned smap : 1;  //!< [21] Supervisor Mode Access Protection Enable
	} fields;
}Cr4,*pCr4;


typedef union _Cr0 {
	ULONG_PTR all;
	struct {
		unsigned pe : 1;          //!< [0] Protected Mode Enabled
		unsigned mp : 1;          //!< [1] Monitor Coprocessor FLAG
		unsigned em : 1;          //!< [2] Emulate FLAG
		unsigned ts : 1;          //!< [3] Task Switched FLAG
		unsigned et : 1;          //!< [4] Extension Type FLAG
		unsigned ne : 1;          //!< [5] Numeric Error
		unsigned reserved1 : 10;  //!< [6:15]
		unsigned wp : 1;          //!< [16] Write Protect
		unsigned reserved2 : 1;   //!< [17]
		unsigned am : 1;          //!< [18] Alignment Mask
		unsigned reserved3 : 10;  //!< [19:28]
		unsigned nw : 1;          //!< [29] Not Write-Through
		unsigned cd : 1;          //!< [30] Cache Disable
		unsigned pg : 1;          //!< [31] Paging Enabled
	} fields;
}Cr0,*pCr0;


typedef union _Ia32FeatureControlMsr {
	unsigned __int64 all;
	struct {
		unsigned lock : 1;                  //!< [0]
		unsigned enable_smx : 1;            //!< [1]
		unsigned enable_vmxon : 1;          //!< [2]
		unsigned reserved1 : 5;             //!< [3:7]
		unsigned enable_local_senter : 7;   //!< [8:14]
		unsigned enable_global_senter : 1;  //!< [15]
		unsigned reserved2 : 16;            //!<
		unsigned reserved3 : 32;            //!< [16:63]
	} fields;
}Ia32FeatureControlMsr,*pIa32FeatureControlMsr;


typedef union _EptPointer {
	ULONG64 all;
	struct {
		ULONG64 memory_type : 3;                      //!< [0:2]
		ULONG64 page_walk_length : 3;                 //!< [3:5]
		ULONG64 enable_accessed_and_dirty_flags : 1;  //!< [6]
		ULONG64 reserved1 : 5;                        //!< [7:11]
		ULONG64 pml4_address : 36;                    //!< [12:48-1]
		ULONG64 reserved2 : 16;                       //!< [48:63]
	} fields;
}EptPointer, *pEptPointer;

/// See: BASIC VMX INFORMATION
typedef union _Ia32VmxBasicMsr {
	unsigned __int64 all;
	struct {
		unsigned revision_identifier : 31;    //!< [0:30]
		unsigned reserved1 : 1;               //!< [31]
		unsigned region_size : 12;            //!< [32:43]
		unsigned region_clear : 1;            //!< [44]
		unsigned reserved2 : 3;               //!< [45:47]
		unsigned supported_ia64 : 1;          //!< [48]
		unsigned supported_dual_moniter : 1;  //!< [49]
		unsigned memory_type : 4;             //!< [50:53]
		unsigned vm_exit_report : 1;          //!< [54]
		unsigned vmx_capability_hint : 1;     //!< [55]
		unsigned reserved3 : 8;               //!< [56:63]
	} fields;
}Ia32VmxBasicMsr, *pIa32VmxBasicMsr;


//----------------------------------

//struct
typedef struct _VmControlStructure {
	unsigned long revision_identifier;
	unsigned long vmx_abort_indicator;
	unsigned long data[1];  //!< Implementation-specific format.
}VmControlStructure, *pVmControlStructure;