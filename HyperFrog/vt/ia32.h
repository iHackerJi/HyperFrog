#pragma once
#include <ntifs.h>


#define		SEGMENT_GDT	1
#define		SEGMENT_LDT	0
#define		RPL_MAX_MASK 3

//-------------Enum

typedef		enum _CpuidIndex
{
	EnumEAX,
	EnumEBX,
	EnumECX,
	EnumEDX
}CpuidIndex,*pCpuidIndex;


typedef enum _Msr {
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
}Msr;


// VMCS data fields
enum
{
	VIRTUAL_PROCESSOR_ID = 0x00000000,  // 16-Bit Control Field
	POSTED_INTERRUPT_NOTIFICATION = 0x00000002,
	EPTP_INDEX = 0x00000004,
	GUEST_ES_SELECTOR = 0x00000800,  // 16-Bit Guest-State Fields
	GUEST_CS_SELECTOR = 0x00000802,
	GUEST_SS_SELECTOR = 0x00000804,
	GUEST_DS_SELECTOR = 0x00000806,
	GUEST_FS_SELECTOR = 0x00000808,
	GUEST_GS_SELECTOR = 0x0000080a,
	GUEST_LDTR_SELECTOR = 0x0000080c,
	GUEST_TR_SELECTOR = 0x0000080e,
	GUEST_INTERRUPT_STATUS = 0x00000810,
	HOST_ES_SELECTOR = 0x00000c00,  // 16-Bit Host-State Fields
	HOST_CS_SELECTOR = 0x00000c02,
	HOST_SS_SELECTOR = 0x00000c04,
	HOST_DS_SELECTOR = 0x00000c06,
	HOST_FS_SELECTOR = 0x00000c08,
	HOST_GS_SELECTOR = 0x00000c0a,
	HOST_TR_SELECTOR = 0x00000c0c,
	IO_BITMAP_A = 0x00002000,  // 64-Bit Control Fields
	IO_BITMAP_A_HIGH = 0x00002001,
	IO_BITMAP_B = 0x00002002,
	IO_BITMAP_B_HIGH = 0x00002003,
	MSR_BITMAP = 0x00002004,
	MSR_BITMAP_HIGH = 0x00002005,
	VM_EXIT_MSR_STORE_ADDR = 0x00002006,
	VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
	VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
	VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
	VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
	VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
	EXECUTIVE_VMCS_POINTER = 0x0000200c,
	EXECUTIVE_VMCS_POINTER_HIGH = 0x0000200d,
	TSC_OFFSET = 0x00002010,
	TSC_OFFSET_HIGH = 0x00002011,
	VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
	VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
	APIC_ACCESS_ADDR = 0x00002014,
	APIC_ACCESS_ADDR_HIGH = 0x00002015,
	EPT_POINTER = 0x0000201a,
	EPT_POINTER_HIGH = 0x0000201b,
	EOI_EXIT_BITMAP_0 = 0x0000201c,
	EOI_EXIT_BITMAP_0_HIGH = 0x0000201d,
	EOI_EXIT_BITMAP_1 = 0x0000201e,
	EOI_EXIT_BITMAP_1_HIGH = 0x0000201f,
	EOI_EXIT_BITMAP_2 = 0x00002020,
	EOI_EXIT_BITMAP_2_HIGH = 0x00002021,
	EOI_EXIT_BITMAP_3 = 0x00002022,
	EOI_EXIT_BITMAP_3_HIGH = 0x00002023,
	EPTP_LIST_ADDRESS = 0x00002024,
	EPTP_LIST_ADDRESS_HIGH = 0x00002025,
	VMREAD_BITMAP_ADDRESS = 0x00002026,
	VMREAD_BITMAP_ADDRESS_HIGH = 0x00002027,
	VMWRITE_BITMAP_ADDRESS = 0x00002028,
	VMWRITE_BITMAP_ADDRESS_HIGH = 0x00002029,
	VIRTUALIZATION_EXCEPTION_INFO_ADDDRESS = 0x0000202a,
	VIRTUALIZATION_EXCEPTION_INFO_ADDDRESS_HIGH = 0x0000202b,
	XSS_EXITING_BITMAP = 0x0000202c,
	XSS_EXITING_BITMAP_HIGH = 0x0000202d,
	GUEST_PHYSICAL_ADDRESS = 0x00002400,  // 64-Bit Read-Only Data Field
	GUEST_PHYSICAL_ADDRESS_HIGH = 0x00002401,
	VMCS_LINK_POINTER = 0x00002800,  // 64-Bit Guest-State Fields
	VMCS_LINK_POINTER_HIGH = 0x00002801,
	GUEST_IA32_DEBUGCTL = 0x00002802,
	GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,
	GUEST_IA32_PAT = 0x00002804,
	GUEST_IA32_PAT_HIGH = 0x00002805,
	GUEST_IA32_EFER = 0x00002806,
	GUEST_IA32_EFER_HIGH = 0x00002807,
	GUEST_IA32_PERF_GLOBAL_CTRL = 0x00002808,
	GUEST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002809,
	GUEST_PDPTR0 = 0x0000280a,
	GUEST_PDPTR0_HIGH = 0x0000280b,
	GUEST_PDPTR1 = 0x0000280c,
	GUEST_PDPTR1_HIGH = 0x0000280d,
	GUEST_PDPTR2 = 0x0000280e,
	GUEST_PDPTR2_HIGH = 0x0000280f,
	GUEST_PDPTR3 = 0x00002810,
	GUEST_PDPTR3_HIGH = 0x00002811,
	HOST_IA32_PAT = 0x00002c00,  // 64-Bit Host-State Fields
	HOST_IA32_PAT_HIGH = 0x00002c01,
	HOST_IA32_EFER = 0x00002c02,
	HOST_IA32_EFER_HIGH = 0x00002c03,
	HOST_IA32_PERF_GLOBAL_CTRL = 0x00002c04,
	HOST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002c05,
	PIN_BASED_VM_EXEC_CONTROL = 0x00004000,  // 32-Bit Control Fields
	CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
	EXCEPTION_BITMAP = 0x00004004,
	PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
	PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
	CR3_TARGET_COUNT = 0x0000400a,
	VM_EXIT_CONTROLS = 0x0000400c,
	VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
	VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
	VM_ENTRY_CONTROLS = 0x00004012,
	VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
	VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
	VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
	VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
	TPR_THRESHOLD = 0x0000401c,
	SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
	PLE_GAP = 0x00004020,
	PLE_WINDOW = 0x00004022,
	VM_INSTRUCTION_ERROR = 0x00004400,  // 32-Bit Read-Only Data Fields
	VM_EXIT_REASON = 0x00004402,
	VM_EXIT_INTR_INFO = 0x00004404,
	VM_EXIT_INTR_ERROR_CODE = 0x00004406,
	IDT_VECTORING_INFO_FIELD = 0x00004408,
	IDT_VECTORING_ERROR_CODE = 0x0000440a,
	VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
	VMX_INSTRUCTION_INFO = 0x0000440e,
	GUEST_ES_LIMIT = 0x00004800,  // 32-Bit Guest-State Fields
	GUEST_CS_LIMIT = 0x00004802,
	GUEST_SS_LIMIT = 0x00004804,
	GUEST_DS_LIMIT = 0x00004806,
	GUEST_FS_LIMIT = 0x00004808,
	GUEST_GS_LIMIT = 0x0000480a,
	GUEST_LDTR_LIMIT = 0x0000480c,
	GUEST_TR_LIMIT = 0x0000480e,
	GUEST_GDTR_LIMIT = 0x00004810,
	GUEST_IDTR_LIMIT = 0x00004812,
	GUEST_ES_AR_BYTES = 0x00004814,
	GUEST_CS_AR_BYTES = 0x00004816,
	GUEST_SS_AR_BYTES = 0x00004818,
	GUEST_DS_AR_BYTES = 0x0000481a,
	GUEST_FS_AR_BYTES = 0x0000481c,
	GUEST_GS_AR_BYTES = 0x0000481e,
	GUEST_LDTR_AR_BYTES = 0x00004820,
	GUEST_TR_AR_BYTES = 0x00004822,
	GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
	GUEST_ACTIVITY_STATE = 0x00004826,
	GUEST_SMBASE = 0x00004828,
	GUEST_SYSENTER_CS = 0x0000482a,
	VMX_PREEMPTION_TIMER_VALUE = 0x0000482e,
	HOST_IA32_SYSENTER_CS = 0x00004c00,  // 32-Bit Host-State Field
	CR0_GUEST_HOST_MASK = 0x00006000,    // Natural-Width Control Fields
	CR4_GUEST_HOST_MASK = 0x00006002,
	CR0_READ_SHADOW = 0x00006004,
	CR4_READ_SHADOW = 0x00006006,
	CR3_TARGET_VALUE0 = 0x00006008,
	CR3_TARGET_VALUE1 = 0x0000600a,
	CR3_TARGET_VALUE2 = 0x0000600c,
	CR3_TARGET_VALUE3 = 0x0000600e,
	EXIT_QUALIFICATION = 0x00006400,  // Natural-Width Read-Only Data Fields
	IO_RCX = 0x00006402,
	IO_RSI = 0x00006404,
	IO_RDI = 0x00006406,
	IO_RIP = 0x00006408,
	GUEST_LINEAR_ADDRESS = 0x0000640a,
	GUEST_CR0 = 0x00006800,  // Natural-Width Guest-State Fields
	GUEST_CR3 = 0x00006802,
	GUEST_CR4 = 0x00006804,
	GUEST_ES_BASE = 0x00006806,
	GUEST_CS_BASE = 0x00006808,
	GUEST_SS_BASE = 0x0000680a,
	GUEST_DS_BASE = 0x0000680c,
	GUEST_FS_BASE = 0x0000680e,
	GUEST_GS_BASE = 0x00006810,
	GUEST_LDTR_BASE = 0x00006812,
	GUEST_TR_BASE = 0x00006814,
	GUEST_GDTR_BASE = 0x00006816,
	GUEST_IDTR_BASE = 0x00006818,
	GUEST_DR7 = 0x0000681a,
	GUEST_RSP = 0x0000681c,
	GUEST_RIP = 0x0000681e,
	GUEST_RFLAGS = 0x00006820,
	GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
	GUEST_SYSENTER_ESP = 0x00006824,
	GUEST_SYSENTER_EIP = 0x00006826,
	HOST_CR0 = 0x00006c00,  // Natural-Width Host-State Fields
	HOST_CR3 = 0x00006c02,
	HOST_CR4 = 0x00006c04,
	HOST_FS_BASE = 0x00006c06,
	HOST_GS_BASE = 0x00006c08,
	HOST_TR_BASE = 0x00006c0a,
	HOST_GDTR_BASE = 0x00006c0c,
	HOST_IDTR_BASE = 0x00006c0e,
	HOST_IA32_SYSENTER_ESP = 0x00006c10,
	HOST_IA32_SYSENTER_EIP = 0x00006c12,
	HOST_RSP = 0x00006c14,
	HOST_RIP = 0x00006c16
};

//------------------------------


//union----------------------------------



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
}Ia32VmxBasicMsr,*pIa32VmxBasicMsr;


typedef union _VmxPinBasedControls
{
	ULONG32 all;
	struct
	{
		unsigned ExternalInterruptExiting : 1;    // [0]
		unsigned Reserved1 : 2;                   // [1-2]
		unsigned NMIExiting : 1;                  // [3]
		unsigned Reserved2 : 1;                   // [4]
		unsigned VirtualNMIs : 1;                 // [5]
		unsigned ActivateVMXPreemptionTimer : 1;  // [6]
		unsigned ProcessPostedInterrupts : 1;     // [7]
	} Fields;
} VmxPinBasedControls, *pVmxPinBasedControls;

typedef union _VmxProcessorBasedControls {
	unsigned int all;
	struct {
		unsigned reserved1 : 2;                   //!< [0:1]
		unsigned interrupt_window_exiting : 1;    //!< [2]
		unsigned use_tsc_offseting : 1;           //!< [3]
		unsigned reserved2 : 3;                   //!< [4:6]
		unsigned hlt_exiting : 1;                 //!< [7]
		unsigned reserved3 : 1;                   //!< [8]
		unsigned invlpg_exiting : 1;              //!< [9]
		unsigned mwait_exiting : 1;               //!< [10]
		unsigned rdpmc_exiting : 1;               //!< [11]
		unsigned rdtsc_exiting : 1;               //!< [12]
		unsigned reserved4 : 2;                   //!< [13:14]
		unsigned cr3_load_exiting : 1;            //!< [15]
		unsigned cr3_store_exiting : 1;           //!< [16]
		unsigned reserved5 : 2;                   //!< [17:18]
		unsigned cr8_load_exiting : 1;            //!< [19]
		unsigned cr8_store_exiting : 1;           //!< [20]
		unsigned use_tpr_shadow : 1;              //!< [21]
		unsigned nmi_window_exiting : 1;          //!< [22]
		unsigned mov_dr_exiting : 1;              //!< [23]
		unsigned unconditional_io_exiting : 1;    //!< [24]
		unsigned use_io_bitmaps : 1;              //!< [25]
		unsigned reserved6 : 1;                   //!< [26]
		unsigned monitor_trap_flag : 1;           //!< [27]
		unsigned use_msr_bitmaps : 1;             //!< [28]
		unsigned monitor_exiting : 1;             //!< [29]
		unsigned pause_exiting : 1;               //!< [30]
		unsigned activate_secondary_control : 1;  //!< [31]
	} fields;
}VmxProcessorBasedControls,*pVmxProcessorBasedControls;

typedef union _CpuFeaturesEcx {
	ULONG32 all;
	struct {
		unsigned sse3 : 1;       //!< [0] Streaming SIMD Extensions 3 (SSE3)
		unsigned pclmulqdq : 1;  //!< [1] PCLMULQDQ
		unsigned dtes64 : 1;     //!< [2] 64-bit DS Area
		unsigned monitor : 1;    //!< [3] MONITOR/WAIT
		unsigned ds_cpl : 1;     //!< [4] CPL qualified Debug Store
		unsigned vmx : 1;        //!< [5] Virtual Machine Technology
		unsigned smx : 1;        //!< [6] Safer Mode Extensions
		unsigned est : 1;        //!< [7] Enhanced Intel Speedstep Technology
		unsigned tm2 : 1;        //!< [8] Thermal monitor 2
		unsigned ssse3 : 1;      //!< [9] Supplemental Streaming SIMD Extensions 3
		unsigned cid : 1;        //!< [10] L1 context ID
		unsigned sdbg : 1;       //!< [11] IA32_DEBUG_INTERFACE MSR
		unsigned fma : 1;        //!< [12] FMA extensions using YMM state
		unsigned cx16 : 1;       //!< [13] CMPXCHG16B
		unsigned xtpr : 1;       //!< [14] xTPR Update Control
		unsigned pdcm : 1;       //!< [15] Performance/Debug capability MSR
		unsigned reserved : 1;   //!< [16] Reserved
		unsigned pcid : 1;       //!< [17] Process-context identifiers
		unsigned dca : 1;        //!< [18] prefetch from a memory mapped device
		unsigned sse4_1 : 1;     //!< [19] SSE4.1
		unsigned sse4_2 : 1;     //!< [20] SSE4.2
		unsigned x2_apic : 1;    //!< [21] x2APIC feature
		unsigned movbe : 1;      //!< [22] MOVBE instruction
		unsigned popcnt : 1;     //!< [23] POPCNT instruction
		unsigned reserved3 : 1;  //!< [24] one-shot operation using a TSC deadline
		unsigned aes : 1;        //!< [25] AESNI instruction
		unsigned xsave : 1;      //!< [26] XSAVE/XRSTOR feature
		unsigned osxsave : 1;    //!< [27] enable XSETBV/XGETBV instructions
		unsigned avx : 1;        //!< [28] AVX instruction extensions
		unsigned f16c : 1;       //!< [29] 16-bit floating-point conversion
		unsigned rdrand : 1;     //!< [30] RDRAND instruction
		unsigned not_used : 1;   //!< [31] Always 0 (a.k.a. HypervisorPresent)
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




typedef union _SEGMENT_SELECTOR
{
	struct
	{
		UINT16 RequestPrivilegeLevel : 2;
		UINT16 Table : 1;

		UINT16 Index : 13;

	};

	UINT16 Flags;
}SEGMENT_SELECTOR,*pSEGMENT_SELECTOR;


typedef union _KGDTENTRY64
{
	struct
	{
		USHORT LimitLow;
		USHORT BaseLow;
		union
		{
			struct
			{
				UCHAR BaseMiddle;
				UCHAR Flags1;
				UCHAR Flags2;
				UCHAR BaseHigh;
			} Bytes;

			struct
			{
				ULONG BaseMiddle : 8;
				ULONG Type : 5;
				ULONG Dpl : 2;
				ULONG Present : 1;
				ULONG LimitHigh : 4;
				ULONG System : 1;
				ULONG LongMode : 1;
				ULONG DefaultBig : 1;
				ULONG Granularity : 1;
				ULONG BaseHigh : 8;
			} Bits;
		};

		ULONG BaseUpper;
		ULONG MustBeZero;
	};

	struct
	{
		LONG64 DataLow;
		LONG64 DataHigh;
	};
	
} KGDTENTRY64, *PKGDTENTRY64;


//----------------------------------

//struct
typedef struct _VmControlStructure {
	unsigned long revision_identifier;
	unsigned long vmx_abort_indicator;
	unsigned long data[1];  //!< Implementation-specific format.
}VmControlStructure, *pVmControlStructure;