#pragma once
#include <ntifs.h>


#define		SEGMENT_GDT	0
#define		SEGMENT_LDT    1
#define		RPL_MAX_MASK 3

#define MSR_APIC_BASE                       0x01B
#define MSR_IA32_FEATURE_CONTROL            0x03A
#define MSR_IA32_VMX_BASIC                  0x480
#define MSR_IA32_VMX_PINBASED_CTLS          0x481
#define MSR_IA32_VMX_PROCBASED_CTLS         0x482
#define MSR_IA32_VMX_EXIT_CTLS              0x483
#define MSR_IA32_VMX_ENTRY_CTLS             0x484
#define MSR_IA32_VMX_MISC                   0x485
#define MSR_IA32_VMX_CR0_FIXED0             0x486
#define MSR_IA32_VMX_CR0_FIXED1             0x487
#define MSR_IA32_VMX_CR4_FIXED0             0x488
#define MSR_IA32_VMX_CR4_FIXED1             0x489
#define MSR_IA32_VMX_VMCS_ENUM              0x48A
#define MSR_IA32_VMX_PROCBASED_CTLS2        0x48B
#define MSR_IA32_VMX_EPT_VPID_CAP           0x48C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS     0x48D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS    0x48E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS         0x48F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS        0x490
#define MSR_IA32_VMX_VMFUNC                 0x491
#define MSR_IA32_SYSENTER_CS                0x174
#define MSR_IA32_SYSENTER_ESP               0x175
#define MSR_IA32_SYSENTER_EIP               0x176
#define MSR_IA32_DEBUGCTL                   0x1D9
#define MSR_LSTAR                           0xC0000082

//-------------Enum

typedef enum _VECTOR_EXCEPTION
{
    VECTOR_DIVIDE_ERROR_EXCEPTION = 0,
    VECTOR_DEBUG_EXCEPTION = 1,
    VECTOR_NMI_INTERRUPT = 2,
    VECTOR_BREAKPOINT_EXCEPTION = 3,
    VECTOR_OVERFLOW_EXCEPTION = 4,
    VECTOR_BOUND_EXCEPTION = 5,
    VECTOR_INVALID_OPCODE_EXCEPTION = 6,
    VECTOR_DEVICE_NOT_AVAILABLE_EXCEPTION = 7,
    VECTOR_DOUBLE_FAULT_EXCEPTION = 8,
    VECTOR_COPROCESSOR_SEGMENT_OVERRUN = 9,
    VECTOR_INVALID_TSS_EXCEPTION = 10,
    VECTOR_SEGMENT_NOT_PRESENT = 11,
    VECTOR_STACK_FAULT_EXCEPTION = 12,
    VECTOR_GENERAL_PROTECTION_EXCEPTION = 13,
    VECTOR_PAGE_FAULT_EXCEPTION = 14,
    VECTOR_X87_FLOATING_POINT_ERROR = 16,
    VECTOR_ALIGNMENT_CHECK_EXCEPTION = 17,
    VECTOR_MACHINE_CHECK_EXCEPTION = 18,
    VECTOR_SIMD_FLOATING_POINT_EXCEPTION = 19,
    VECTOR_VIRTUALIZATION_EXCEPTION = 20
} VECTOR_EXCEPTION;


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
	VIRTUAL_PROCESSOR_ID = 0x00000000,
	POSTED_INTR_NOTIFICATION_VECTOR = 0x00000002,
	EPTP_INDEX = 0x00000004,
	GUEST_ES_SELECTOR = 0x00000800,
	GUEST_CS_SELECTOR = 0x00000802,
	GUEST_SS_SELECTOR = 0x00000804,
	GUEST_DS_SELECTOR = 0x00000806,
	GUEST_FS_SELECTOR = 0x00000808,
	GUEST_GS_SELECTOR = 0x0000080a,
	GUEST_LDTR_SELECTOR = 0x0000080c,
	GUEST_TR_SELECTOR = 0x0000080e,
	GUEST_INTR_STATUS = 0x00000810,
	GUEST_PML_INDEX = 0x00000812,
	HOST_ES_SELECTOR = 0x00000c00,
	HOST_CS_SELECTOR = 0x00000c02,
	HOST_SS_SELECTOR = 0x00000c04,
	HOST_DS_SELECTOR = 0x00000c06,
	HOST_FS_SELECTOR = 0x00000c08,
	HOST_GS_SELECTOR = 0x00000c0a,
	HOST_TR_SELECTOR = 0x00000c0c,
	IO_BITMAP_A = 0x00002000,
	IO_BITMAP_B = 0x00002002,
	MSR_BITMAP = 0x00002004,
	VM_EXIT_MSR_STORE_ADDR = 0x00002006,
	VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
	VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
	PML_ADDRESS = 0x0000200e,
	TSC_OFFSET = 0x00002010,
	VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
	APIC_ACCESS_ADDR = 0x00002014,
	PI_DESC_ADDR = 0x00002016,
	VM_FUNCTION_CONTROL = 0x00002018,
	EPT_POINTER = 0x0000201a,
	EOI_EXIT_BITMAP0 = 0x0000201c,
	EPTP_LIST_ADDR = 0x00002024,
	VMREAD_BITMAP = 0x00002026,
	VMWRITE_BITMAP = 0x00002028,
	VIRT_EXCEPTION_INFO = 0x0000202a,
	XSS_EXIT_BITMAP = 0x0000202c,
	TSC_MULTIPLIER = 0x00002032,
	GUEST_PHYSICAL_ADDRESS = 0x00002400,
	GUEST_PHYSICAL_ADDRESS_HIGH = 0x00002401,
	VMCS_LINK_POINTER = 0x00002800,
	GUEST_IA32_DEBUGCTL = 0x00002802,
	GUEST_PAT = 0x00002804,
	GUEST_EFER = 0x00002806,
	GUEST_PERF_GLOBAL_CTRL = 0x00002808,
	GUEST_PDPTE0 = 0x0000280a,
	GUEST_BNDCFGS = 0x00002812,
	HOST_PAT = 0x00002c00,
	HOST_EFER = 0x00002c02,
	HOST_PERF_GLOBAL_CTRL = 0x00002c04,
	PIN_BASED_VM_EXEC_CONTROL = 0x00004000, // 基于处理器的主vm执行控制信息域
	CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
	EXCEPTION_BITMAP = 0x00004004,			// 异常 BitMap
	PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
	PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
	CR3_TARGET_COUNT = 0x0000400a,
	VM_EXIT_CONTROLS = 0x0000400c,
	VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
	VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
	VM_ENTRY_CONTROLS = 0x00004012,
	VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
	VM_ENTRY_INTR_INFO = 0x00004016,
	VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
	VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
	TPR_THRESHOLD = 0x0000401c,
	SECONDARY_VM_EXEC_CONTROL = 0x0000401e, // 基于处理器的辅助vm执行控制信息域的扩展字段 【Secondary Processor-Based VM-Execution Controls】
	PLE_GAP = 0x00004020,
	PLE_WINDOW = 0x00004022,
	VM_INSTRUCTION_ERROR = 0x00004400,
	VM_EXIT_REASON = 0x00004402,
	VM_EXIT_INTR_INFO = 0x00004404,
	VM_EXIT_INTR_ERROR_CODE = 0x00004406,   // See: VM-Instruction Error Numbers
	IDT_VECTORING_INFO = 0x00004408,
	IDT_VECTORING_ERROR_CODE = 0x0000440a,
	VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
	VMX_INSTRUCTION_INFO = 0x0000440e,
	GUEST_ES_LIMIT = 0x00004800,
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
	GUEST_PREEMPTION_TIMER = 0x0000482e,
	HOST_SYSENTER_CS = 0x00004c00,
	CR0_GUEST_HOST_MASK = 0x00006000,
	CR4_GUEST_HOST_MASK = 0x00006002,
	CR0_READ_SHADOW = 0x00006004,
	CR4_READ_SHADOW = 0x00006006,
	CR3_TARGET_VALUE0 = 0x00006008,
	EXIT_QUALIFICATION = 0x00006400, // (哪些指令该字段有效，请参考【处理器虚拟化技术】(第3.10.1.3节))
	GUEST_LINEAR_ADDRESS = 0x0000640a,
	GUEST_CR0 = 0x00006800,
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
	HOST_CR0 = 0x00006c00,
	HOST_CR3 = 0x00006c02,
	HOST_CR4 = 0x00006c04,
	HOST_FS_BASE = 0x00006c06,
	HOST_GS_BASE = 0x00006c08,
	HOST_TR_BASE = 0x00006c0a,
	HOST_GDTR_BASE = 0x00006c0c,
	HOST_IDTR_BASE = 0x00006c0e,
	HOST_SYSENTER_ESP = 0x00006c10,
	HOST_SYSENTER_EIP = 0x00006c12,
	HOST_RSP = 0x00006c14,
	HOST_RIP = 0x00006c16,
};

enum MovCrAccessType {
    kMoveToCr = 0, // MOV crx, reg
    KMobeFromCr,   // MOV reg, crx
    kClts,
    kLmsw
};


//------------------------------


//union----------------------------------



typedef union _FlagReg {
    ULONG_PTR all;
    struct {
        ULONG_PTR cf : 1;          //!< [0] Carry flag
        ULONG_PTR reserved1 : 1;   //!< [1] Always 1
        ULONG_PTR pf : 1;          //!< [2] Parity flag
        ULONG_PTR reserved2 : 1;   //!< [3] Always 0
        ULONG_PTR af : 1;          //!< [4] Borrow flag
        ULONG_PTR reserved3 : 1;   //!< [5] Always 0
        ULONG_PTR zf : 1;          //!< [6] Zero flag
        ULONG_PTR sf : 1;          //!< [7] Sign flag
        ULONG_PTR tf : 1;          //!< [8] Trap flag
        ULONG_PTR intf : 1;        //!< [9] Interrupt flag
        ULONG_PTR df : 1;          //!< [10] Direction flag
        ULONG_PTR of : 1;          //!< [11] Overflow flag
        ULONG_PTR iopl : 2;        //!< [12:13] I/O privilege level
        ULONG_PTR nt : 1;          //!< [14] Nested task flag
        ULONG_PTR reserved4 : 1;   //!< [15] Always 0
        ULONG_PTR rf : 1;          //!< [16] Resume flag
        ULONG_PTR vm : 1;          //!< [17] Virtual 8086 mode
        ULONG_PTR ac : 1;          //!< [18] Alignment check
        ULONG_PTR vif : 1;         //!< [19] Virtual interrupt flag
        ULONG_PTR vip : 1;         //!< [20] Virtual interrupt pending
        ULONG_PTR id : 1;          //!< [21] Identification flag
        ULONG_PTR reserved5 : 10;  //!< [22:31] Always 0
    } fields;
}FlagReg, *pFlagReg;


typedef union _CrxVmExitQualification
{
    ULONG_PTR all;
    struct
    {
        ULONG_PTR crn : 4;				  //!< [0:3]	记录访问的控制寄存器
        ULONG_PTR access_type : 2;		  //!< [4:5]	访问类型 (MovCrAccessType)
        ULONG_PTR lmsw_operand_type : 1;  //!< [6]		LMSW指令的操作数类型
        ULONG_PTR reserved1 : 1;          //!< [7]		
        ULONG_PTR gp_register : 4;        //!< [8:11]	记录使用的通用寄存器
        ULONG_PTR reserved2 : 4;          //!< [12:15]	
        ULONG_PTR lmsw_source_data : 16;  //!< [16:31]	LMSW指令的源操作数
        ULONG_PTR reserved3 : 32;         //!< [32:63]
    }Bits;
}CrxVmExitQualification, *pCrxVmExitQualification;


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

typedef union _VmxVmentryControls
{
	unsigned int all;
	struct {
		unsigned reserved1 : 2;                          //!< [0:1] 
		unsigned load_debug_controls : 1;                //!< [2]	为1时, 从(guest-state)加载debug寄存器
		unsigned reserved2 : 6;                          //!< [3:8]
		unsigned ia32e_mode_guest : 1;                   //!< [9]	为1时, 进入IA-32e模式
		unsigned entry_to_smm : 1;                       //!< [10]	为1时, 进入SMM模式
		unsigned deactivate_dual_monitor_treatment : 1;  //!< [11]	为1时, 返回executive monitor, 关闭 SMM 双重监控处理
		unsigned reserved3 : 1;                          //!< [12]
		unsigned load_ia32_perf_global_ctrl : 1;         //!< [13]	为1时, 加载 ia32_perf_global_ctrl
		unsigned load_ia32_pat : 1;                      //!< [14]	为1时, 加载 ia32_pat
		unsigned load_ia32_efer : 1;                     //!< [15]	为1时, 加载 ia32_efer
		unsigned load_ia32_bndcfgs : 1;                  //!< [16]	为1时, 加载 ia32_bndcfgs
		unsigned conceal_vmentries_from_intel_pt : 1;    //!< [17]	
	}fields;
}VmxVmentryControls, *pVmxVmentryControls;

typedef union _VmxmexitControls
{
	unsigned int all;
	struct {
		unsigned reserved1 : 2;                        //!< [0:1]	
		unsigned save_debug_controls : 1;              //!< [2]		为1时, 保存debug寄存器
		unsigned reserved2 : 6;                        //!< [3:8]
		unsigned host_address_space_size : 1;          //!< [9]		为1时, 返回到IA-32e模式
		unsigned reserved3 : 2;                        //!< [10:11]
		unsigned load_ia32_perf_global_ctrl : 1;       //!< [12]	为1时, 加载 ia32_perf_global_ctrl
		unsigned reserved4 : 2;                        //!< [13:14]
		unsigned acknowledge_interrupt_on_exit : 1;    //!< [15]	为1时, VM-exit 时处理器响应中断寄存器, 读取中断向量号
		unsigned reserved5 : 2;                        //!< [16:17]
		unsigned save_ia32_pat : 1;                    //!< [18]	为1时, 保存 ia32_pat
		unsigned load_ia32_pat : 1;                    //!< [19]	为1时, 加载 ia32_pat
		unsigned save_ia32_efer : 1;                   //!< [20]	为1时, 保存 ia32_efer
		unsigned load_ia32_efer : 1;                   //!< [21]	为1时, 加载 ia32_efer
		unsigned save_vmx_preemption_timer_value : 1;  //!< [22]	为1时, VM-exit 时保存VMX定时器计数值
		unsigned clear_ia32_bndcfgs : 1;               //!< [23]	此控件确定IA32_BNDCFGS的MSR是否在VM退出时被清除。
		unsigned conceal_vmexits_from_intel_pt : 1;    //!< [24]
	}fields;
}VmxmexitControls, *pVmxmexitControls;

typedef union _VmxSecondaryProcessorBasedControls {
	unsigned int all;
	struct {
		unsigned virtualize_apic_accesses : 1;            //!< [0]
		unsigned enable_ept : 1;                          //!< [1]
		unsigned descriptor_table_exiting : 1;            //!< [2]
		unsigned enable_rdtscp : 1;                       //!< [3]
		unsigned virtualize_x2apic_mode : 1;              //!< [4]
		unsigned enable_vpid : 1;                         //!< [5]
		unsigned wbinvd_exiting : 1;                      //!< [6]
		unsigned unrestricted_guest : 1;                  //!< [7]
		unsigned apic_register_virtualization : 1;        //!< [8]
		unsigned virtual_interrupt_delivery : 1;          //!< [9]
		unsigned pause_loop_exiting : 1;                  //!< [10]
		unsigned rdrand_exiting : 1;                      //!< [11]
		unsigned enable_invpcid : 1;                      //!< [12]
		unsigned enable_vm_functions : 1;                 //!< [13]
		unsigned vmcs_shadowing : 1;                      //!< [14]
		unsigned reserved1 : 1;                           //!< [15]
		unsigned rdseed_exiting : 1;                      //!< [16]
		unsigned reserved2 : 1;                           //!< [17]
		unsigned ept_violation_ve : 1;                    //!< [18]
		unsigned reserved3 : 1;                           //!< [19]
		unsigned enable_xsaves_xstors : 1;                //!< [20]
		unsigned reserved4 : 1;                           //!< [21]
		unsigned mode_based_execute_control_for_ept : 1;  //!< [22]
		unsigned reserved5 : 2;                           //!< [23:24]
		unsigned use_tsc_scaling : 1;                     //!< [25]
	} fields;
}VmxSecondaryProcessorBasedControls,*pVmxSecondaryProcessorBasedControls;


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
	struct {
		ULONG64 memory_type : 3;                      //!< [0:2]
		ULONG64 page_walk_length : 3;                 //!< [3:5]
		ULONG64 enable_accessed_and_dirty_flags : 1;  //!< [6]
		ULONG64 reserved1 : 5;                        //!< [7:11]
		ULONG64 pml4_address : 36;                    //!< [12:48-1]
		ULONG64 reserved2 : 16;                       //!< [48:63]
	} fields;
	ULONG64 all;
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


// See: Format of Exit Reason in Basic VM-Exit Information
// 定义 Exit reason 字段 (参考 【处理器虚拟化技术】(第3.10.1.1节))
typedef union _VmxExitInfo
{
	unsigned int all;
	struct
	{
		unsigned short reason;                     //!< [0:15]	保存VM退出原因值
		unsigned short reserved1 : 12;             //!< [16:27]
		unsigned short pending_mtf_vm_exit : 1;    //!< [28]	为1时，指示SMM VM-exit 时, 存在 pending MTF VM-exit 事件
		unsigned short vm_exit_from_vmx_root : 1;  //!< [29]	为1时，指示SMM VM-exit从VMX root-operation 
		unsigned short reserved2 : 1;              //!< [30]
		unsigned short vm_entry_failure : 1;       //!< [31]	为1时, 表明是在VM-entry过程中引发VM-exit
	}fields;
}VmxExitInfo, *pVmxExitInfo;


enum VmxExitReason
{
	//软件异常导致的,要求异常位图中设置;出现了不可屏蔽中断Nmi并且要求vm执行域的NmiExit置1
	ExitExceptionOrNmi = 0,
	//An external interrupt arrived and the “external-interrupt exiting” VM-execution control was 1.
	ExitExternalInterrupt = 1,
	//3重异常,对它的处理直接蓝屏;The logical processor encountered an exception while attempting to call the double-fault handler and that exception did not itself cause a VM exit due to the exception bitmap
	ExitTripleFault = 2,
	//这几个没有控制域来进行关闭,但很少发生
	//An INIT signal arrived
	ExitInit = 3,
	//A SIPI arrived while the logical processor was in the “wait-for-SIPI” state.
	ExitSipi = 4,
	//An SMI arrived immediately after retirement of an I/O instruction and caused an SMM VM exit
	ExitIoSmi = 5,
	//An SMI arrived and caused an SMM VM exit (see Section 34.15.2) but not immediately after retirement of an I/O instruction
	ExitOtherSmi = 6,
	//At the beginning of an instruction, RFLAGS.IF was 1; events were not blocked by STI or by MOV SS; and the “interrupt-window exiting” VM-execution control was 1.
	ExitPendingInterrupt = 7,
	//At the beginning of an instruction, there was no virtual-NMI blocking; events were not blocked by MOV SS; and the “NMI-window exiting” VM-execution control was 1.
	ExitNmiWindow = 8,
	//必须处理 由指令引发的无条件vmexit,也无法在控制域中关闭
	// Guest software attempted a task switch.
	ExitTaskSwitch = 9,
	ExitCpuid = 10,
	ExitGetSec = 11,
	//Guest software attempted to execute HLT and the “HLT exiting” VM-execution control was 1.
	ExitHlt = 12,
	//必须处理  Guest software attempted to execute INVD.无法在控制域中关闭
	ExitInvd = 13,
	//Guest software attempted to execute INVLPG and the “INVLPG exiting” VM-execution control was 1.
	ExitInvlpg = 14,
	//Guest software attempted to execute RDPMC and the “RDPMC exiting” VM-execution control was 1.
	ExitRdpmc = 15,
	//Guest software attempted to execute RDTSC and the “RDTSC exiting” VM-execution control was 1.
	ExitRdtsc = 16,
	//Guest software attempted to execute RSM in SMM.直接忽略
	ExitRsm = 17,
	//必须处理 
	ExitVmcall = 18,
	ExitVmclear = 19,
	ExitVmlaunch = 20,
	ExitVmptrld = 21,
	ExitVmptrst = 22,
	ExitVmread = 23,
	ExitVmresume = 24,
	ExitVmwrite = 25,
	ExitVmoff = 26,
	ExitVmon = 27,
	//Guest software attempted to access CR0, CR3, CR4, or CR8 using CLTS, LMSW, or MOV CR and the VM-execution control fields 
	//indicate that a VM exit should occur (see Section 25.1 for details). This basic exit reason is not used for trap-like VM exits 
	//following executions of the MOV to CR8 instruction when the “use TPR shadow” VM-execution control is 1.
	//Such VM exits instead use basic exit reason 43.
	ExitCrAccess = 28,
	//Guest software attempted a MOV to or from a debug register and the “MOV-DR exiting” VM-execution control was 1.
	ExitDrAccess = 29,
	//io指令和msr访问都可以进行禁用.这里需要将use I/O bitmaps域置0,并且unconditional I/O exiting置0
	//IN, INS/INSB/INSW/INSD, OUT, OUTS/OUTSB/OUTSW/OUTSD
	//Guest software attempted to execute an I/O instruction and either: 1: The “use I/O bitmaps” VM-execution control was 0 
	//and the “unconditional I/O exiting” VM-execution control was 1. 2: The “use I/O bitmaps” VM-execution control was 1 
	//and a bit in the I/O bitmap associated with one of the ports accessed by the I/O instruction was 1.
	ExitIoInstruction = 30,
	//同理,禁用方式如上
	//Guest software attempted to execute RDMSR and either: 1: The “use MSR bitmaps” VM-execution control was 0. 
	//2: The value of RCX is neither in the range 00000000H – 00001FFFH nor in the range C0000000H – C0001FFFH. 越界意味着#GP异常
	//3: The value of RCX was in the range 00000000H – 00001FFFH and the nth bit in read bitmap for low MSRs is 1, where n was the value of RCX.
	//4: The value of RCX is in the range C0000000H – C0001FFFH and the nth bit in read bitmap for high MSRs is 1, where n is the value of RCX & 00001FFFH.
	ExitMsrRead = 31,
	ExitMsrWrite = 32,
	//致命错误 A VM entry failed one of the checks identified in Section 26.3.1.
	ExitInvalidGuestState = 33,  // See: BASIC VM-ENTRY CHECKS
	//A VM entry failed in an attempt to load MSRs. 
	ExitMsrLoading = 34,
	ExitUndefined35 = 35,
	//Guest software attempted to execute MWAIT and the “MWAIT exiting” VM-execution control was 1.
	ExitMwaitInstruction = 36,
	//A VM entry occurred due to the 1-setting of the “monitor trap flag” VM-execution control and injection of an MTF VM exit as part of VM entry.
	ExitMonitorTrapFlag = 37,
	ExitUndefined38 = 38,
	//Guest software attempted to execute MONITOR and the “MONITOR exiting” VM-execution control was 1.
	ExitMonitorInstruction = 39,
	//Either guest software attempted to execute PAUSE and the “PAUSE exiting” VM-execution control was 1 or 
	//the “PAUSE-loop exiting” VM-execution control was 1 and guest software executed a PAUSE loop with execution time exceeding PLE_Window
	ExitPauseInstruction = 40,
	//致命错误A machine-check event occurred during VM entry
	ExitMachineCheck = 41,
	ExitUndefined42 = 42,
	//The logical processor determined that the value of bits 7:4 of the byte at offset 080H on the virtual-APIC page 
	//was below that of the TPR threshold VM-execution control field while the “use TPR shadow” VMexecution control was 1 either as part of TPR virtualization (Section 29.1.2) or VM entry 
	ExitTprBelowThreshold = 43,
	//Guest software attempted to access memory at a physical address on the APIC-access page 
	//and the “virtualize APIC accesses” VM-execution control was 1
	ExitApicAccess = 44,
	//EOI virtualization was performed for a virtual interrupt whose vector indexed a bit set in the EOIexit bitmap
	ExitVirtualizedEoi = 45,
	//Guest software attempted to execute LGDT, LIDT, SGDT, or SIDT and the “descriptor-table exiting” VM-execution control was 1.
	ExitGdtrOrIdtrAccess = 46,
	//Guest software attempted to execute LLDT, LTR, SLDT, or STR and the “descriptor-table exiting” VM-execution control was 1
	ExitLdtrOrTrAccess = 47,
	//An attempt to access memory with a guest-physical address was disallowed by the configuration of the EPT paging structures.
	ExitEptViolation = 48,
	//致命错误An attempt to access memory with a guest-physical address encountered a misconfigured EPT paging-structure entry.
	ExitEptMisconfig = 49,
	//必须处理 Guest software attempted to execute INVEPT.
	ExitInvept = 50,
	//Guest software attempted to execute RDTSCP and the “enable RDTSCP” and “RDTSC exiting” VM-execution controls were both 1.
	ExitRdtscp = 51,
	//The preemption timer counted down to zero.
	ExitVmxPreemptionTime = 52,
	//必须处理 Guest software attempted to execute INVVPID.
	ExitInvvpid = 53,
	//Guest software attempted to execute WBINVD and the “WBINVD exiting” VM-execution control was 1.
	ExitWbinvd = 54,
	//必须处理 Guest software attempted to execute XSETBV.
	ExitXsetbv = 55,
	//Guest software completed a write to the virtual-APIC page that must be virtualized by VMM software
	ExitApicWrite = 56,
	//Guest software attempted to execute RDRAND and the “RDRAND exiting” VM-execution control was 1.
	ExitRdrand = 57,
	//Guest software attempted to execute INVPCID and the “enable INVPCID” and “INVLPG exiting” VM-execution controls were both 1.
	ExitInvpcid = 58,
	//可以关闭 Guest software invoked a VM function with the VMFUNC instruction and the VM function 
	//either was not enabled or generated a function-specific condition causing a VM exit.
	ExitVmfunc = 59,
	//可以关闭 Guest software attempted to execute ENCLS and “enable ENCLS exiting” VM-execution control was 1 and either (1) EAX < 63 
	//and the corresponding bit in the ENCLS-exiting bitmap is 1; or (2) EAX ≥ 63 and bit 63 in the ENCLS-exiting bitmap is 1
	ExitUndefined60 = 60,
	//可以关闭 Guest software attempted to execute RDSEED and the “RDSEED exiting” VM-execution control was 1.
	ExitRdseed = 61,
	//The processor attempted to create a page-modification log entry and the value of the PML index was not in the range 0–511.
	ExitUndefined62 = 62,
	//可以关闭 Guest software attempted to execute XSAVES, the “enable XSAVES/XRSTORS” was 1, 
	//and a bit was set in the logical-AND of the following three values: EDX:EAX, the IA32_XSS MSR, and the XSS-exiting bitmap.
	ExitXsaves = 63,
	//可以关闭 Guest software attempted to execute XRSTORS, the “enable XSAVES/XRSTORS” was 1, 
	//and a bit was set in the logical-AND of the following three values: EDX:EAX, the IA32_XSS MSR, and the XSS-exiting bitmap.
	ExitXrstors = 64,
};


//----------------------------------

//struct
typedef struct _VmControlStructure {
	unsigned long revision_identifier;
	unsigned long vmx_abort_indicator;
	unsigned long data[1];  //!< Implementation-specific format.
}VmControlStructure, *pVmControlStructure;

typedef struct _vCpuId
{
    ULONG32 eax;
    ULONG32 ebx;
    ULONG32 ecx;
    ULONG32 edx;
}CpuId, *pCpuId;