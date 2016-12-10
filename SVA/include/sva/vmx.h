/*===- vmx.h - SVA VMM Extension ------------------------------------------===
 *
 *                     The LLVM Compiler Infrastructure
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===----------------------------------------------------------------------===
 *
 * TODO: Edit this description.
 *
 * This header files defines functions and macros used by the SVA Execution
 * Engine for managing processor state.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef _SVA_VMX_H
#define _SVA_VMX_H

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sva/mmu.h>
#include <sva/config.h>

#ifndef NULL
#define NULL ((void *)0)
#endif /* NULL */

/* VMX capability MSRs */
#define MSR_IA32_FEATURE_CONTROL		0x03a
#define MSR_IA32_VMX_BASIC			0x480
#define MSR_IA32_VMX_PINBASED_CTLS		0x481
#define MSR_IA32_VMX_PROCBASED_CTLS		0x482
#define MSR_IA32_VMX_PROCBASED_CTLS2		0x48b
#define MSR_IA32_VMX_EXIT_CTLS			0x483
#define MSR_IA32_VMX_ENTRY_CTLS			0x484
#define MSR_IA32_VMX_MISC			0x485
#define MSR_IA32_VMX_CR0_FIXED0			0x486
#define MSR_IA32_VMX_CR0_FIXED1			0x487
#define MSR_IA32_VMX_CR4_FIXED0			0x488
#define MSR_IA32_VMX_CR4_FIXED1			0x489
#define MSR_IA32_VMX_VMCS_ENUM			0x48a
#define MSR_IA32_VMX_PROCBASED_CTLS2		0x48b
#define MSR_IA32_VMX_EPT_VPID_CAP		0x48c
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS		0x48d
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS	0x48e
#define MSR_IA32_VMX_TRUE_EXIT_CTLS		0x48f
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS		0x490

/* IA32_FRATURE_CONTROL MSR bits */
#define IA32_FEATURE_CONTROL_LOCK	(1 << 0)
#define IA32_FEATURE_CONTROL_VMX	(1 << 2)

/*
 * VMX capability MSR control bits.
 */
/* Pin-based VM-Execution Controls. See Section 24.6.1. */
#define PINBASED_EXTERNAL_INT_EXITING	(1 << 0)
#define PINBASED_NMI_EXITING		(1 << 3)
#define PINBASED_VIRTUAL_NMI		(1 << 5)
#define PINBASED_PREMPTION_TIMER	(1 << 6)
#define PINBASED_PROCESS_POSTED_INT	(1 << 7)

/* Primary Processor-based VM-Execution Controls. See Section 24.6.2. */
#define PROCBASED_INT_WINDOW_EXITING	(1 << 2)
#define PROCBASED_USE_TSC_OFFSETTING	(1 << 3)
#define PROCBASED_HLT_EXITING		(1 << 7)
#define PROCBASED_INVLPG_EXITING	(1 << 9)
#define PROCBASED_MWAIT_EXITING		(1 << 10)
#define PROCBASED_RDPMC_EXITING		(1 << 11)
#define PROCBASED_RDTSC_EXITING		(1 << 12)
#define PROCBASED_CR3_LD_EXITING	(1 << 15)
#define PROCBASED_CR3_ST_EXITING	(1 << 16)
#define PROCBASED_CR8_LD_EXITING	(1 << 19)
#define PROCBASED_CR8_ST_EXITING	(1 << 20)
#define PROCBASED_USE_TPR_SHADOW	(1 << 21)
#define PROCBASED_NMI_WINDOW_EXITING	(1 << 22)
#define PROCBASED_MOV_OR_EXITING	(1 << 23)
#define PROCBASED_UNCOND_IO_EXITING	(1 << 24)
#define PROCBASED_USE_IO_BITMAPS	(1 << 25)
#define PROCBASED_MONITOR_TRAP_FLAG	(1 << 27)
#define PROCBASED_USE_MSR_BITMAPS	(1 << 28)
#define PROCBASED_MONITOR_EXITING	(1 << 29)
#define PROCBASED_PAUSE_EXITING		(1 << 30)
#define PROCBASED_SECONDARY_CTLS	(1u << 31)

/* Secondary Processor-based VM-Execution Controls. See Section 24.6.2. */
#define PROCBASED2_VIRTUAL_APIC_ACCESS	(1 << 0)
#define PROCBASED2_ENABLE_EPT		(1 << 1)
#define PROCBASED2_DT_EXITING		(1 << 2)
#define PROCBASED2_ENABLE_RDTSCP	(1 << 3)
#define PROCBASED2_VIRTUALIZE_X2APIC	(1 << 4)
#define PROCBASED2_ENABLE_VPID		(1 << 5)
#define PROCBASED2_WBINVD_EXITING	(1 << 6)
#define PROCBASED2_UNRESTRICTED_GUEST	(1 << 7)
#define PROCBASED2_APIC_REG_VIRT	(1 << 8)
#define PROCBASED2_VIRTUAL_INT_DELIVERY	(1 << 9)
#define PROCBASED2_PAUSE_LOOP_EXITING	(1 << 10)
#define PROCBASED2_RDRAND_EXITING	(1 << 11)
#define PROCBASED2_ENABLE_INVPCID	(1 << 12)
#define PROCBASED2_ENABLE_VM_FUNCIONS	(1 << 13)
#define PROCBASED2_VMCS_SHADOWING	(1 << 14)
#define PROCBASED2_ENABLE_ENCLS_EXITING	(1 << 15)
#define PROCBASED2_RDSEED_EXITING	(1 << 16)
#define PROCBASED2_ENABLE_PML		(1 << 17)
#define PROCBASED2_EPT_VIOLATION_VE	(1 << 18)
#define PROCBASED2_CONCEL_VMX_NONROOT	(1 << 19)
#define PROCBASED2_ENABLE_XSAVES	(1 << 20)
#define PROCBASED2_MODEL_BASED_EXECTL	(1 << 22)
#define PROCBASED2_USE_TSC_SCALING	(1 << 25)

/* VM-Exit Controls. See Section 24.7.1. */
#define VM_EXIT_SAVE_DEBUG_CTLS		(1 << 2)
#define VM_EXIT_HOST_ADDR_SPACE_SIZE	(1 << 9)
#define VM_EXIT_LOAD_PERF_GLOBAL_CTRL	(1 << 12)
#define VM_EXIT_ACK_INT_ON_EXIT		(1 << 15)
#define VM_EXIT_SAVE_IA32_PAT		(1 << 18)
#define VM_EXIT_LOAD_IA32_PAT		(1 << 19)
#define VM_EXIT_SAVE_IA32_EFER		(1 << 20)
#define VM_EXIT_LOAD_IA32_EFER		(1 << 21)
#define VM_EXIT_SAVE_PREMPTION_TIMER	(1 << 22)
#define VM_EXIT_CLEAR_IA32_BNDCFGS	(1 << 23)
#define VM_EXIT_CONCEAL_VM_EXITS	(1 << 24)

/* VM-Entry Controls. See Section 24.8.1. */
#define VM_ENTRY_LOAD_DEBUG_CTLS	(1 << 2)
#define VM_ENTRY_IA32E_GUEST		(1 << 9)
#define VM_ENTRY_ENTRY_TO_SMM		(1 << 10)
#define VM_ENTRY_DEACT_DUAL_MONITOR	(1 << 11)
#define VM_ENTRY_LOAD_PERF_GLOBAL_CTRL	(1 << 13)
#define VM_ENTRY_LOAD_IA32_PAT		(1 << 14)
#define VM_ENTRY_LOAD_IA32_EFER		(1 << 15)
#define VM_ENTRY_LOAD_IA32_BNDCFGS	(1 << 16)
#define VM_ENTRY_CONCEAL_VM_ENTRIES	(1 << 17)

/*
 * TODO: Add descriptions.
 */
#define PINBASED_1_SETTINGS	(PINBASED_EXTERNAL_INT_EXITING |	\
				 PINBASED_NMI_EXITING |			\
				 PINBASED_VIRTUAL_NMI)
#define PINBASED_0_SETTINGS	(0)

#define PROCBASED_1_SETTINGS	(PROCBASED_MWAIT_EXITING |		\
				 PROCBASED_CR8_LD_EXITING |		\
				 PROCBASED_CR8_ST_EXITING |		\
				 PROCBASED_UNCOND_IO_EXITING |		\
				 PROCBASED_MONITOR_EXITING |		\
				 PROCBASED_USE_MSR_BITMAPS |		\
				 PROCBASED_SECONDARY_CTLS)
#define PROCBASED_0_SETTINGS	(PROCBASED_CR3_LD_EXITING |		\
				 PROCBASED_CR3_ST_EXITING |		\
				 PROCBASED_USE_IO_BITMAPS)

#define PROCBASED2_1_SETTINGS	(PROCBASED2_ENABLE_EPT |		\
				 PROCBASED2_ENABLE_VPID)
#define PROCBASED2_0_SETTINGS	(0)

#define VM_EXIT_1_SETTINGS	(VM_EXIT_HOST_ADDR_SPACE_SIZE |		\
				 VM_EXIT_SAVE_IA32_EFER |		\
				 VM_EXIT_LOAD_IA32_EFER |		\
				 VM_EXIT_ACK_INT_ON_EXIT)
#define VM_EXIT_0_SETTINGS	(VM_EXIT_SAVE_DEBUG_CTLS)

#define VM_ENTRY_1_SETTINGS	(VM_ENTRY_LOAD_IA32_EFER)
#define VM_ENTRY_0_SETTINGS	(VM_ENTRY_LOAD_DEBUG_CTLS |		\
				 VM_ENTRY_ENTRY_TO_SMM |		\
				 VM_ENTRY_DEACT_DUAL_MONITOR)

/* Structure for VMXON region and VMCS */
struct sva_vmcs {
	uint32_t revision;
	uint32_t abort_code;
	uint8_t data[PAGE_SIZE - 8];
};

static inline void _wcr4(uint64_t cr4)
{
	__asm__ __volatile__ ("movq %0, %%cr4"
			      : : "r" (cr4));
}

/* Inline assembly code for VMX error checking */
#define VMX_CHECK_ERROR							\
	"	jnc 1f;"						\
	"	movl $1, %0;" /* RFLAGS.CF = 1 => error = 1 */		\
	"	jmp 3f;"						\
	"1:	jnz 2f;"						\
	"	movl $2, %0;" /* RFLAGS.ZF = 1 => error = 2 */		\
	"	jmp 3f;"						\
	"2:	movl $0, %0;" /* No error */				\
	"3:"

/*
 * Wrapper of CPU VMX instructions
 */

/*
 * TODO: Add description.
 */
static inline int vmxon(struct sva_vmcs * region)
{
	/*
	 * VMXON requires the physcal address of the region.
	 */
	uintptr_t paddr = getPhysicalAddr(region);
	int err = 0;

	__asm__ __volatile__ ("vmxon %1;"
			      VMX_CHECK_ERROR
			      : "=g" (err)
			      : "m" (paddr)
			      : "memory");
	return err;
}

/*
 * TODO: Add description.
 */
static inline void vmxoff(void)
{
	__asm__ __volatile__ ("vmxoff");
}

/* SVA VMX Intrinsics */
extern int sva_vmxon(int proc_id);
extern void sva_vmxoff(void);

#endif /* _SVA_VMX_H */
