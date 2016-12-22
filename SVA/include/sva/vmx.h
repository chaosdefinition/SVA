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

#ifndef _KERNEL
#define _KERNEL /* Allow the use of something only for kernel */
#endif /* _KERNEL */

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/param.h>

#include <vm/vm.h>
#include <vm/pmap.h>

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

/* Structure for VMXON region and VMCS */
struct sva_vmcs {
	uint32_t revision;
	uint32_t abort_code;
	uint8_t data[PAGE_SIZE - 8];
} __attribute__((aligned(PAGE_SIZE)));

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
	uintptr_t paddr = vtophys(region);
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
extern void sva_vmxoff(int proc_id);

#endif /* _SVA_VMX_H */
