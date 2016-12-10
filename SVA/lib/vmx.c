#include <sva/vmx.h>

#if 0
/* VM-Execution Controls */
static uint32_t pinbased_ctls = 0;
static uint32_t procbased_ctls = 0;
static uint32_t procbased_ctls2 = 0;
static uint32_t vm_exit_ctls = 0;
static uint32_t vm_entry_ctls = 0;
#endif

/* VMXON region for each logical processor */
static struct sva_vmcs vmxon_region[numProcessors] = { 0 };

/*
 * Function: cpuid()
 *
 * Description:
 *  Execute CPUID instruction.
 *
 * Inputs:
 *  - eax: the input to the CPUID instruction
 *
 * Outputs:
 *  - peax: the address to hold the return value of EAX
 *  - pebx: the address to hold the return value of EBX
 *  - pecx: the address to hold the return value of ECX
 *  - pedx: the address to hold the return value of EDX
 */
static void cpuid(uint32_t eax, uint32_t * peax, uint32_t * pebx,
		  uint32_t * pecx, uint32_t * pedx)
{
	uint32_t ebx = 0, ecx = 0, edx = 0;

	__asm__ __volatile__ ("cpuid"
			      : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
			      : "0" (eax));
	if (peax != NULL) {
		*peax = eax;
	}
	if (pebx != NULL) {
		*pebx = ebx;
	}
	if (pecx != NULL) {
		*pecx = ecx;
	}
	if (pedx != NULL) {
		*pedx = edx;
	}
}

/*
 * Function: vmx_supported
 *
 * Description:
 *  Check if VMX is supported by the processor.
 *
 * Outputs:
 *  1 - if VMX is supported
 *  0 - otherwise
 */
static inline int vmx_supported(void)
{
	uint32_t ecx = 0;

	/*
	 * Check if CPUID.1:ECX[bit 5] is set.
	 */
	cpuid(1, NULL, NULL, &ecx, NULL);
	return (ecx & 0x20) != 0;
}

#if 0
/*
 * TODO: Add description.
 */
static int get_vmx_ctls(int msr, int true_msr, uint32_t mask0, uint32_t mask1,
			uint32_t * retval)
{
	uint64_t val = 0;
	uint64_t true_val = 0;
	uint32_t ret = 0;
	int i = 0;
	int allow0 = 0, allow1 = 0;

	/* The same bit cannot be set in both masks */
	if ((mask1 ^ mask0) != (mask1 | mask0)) {
		return -1;
	}

	/*
	 * Read the value of the MSR.
	 * See Algorithm 3 step a.
	 */
	val = rdmsr(msr);

	/*
	 * IA32_VMX_BASIC[bit 55] is set.
	 * See Algorithm 3 step c.
	 */
	if (rdmsr(MSR_IA32_VMX_BASIC) & (1ul << 55)) {
		/* Read the value of the relevant TRUE_MSR. */
		true_val = rdmsr(true_msr);

		for (i = 0; i < 32; ++i) {
			allow0 = ((true_val & (1ul << i)) == 0);
			allow1 = ((true_val & (1ul << (i + 32))) != 0);
			if (!allow0 && !allow1) {
				return -1;
			}

			/* Step c(i) */
			if (!allow0 && allow1) {
				if (mask0 && (1 << i)) {
					return -1;
				}
				ret |= (1 << i);
			} else if (!allow1 && allow0) {
				if (mask1 && (1 << i)) {
					return -1;
				}
				ret &= ~(1 << i);
			}
			/* Step c(ii) */
			else if (mask0 & (1 << i)) {
				ret &= ~(1 << i);
			} else if (mask1 & (1 << i)) {
				ret |= (1 << i);
			}
			/* Step c(iii) */
			else if ((val & (1ul << i)) == 0) {
				ret &= ~(1 << i);
			}
			/* Step c(iv) */
			else if ((val & (1ul << (i + 32))) != 0) {
				ret |= (1 << i);
			} else {
				return -1;
			}
		}
	}
	/*
	 * IA32_VMX_BASIC[bit 55] is clear.
	 * See Algorithm 3 step b.
	 */
	else for (i = 0; i < 32; ++i) {
		allow0 = ((val & (1ul << i)) == 0);
		allow1 = ((val & (1ul << (i + 32))) != 0);
		if (!allow0 && !allow1) {
			return -1;
		}

		/* Step b(i) */
		if (!allow0 && allow1) {
			if (mask0 & (1 << i)) {
				return -1;
			}
			ret |= (1 << i);
		} else if (!allow1 && allow0) {
			if (mask1 & (1 << i)) {
				return -1;
			}
			ret &= ~(1 << i);
		}
		/* Step b(ii) */
		else if (mask0 & (1 << i)) {
			ret &= ~(1 << i);
		} else if (mask1 & (1 << i)) {
			ret |= (1 << i);
		}
		/* Step b(iii) */
		else {
			ret &= ~(1 << i);
		}
	}

	*retval = ret;
	return 0;
}
#endif

/*
 * TODO: Add description.
 */
static inline int enable_vmx(void)
{
#if 0
	/* Check and get Pin-based VM-Execution Controls */
	if (get_vmx_ctls(MSR_IA32_VMX_PINBASED_CTLS,
			 MSR_IA32_VMX_TRUE_PINBASED_CTLS,
			 PINBASED_0_SETTINGS,
			 PINBASED_1_SETTINGS,
			 &pinbased_ctls) < 0) {
		return -1;
	}
	/* Check and get Primary Processor-based VM-Execution Controls */
	if (get_vmx_ctls(MSR_IA32_VMX_PROCBASED_CTLS,
			 MSR_IA32_VMX_TRUE_PROCBASED_CTLS,
			 PROCBASED_0_SETTINGS,
			 PROCBASED_1_SETTINGS,
			 &procbased_ctls) < 0) {
		return -1;
	}
	/* Check and get Secondary Processor-based VM-Execution Controls */
	if (get_vmx_ctls(MSR_IA32_VMX_PROCBASED_CTLS2,
			 MSR_IA32_VMX_PROCBASED_CTLS2,
			 PROCBASED2_0_SETTINGS,
			 PROCBASED2_1_SETTINGS,
			 &procbased_ctls2) < 0) {
		return -1;
	}
	/* Check and get VM-Exit Controls */
	if (get_vmx_ctls(MSR_IA32_VMX_EXIT_CTLS,
			 MSR_IA32_VMX_TRUE_EXIT_CTLS,
			 VM_EXIT_0_SETTINGS,
			 VM_EXIT_1_SETTINGS,
			 &vm_exit_ctls) < 0) {
		return -1;
	}
	/* Check and get VM-Entry Controls */
	if (get_vmx_ctls(MSR_IA32_VMX_ENTRY_CTLS,
			 MSR_IA32_VMX_TRUE_ENTRY_CTLS,
			 VM_ENTRY_0_SETTINGS,
			 VM_ENTRY_1_SETTINGS,
			 &vm_entry_ctls) < 0) {
		return -1;
	}

	/* TODO: Finish the remaining jobs here if necessary, */
#endif

	/* Enable VMX by setting CR4[bit 13] to 1 */
	_wcr4(_rcr4() | (1 << 13));
	return 0;
}

/*
 * TODO: Add description.
 */
static inline void disable_vmx(void)
{
	/* Disable VMX by clearing CR4[bit 13] to 0 */
	_wcr4(_rcr4() & ~(1 << 13));
}

/*
 * TODO: Add description.
 */
static uint32_t get_vmx_revision(void)
{
	/* IA32_VMX_BASIC[bit 30 - 0] */
	return rdmsr(MSR_IA32_VMX_BASIC) & 0x7fffffff;
}

/*
 * Intrinsic: sva_vmxon()
 *
 * Description:
 *  This intrinsic enables VMX and enters VMX root operation for a specific
 *  logical processor.
 *
 * Inputs:
 *  - proc_id: the ID of a processor
 *
 * Return value:
 *  0 - operation succeeded.
 *  -1 - operation failed.
 */
int sva_vmxon(int proc_id)
{
#if 0
	if (!vmx_supported()) {
		return -1;
	}
#endif

	/* Check validity of proc_id */
	if (proc_id < 0 || proc_id >= numProcessors) {
		return -1;
	}

	/* Enable VMX */
	if (enable_vmx() < 0) {
		return -1;
	}

	/*
	 * Set VMX revision number in VMXON region and enter VMX root
	 * operation.
	 */
	vmxon_region[proc_id].revision = get_vmx_revision();
	if (vmxon(&vmxon_region[proc_id]) != 0) {
		return -1;
	}
	return 0;
}

/*
 * Intrinsic: sva_vmxoff()
 *
 * Description:
 *  This intrinsic leaves VMX root operation and disables VMX for the current
 *  logical processors.
 */
void sva_vmxoff(void)
{
	vmxoff();
	disable_vmx();
}
