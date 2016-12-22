#include <sva/vmx.h>
#include <sva/vmx_util.h>

/* VMXON region for each logical processor */
static struct sva_vmcs vmxon_region[numProcessors] = { 0 };

/* Flags indicating whether VMXON is executed in each logical processor  */
static int vmxon_done[numProcessors] = { 0 };

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
static inline void cpuid(uint32_t eax, uint32_t * peax, uint32_t * pebx,
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


/*
 * TODO: Add description.
 */
static inline int enable_vmx(void)
{
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
static inline uint32_t get_vmx_revision(void)
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

	/* Check double-enter */
	if (vmxon_done[proc_id]) {
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
	vmxon_done[proc_id] = 1;
	return 0;
}

/*
 * Intrinsic: sva_vmxoff()
 *
 * Inputs:
 *  - proc_id: the ID of a processor
 *
 * Description:
 *  This intrinsic leaves VMX root operation and disables VMX for the current
 *  logical processors.
 */
void sva_vmxoff(int proc_id)
{
	/* Check validity of proc_id */
	if (proc_id < 0 || proc_id >= numProcessors) {
		return;
	}

	/* Leave VMX root operation */
	if (vmxon_done[proc_id]) {
		vmxoff();
		vmxon_done[proc_id] = 0;
	}

	/* Disable VMX */
	disable_vmx();
}
