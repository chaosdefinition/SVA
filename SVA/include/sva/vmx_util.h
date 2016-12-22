#ifndef _SVA_VMX_UTIL_H
#define _SVA_VMX_UTIL_H

#include <sys/cdefs.h>
#include <sys/types.h>

static inline uint64_t _rdmsr(unsigned int msr)
{
	uint32_t low, high;

	__asm__ __volatile__ ("rdmsr"
			      : "=a" (low), "=d" (high)
			      : "c" (msr));
	return ((uint64_t)high << 32) | low;
}

static inline uint64_t _rcr4(void)
{
	uint64_t cr4;

	__asm__ __volatile__ ("movq %%cr4, %0"
			      : "=r" (cr4));
	return cr4;
}

static inline void _wcr4(uint64_t cr4)
{
	__asm__ __volatile__ ("movq %0, %%cr4"
			      : : "r" (cr4));
}

#endif /* _SVA_VMX_UTIL_H */
