// Do not include system headers in this file. Code in this file needs to be
// self-contained, as it runs in a VM.
#include "hvtest_x86_guest.h"
#include <stdbool.h>
#include <stdatomic.h>

#define VMCALL(x) __asm__("vmcall" : : "a" ((x)) :)

void
simple_long_mode_vcpu_entry(uint64_t arg)
{
	VMCALL(arg + 0x23456);

	while (true) {
	}
}

void
smp_vcpu_entry(uint64_t arg)
{
	// Performing this atomic operation on the same memory on all VCPUs confirms
	// that they are running in the same IPA space, and that the space is
	// shareable.
	atomic_uint *count = (atomic_uint *)arg;

	VMCALL(atomic_fetch_add_explicit(count, 1,
	    memory_order_relaxed));

	while (true) {
	}
}

__unused static inline uint64_t
rdmsr(uint64_t msr)
{
	uint32_t idx = (uint32_t)msr;
	uint32_t outhi, outlo;

	__asm__("rdmsr" : "=d"(outhi), "=a"(outlo) : "c"(idx));

	return ((uint64_t)outhi << 32) | outlo;
}

static inline void
wrmsr(uint64_t msr, uint64_t value)
{
	uint32_t idx = (uint32_t)msr;
	uint32_t inhi = (uint32_t)((value & 0xffffffff00000000UL) >> 32);
	uint32_t inlo = (uint32_t)(value & 0xffffffffUL);

	__asm__("wrmsr" : : "d"(inhi),"a"(inlo),"c"(idx));
}

void
native_msr_vcpu_entry(uint64_t arg __unused)
{
	wrmsr(MSR_IA32_STAR, 0x123456789abcdef0);
	wrmsr(MSR_IA32_LSTAR, 0x123456789abc);
	wrmsr(MSR_IA32_CSTAR, 0x123456789abc);

	wrmsr(MSR_IA32_FMASK, 0x123456789abcdef0);

	wrmsr(MSR_IA32_TSC_AUX, 0x123);

	wrmsr(MSR_IA32_SYSENTER_CS, 0xffff);
	wrmsr(MSR_IA32_SYSENTER_ESP, 0x123456789abc);
	wrmsr(MSR_IA32_SYSENTER_EIP, 0x123456789abc);

	wrmsr(MSR_IA32_FS_BASE, 0x123456789abc);
	wrmsr(MSR_IA32_GS_BASE, 0x123456789abc);
	wrmsr(MSR_IA32_KERNEL_GS_BASE, 0x123456789abc);

	VMCALL(0x23456);

	while (true) {
	}
}
