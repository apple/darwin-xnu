#include <darwintest.h>
#include <pthread.h>
#include <stdatomic.h>

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_page_size.h>

#include <sys/sysctl.h>

#include "hvtest_x86_guest.h"

#include <Foundation/Foundation.h>
#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vmx.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.intel.hv"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_REQUIRES_SYSCTL_NE("hw.optional.arm64", 1) // Don't run translated.
	);

static bool
hv_support()
{
	int hv_support;
	size_t hv_support_size = sizeof(hv_support);

	int err = sysctlbyname("kern.hv_support", &hv_support, &hv_support_size, NULL, 0);
	if (err) {
		return false;
	} else {
		return hv_support != 0;
	}
}

static uint64_t get_reg(hv_vcpuid_t vcpu, hv_x86_reg_t reg)
{
	uint64_t val;
	T_QUIET; T_EXPECT_EQ(hv_vcpu_read_register(vcpu, reg, &val), HV_SUCCESS,
                         "get register");
	return val;
}

static void set_reg(hv_vcpuid_t vcpu, hv_x86_reg_t reg, uint64_t value)
{
	T_QUIET; T_EXPECT_EQ(hv_vcpu_write_register(vcpu, reg, value), HV_SUCCESS,
                         "set register");
}

static uint64_t get_vmcs(hv_vcpuid_t vcpu, uint32_t field)
{
	uint64_t val;
	T_QUIET; T_EXPECT_EQ(hv_vmx_vcpu_read_vmcs(vcpu, field, &val), HV_SUCCESS,
                         "get vmcs");
	return val;
}

static void set_vmcs(hv_vcpuid_t vcpu, uint32_t field, uint64_t value)
{
	T_QUIET; T_EXPECT_EQ(hv_vmx_vcpu_write_vmcs(vcpu, field, value), HV_SUCCESS,
                         "set vmcs");
}

static uint64_t get_cap(uint32_t field)
{
    uint64_t val;
    T_QUIET; T_ASSERT_EQ(hv_vmx_read_capability(field, &val), HV_SUCCESS,
                         "get capability");
    return val;
}



static NSMutableDictionary *page_cache;
static NSMutableSet *allocated_phys_pages;
static pthread_mutex_t page_cache_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t next_phys = 0x4000000;

/*
 * Map a page into guest's physical address space, return gpa of the
 * page.  If *host_uva is NULL, a new host user page is allocated.
 */
static hv_gpaddr_t
map_guest_phys(void **host_uva)
{
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_lock(&page_cache_lock),
	    "acquire page lock");

    hv_gpaddr_t gpa = next_phys;
    next_phys += vm_page_size;

    if (*host_uva == NULL) {
        *host_uva = valloc(vm_page_size);
        memset(*host_uva, 0, vm_page_size);
        [allocated_phys_pages addObject:@((uintptr_t)*host_uva)];
    }

    T_QUIET; T_ASSERT_EQ(hv_vm_map(*host_uva, gpa, vm_page_size, HV_MEMORY_READ), HV_SUCCESS, "enter hv mapping");

    [page_cache setObject:@((uintptr_t)*host_uva) forKey:@(gpa)];


	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_unlock(&page_cache_lock),
	    "release page lock");

    return gpa;
}

static uint64_t *pml4;
static hv_gpaddr_t pml4_gpa;

/* Stolen from kern/bits.h, which cannot be included outside the kernel. */
#define BIT(b)                          (1ULL << (b))

#define mask(width)                     (width >= 64 ? (unsigned long long)-1 : (BIT(width) - 1))
#define extract(x, shift, width)        ((((uint64_t)(x)) >> (shift)) & mask(width))
#define bits(x, hi, lo)                 extract((x), (lo), (hi) - (lo) + 1)


/*
 * Enter a page in a level of long mode's PML4 paging structures.
 * Helper for fault_in_page.
 */
static void *
enter_level(uint64_t *table, void *host_va, void *va, int hi, int lo) {
    uint64_t * const te = &table[bits(va, hi, lo)];

    const uint64_t present = 1;
    const uint64_t rw = 2;

    const uint64_t addr_mask = mask(47-12) << 12;

    if (!(*te & present)) {
        hv_gpaddr_t gpa = map_guest_phys(&host_va);
        *te = (gpa & addr_mask) | rw | present;
    } else {
        NSNumber *num = [page_cache objectForKey:@(*te & addr_mask)];
        T_QUIET; T_ASSERT_NOTNULL(num, "existing page is backed");
        void *backing = (void*)[num unsignedLongValue];
        if (host_va != 0) {
            T_QUIET; T_ASSERT_EQ(va, backing, "backing page matches");
        } else {
            host_va = backing;
        }
    }

    return host_va;
}

/*
 * Enters a page both into the guest paging structures and the EPT
 * (long mode PML4 only, real mode and protected mode support running
 * without paging, and that's what they use instead.)
 */
static void *
map_page(void *host_va, void *va) {
    uint64_t *pdpt = enter_level(pml4, NULL, va, 47, 39);
    uint64_t *pd = enter_level(pdpt, NULL, va, 38, 30);
    uint64_t *pt = enter_level(pd, NULL, va, 29, 21);
    return enter_level(pt, host_va, va, 20, 12);
}

static void
fault_in_page(void *va) {
	map_page(va, va);
}

static void free_page_cache(void)
{
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_lock(&page_cache_lock),
	    "acquire page lock");

	for (NSNumber *uvaNumber in allocated_phys_pages) {
		uintptr_t va = [uvaNumber unsignedLongValue];
		free((void *)va);
	}
	[page_cache release];
    [allocated_phys_pages release];

	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_unlock(&page_cache_lock),
	    "release page lock");
}

static uint64_t
run_to_next_vm_fault(hv_vcpuid_t vcpu, bool on_demand_paging)
{
	bool retry;
    uint64_t exit_reason, qual, gpa, gla, info, vector_info, error_code;
	do {
        retry = false;
		do {
            T_QUIET; T_ASSERT_EQ(hv_vcpu_run_until(vcpu, ~(uint64_t)0), HV_SUCCESS, "run VCPU");
            exit_reason = get_vmcs(vcpu, VMCS_RO_EXIT_REASON);

		} while (exit_reason == VMX_REASON_IRQ);

        qual = get_vmcs(vcpu, VMCS_RO_EXIT_QUALIFIC);
        gpa = get_vmcs(vcpu, VMCS_GUEST_PHYSICAL_ADDRESS);
        gla = get_vmcs(vcpu, VMCS_RO_GUEST_LIN_ADDR);
        info = get_vmcs(vcpu, VMCS_RO_VMEXIT_IRQ_INFO);
        vector_info = get_vmcs(vcpu, VMCS_RO_IDT_VECTOR_INFO);
        error_code = get_vmcs(vcpu, VMCS_RO_VMEXIT_IRQ_ERROR);

        if (on_demand_paging) {
            if (exit_reason == VMX_REASON_EXC_NMI &&
                (info & 0x800003ff) == 0x8000030e &&
                (error_code & 0x1) == 0) {
                // guest paging fault
                fault_in_page((void*)qual);
                retry = true;
            }
            else if (exit_reason == VMX_REASON_EPT_VIOLATION) {
                if ((qual & 0x86) == 0x82) {
                    // EPT write fault
                    T_QUIET; T_ASSERT_EQ(hv_vm_protect(gpa & ~(hv_gpaddr_t)PAGE_MASK, vm_page_size,
                                                       HV_MEMORY_READ | HV_MEMORY_WRITE),
                                         HV_SUCCESS, "make page writable");
                    retry = true;
                }
                else if ((qual & 0x86) == 0x84) {
                    // EPT exec fault
                    T_QUIET; T_ASSERT_EQ(hv_vm_protect(gpa & ~(hv_gpaddr_t)PAGE_MASK, vm_page_size,
                                                       HV_MEMORY_READ | HV_MEMORY_EXEC),
                                         HV_SUCCESS, "make page executable");
                    retry = true;
                }
            }
        }
	} while (retry);

    // printf("reason: %lld, qualification: %llx\n", exit_reason, qual);
    // printf("gpa: %llx, gla: %llx\n", gpa, gla);
    // printf("RIP: %llx\n", get_reg(vcpu, HV_X86_RIP));
    // printf("CR3: %llx\n", get_reg(vcpu, HV_X86_CR3));
    // printf("info: %llx\n", info);
    // printf("vector_info: %llx\n", vector_info);
    // printf("error_code: %llx\n", error_code);

    return exit_reason;
}

static uint64_t
expect_vmcall(hv_vcpuid_t vcpu, bool on_demand_paging)
{
	uint64_t reason = run_to_next_vm_fault(vcpu, on_demand_paging);
	T_ASSERT_EQ(reason, (uint64_t)VMX_REASON_VMCALL, "expect vmcall exit");

    // advance RIP to after VMCALL
    set_vmcs(vcpu, VMCS_GUEST_RIP, get_reg(vcpu, HV_X86_RIP)+get_vmcs(vcpu, VMCS_RO_VMEXIT_INSTR_LEN));

    return get_reg(vcpu, HV_X86_RAX);
}

static uint64_t
expect_vmcall_with_value(hv_vcpuid_t vcpu, uint64_t rax, bool on_demand_paging)
{
	uint64_t reason = run_to_next_vm_fault(vcpu, on_demand_paging);
	T_QUIET; T_ASSERT_EQ(reason, (uint64_t)VMX_REASON_VMCALL, "check for vmcall exit");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_RAX), rax, "vmcall exit with expected RAX value %llx", rax);

    // advance RIP to after VMCALL
    set_vmcs(vcpu, VMCS_GUEST_RIP, get_reg(vcpu, HV_X86_RIP)+get_vmcs(vcpu, VMCS_RO_VMEXIT_INSTR_LEN));

    return reason;
}

typedef void (*vcpu_entry_function)(uint64_t);
typedef void *(*vcpu_monitor_function)(void *, hv_vcpuid_t);

struct test_vcpu {
	hv_vcpuid_t vcpu;
	vcpu_entry_function guest_func;
	uint64_t guest_param;
	vcpu_monitor_function monitor_func;
	void *monitor_param;
};

static uint64_t
canonicalize(uint64_t ctrl, uint64_t mask)
{
	return (ctrl | (mask & 0xffffffff)) & (mask >> 32);
}

static void
setup_real_mode(hv_vcpuid_t vcpu)
{
    uint64_t pin_cap, proc_cap, proc2_cap, entry_cap, exit_cap;

    pin_cap = get_cap(HV_VMX_CAP_PINBASED);
    proc_cap = get_cap(HV_VMX_CAP_PROCBASED);
    proc2_cap = get_cap(HV_VMX_CAP_PROCBASED2);
    entry_cap = get_cap(HV_VMX_CAP_ENTRY);
    exit_cap = get_cap(HV_VMX_CAP_EXIT);

    set_vmcs(vcpu, VMCS_CTRL_PIN_BASED, canonicalize(0, pin_cap));
	set_vmcs(vcpu, VMCS_CTRL_CPU_BASED,
             canonicalize(CPU_BASED_HLT | CPU_BASED_CR8_LOAD | CPU_BASED_CR8_STORE, proc_cap));
	set_vmcs(vcpu, VMCS_CTRL_CPU_BASED2, canonicalize(0, proc2_cap));
    set_vmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS, canonicalize(0, entry_cap));
	set_vmcs(vcpu, VMCS_CTRL_VMEXIT_CONTROLS, canonicalize(0, exit_cap));

    set_vmcs(vcpu, VMCS_GUEST_CR0, 0x20);
	set_vmcs(vcpu, VMCS_CTRL_CR0_MASK, ~0u);
	set_vmcs(vcpu, VMCS_CTRL_CR0_SHADOW, 0x20);
	set_vmcs(vcpu, VMCS_GUEST_CR4, 0x2000);
	set_vmcs(vcpu, VMCS_CTRL_CR4_MASK, ~0u);
	set_vmcs(vcpu, VMCS_CTRL_CR4_SHADOW, 0x0000);
	set_vmcs(vcpu, VMCS_GUEST_TR_AR, 0x83);
	set_vmcs(vcpu, VMCS_GUEST_LDTR_AR, 0x10000);
	set_vmcs(vcpu, VMCS_GUEST_SS, 0);
	set_vmcs(vcpu, VMCS_GUEST_SS_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_SS_LIMIT, 0xffff);
	set_vmcs(vcpu, VMCS_GUEST_SS_AR, 0x93);
	set_vmcs(vcpu, VMCS_GUEST_CS, 0);
	set_vmcs(vcpu, VMCS_GUEST_CS_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_CS_LIMIT, 0xffff);
	set_vmcs(vcpu, VMCS_GUEST_CS_AR, 0x9b);
	set_vmcs(vcpu, VMCS_GUEST_DS, 0);
	set_vmcs(vcpu, VMCS_GUEST_DS_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_DS_LIMIT, 0xffff);
	set_vmcs(vcpu, VMCS_GUEST_DS_AR, 0x93);
	set_vmcs(vcpu, VMCS_GUEST_ES, 0);
	set_vmcs(vcpu, VMCS_GUEST_ES_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_ES_LIMIT, 0xffff);
	set_vmcs(vcpu, VMCS_GUEST_ES_AR, 0x93);
	set_vmcs(vcpu, VMCS_GUEST_FS, 0);
	set_vmcs(vcpu, VMCS_GUEST_FS_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_FS_LIMIT, 0xffff);
	set_vmcs(vcpu, VMCS_GUEST_FS_AR, 0x93);
	set_vmcs(vcpu, VMCS_GUEST_GS, 0);
	set_vmcs(vcpu, VMCS_GUEST_GS_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_GS_LIMIT, 0xffff);
	set_vmcs(vcpu, VMCS_GUEST_GS_AR, 0x93);

    set_vmcs(vcpu, VMCS_GUEST_GDTR_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_GDTR_LIMIT, 0);
    set_vmcs(vcpu, VMCS_GUEST_IDTR_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_IDTR_LIMIT, 0);

    set_vmcs(vcpu, VMCS_GUEST_RFLAGS, 0x2);

	set_vmcs(vcpu, VMCS_CTRL_EXC_BITMAP, 0xffffffff);
}

static void
setup_protected_mode(hv_vcpuid_t vcpu)
{
    uint64_t pin_cap, proc_cap, proc2_cap, entry_cap, exit_cap;

    pin_cap = get_cap(HV_VMX_CAP_PINBASED);
    proc_cap = get_cap(HV_VMX_CAP_PROCBASED);
    proc2_cap = get_cap(HV_VMX_CAP_PROCBASED2);
    entry_cap = get_cap(HV_VMX_CAP_ENTRY);
    exit_cap = get_cap(HV_VMX_CAP_EXIT);

    set_vmcs(vcpu, VMCS_CTRL_PIN_BASED, canonicalize(0, pin_cap));
	set_vmcs(vcpu, VMCS_CTRL_CPU_BASED,
             canonicalize(CPU_BASED_HLT | CPU_BASED_CR8_LOAD | CPU_BASED_CR8_STORE, proc_cap));
	set_vmcs(vcpu, VMCS_CTRL_CPU_BASED2, canonicalize(0, proc2_cap));
    set_vmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS, canonicalize(0, entry_cap));
	set_vmcs(vcpu, VMCS_CTRL_VMEXIT_CONTROLS, canonicalize(0, exit_cap));

    set_vmcs(vcpu, VMCS_GUEST_CR0, 0x21);
	set_vmcs(vcpu, VMCS_CTRL_CR0_MASK, ~0u);
	set_vmcs(vcpu, VMCS_CTRL_CR0_SHADOW, 0x21);
	set_vmcs(vcpu, VMCS_GUEST_CR3, 0);
	set_vmcs(vcpu, VMCS_GUEST_CR4, 0x2000);
	set_vmcs(vcpu, VMCS_CTRL_CR4_MASK, ~0u);
	set_vmcs(vcpu, VMCS_CTRL_CR4_SHADOW, 0x0000);

    set_vmcs(vcpu, VMCS_GUEST_TR, 0);
    set_vmcs(vcpu, VMCS_GUEST_TR_AR, 0x8b);
    
	set_vmcs(vcpu, VMCS_GUEST_LDTR, 0x0);
	set_vmcs(vcpu, VMCS_GUEST_LDTR_AR, 0x10000);

	set_vmcs(vcpu, VMCS_GUEST_SS, 0x8);
	set_vmcs(vcpu, VMCS_GUEST_SS_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_SS_LIMIT, 0xffffffff);
	set_vmcs(vcpu, VMCS_GUEST_SS_AR, 0xc093);

	set_vmcs(vcpu, VMCS_GUEST_CS, 0x10);
	set_vmcs(vcpu, VMCS_GUEST_CS_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_CS_LIMIT, 0xffffffff);
	set_vmcs(vcpu, VMCS_GUEST_CS_AR, 0xc09b);

	set_vmcs(vcpu, VMCS_GUEST_DS, 0x8);
	set_vmcs(vcpu, VMCS_GUEST_DS_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_DS_LIMIT, 0xffffffff);
	set_vmcs(vcpu, VMCS_GUEST_DS_AR, 0xc093);

	set_vmcs(vcpu, VMCS_GUEST_ES, 0x8);
	set_vmcs(vcpu, VMCS_GUEST_ES_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_ES_LIMIT, 0xffffffff);
	set_vmcs(vcpu, VMCS_GUEST_ES_AR, 0xc093);

	set_vmcs(vcpu, VMCS_GUEST_FS, 0x8);
	set_vmcs(vcpu, VMCS_GUEST_FS_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_FS_LIMIT, 0xffffffff);
	set_vmcs(vcpu, VMCS_GUEST_FS_AR, 0xc093);

	set_vmcs(vcpu, VMCS_GUEST_GS, 0x8);
	set_vmcs(vcpu, VMCS_GUEST_GS_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_GS_LIMIT, 0xffffffff);
	set_vmcs(vcpu, VMCS_GUEST_GS_AR, 0xc093);

    set_vmcs(vcpu, VMCS_GUEST_GDTR_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_GDTR_LIMIT, 0);

    set_vmcs(vcpu, VMCS_GUEST_IDTR_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_IDTR_LIMIT, 0);

    set_vmcs(vcpu, VMCS_GUEST_RFLAGS, 0x2);

	set_vmcs(vcpu, VMCS_CTRL_EXC_BITMAP, 0xffffffff);
}

static void
setup_long_mode(hv_vcpuid_t vcpu)
{
    uint64_t pin_cap, proc_cap, proc2_cap, entry_cap, exit_cap;

    pin_cap = get_cap(HV_VMX_CAP_PINBASED);
    proc_cap = get_cap(HV_VMX_CAP_PROCBASED);
    proc2_cap = get_cap(HV_VMX_CAP_PROCBASED2);
    entry_cap = get_cap(HV_VMX_CAP_ENTRY);
    exit_cap = get_cap(HV_VMX_CAP_EXIT);

    set_vmcs(vcpu, VMCS_CTRL_PIN_BASED, canonicalize(0, pin_cap));
	set_vmcs(vcpu, VMCS_CTRL_CPU_BASED,
             canonicalize(CPU_BASED_HLT | CPU_BASED_CR8_LOAD | CPU_BASED_CR8_STORE, proc_cap));
	set_vmcs(vcpu, VMCS_CTRL_CPU_BASED2, canonicalize(0, proc2_cap));
    set_vmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS, canonicalize(VMENTRY_GUEST_IA32E, entry_cap));
	set_vmcs(vcpu, VMCS_CTRL_VMEXIT_CONTROLS, canonicalize(0, exit_cap));

    set_vmcs(vcpu, VMCS_GUEST_CR0, 0x80000021L);
	set_vmcs(vcpu, VMCS_CTRL_CR0_MASK, ~0u);
	set_vmcs(vcpu, VMCS_CTRL_CR0_SHADOW, 0x80000021L);
	set_vmcs(vcpu, VMCS_GUEST_CR4, 0x2020);
	set_vmcs(vcpu, VMCS_CTRL_CR4_MASK, ~0u);
	set_vmcs(vcpu, VMCS_CTRL_CR4_SHADOW, 0x2020);

    set_vmcs(vcpu, VMCS_GUEST_IA32_EFER, 0x500);

    T_QUIET; T_ASSERT_EQ(hv_vcpu_enable_native_msr(vcpu, MSR_IA32_KERNEL_GS_BASE, true), HV_SUCCESS, "enable native GS_BASE");
    
    set_vmcs(vcpu, VMCS_GUEST_TR, 0);
    set_vmcs(vcpu, VMCS_GUEST_TR_AR, 0x8b);
    
	set_vmcs(vcpu, VMCS_GUEST_LDTR, 0x0);
	set_vmcs(vcpu, VMCS_GUEST_LDTR_AR, 0x10000);

	set_vmcs(vcpu, VMCS_GUEST_SS, 0x8);
	set_vmcs(vcpu, VMCS_GUEST_SS_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_SS_LIMIT, 0xffffffff);
	set_vmcs(vcpu, VMCS_GUEST_SS_AR, 0xa093);

	set_vmcs(vcpu, VMCS_GUEST_CS, 0x10);
	set_vmcs(vcpu, VMCS_GUEST_CS_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_CS_LIMIT, 0xffffffff);
	set_vmcs(vcpu, VMCS_GUEST_CS_AR, 0xa09b);

	set_vmcs(vcpu, VMCS_GUEST_DS, 0x8);
	set_vmcs(vcpu, VMCS_GUEST_DS_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_DS_LIMIT, 0xffffffff);
	set_vmcs(vcpu, VMCS_GUEST_DS_AR, 0xa093);

	set_vmcs(vcpu, VMCS_GUEST_ES, 0x8);
	set_vmcs(vcpu, VMCS_GUEST_ES_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_ES_LIMIT, 0xffffffff);
	set_vmcs(vcpu, VMCS_GUEST_ES_AR, 0xa093);

	set_vmcs(vcpu, VMCS_GUEST_FS, 0x8);
	set_vmcs(vcpu, VMCS_GUEST_FS_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_FS_LIMIT, 0xffffffff);
	set_vmcs(vcpu, VMCS_GUEST_FS_AR, 0xa093);

	set_vmcs(vcpu, VMCS_GUEST_GS, 0x8);
	set_vmcs(vcpu, VMCS_GUEST_GS_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_GS_LIMIT, 0xffffffff);
	set_vmcs(vcpu, VMCS_GUEST_GS_AR, 0xa093);

    set_vmcs(vcpu, VMCS_GUEST_RFLAGS, 0x2);

    set_vmcs(vcpu, VMCS_CTRL_EXC_BITMAP, 0xffffffff);

    set_vmcs(vcpu, VMCS_GUEST_CR3, pml4_gpa);

    set_vmcs(vcpu, VMCS_GUEST_GDTR_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_GDTR_LIMIT, 0);

    set_vmcs(vcpu, VMCS_GUEST_IDTR_BASE, 0);
	set_vmcs(vcpu, VMCS_GUEST_IDTR_LIMIT, 0);
}

static void *
wrap_monitor(void *param)
{
	struct test_vcpu *test = (struct test_vcpu *)param;

    T_QUIET; T_ASSERT_EQ(hv_vcpu_create(&test->vcpu, HV_VCPU_DEFAULT), HV_SUCCESS,
	    "created vcpu");

	const size_t stack_size = 0x4000;
	void *stack_bottom = valloc(stack_size);
	T_QUIET; T_ASSERT_NOTNULL(stack_bottom, "allocate VCPU stack");
	vcpu_entry_function entry = test->guest_func;

    set_vmcs(test->vcpu, VMCS_GUEST_RIP, (uintptr_t)entry);
	set_vmcs(test->vcpu, VMCS_GUEST_RSP, (uintptr_t)stack_bottom + stack_size);
	set_reg(test->vcpu, HV_X86_RDI, test->guest_param);

	void *result = test->monitor_func(test->monitor_param, test->vcpu);

	T_QUIET; T_ASSERT_EQ(hv_vcpu_destroy(test->vcpu), HV_SUCCESS, "Destroyed vcpu");
	free(stack_bottom);
	free(test);
	return result;
}

static pthread_t
create_vcpu_thread(
    vcpu_entry_function guest_function, uint64_t guest_param,
    vcpu_monitor_function monitor_func, void *monitor_param)
{

	pthread_t thread;
	struct test_vcpu *test = malloc(sizeof(*test));
    T_QUIET; T_ASSERT_NOTNULL(test, "malloc test params");
	test->guest_func = guest_function;
	test->guest_param = guest_param;
	test->monitor_func = monitor_func;
	test->monitor_param = monitor_param;
	T_ASSERT_POSIX_SUCCESS(pthread_create(&thread, NULL, wrap_monitor, test),
	    "create vcpu pthread");
	// ownership of test struct moves to the thread
	test = NULL;

	return thread;
}

static void
vm_setup()
{
	T_SETUPBEGIN;

	if (hv_support() < 1) {
		T_SKIP("Running on non-HV target, skipping...");
		return;
	}

	page_cache = [[NSMutableDictionary alloc] init];
	allocated_phys_pages = [[NSMutableSet alloc] init];

	T_ASSERT_EQ(hv_vm_create(HV_VM_DEFAULT), HV_SUCCESS, "Created vm");


    // Set up root paging structures for long mode,
    // where paging is mandatory.

    pml4_gpa = map_guest_phys((void**)&pml4);
    memset(pml4, 0, vm_page_size);

    T_SETUPEND;
}

static void
vm_cleanup()
{
    T_ASSERT_EQ(hv_vm_destroy(), HV_SUCCESS, "Destroyed vm");
	free_page_cache();
}

static pthread_cond_t ready_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t vcpus_ready_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t vcpus_initializing;
static pthread_mutex_t vcpus_hang_lock = PTHREAD_MUTEX_INITIALIZER;

static void *
multikill_vcpu_thread_function(void __unused *arg)
{
 	hv_vcpuid_t *vcpu = (hv_vcpuid_t*)arg;

    T_QUIET; T_ASSERT_EQ(hv_vcpu_create(vcpu, HV_VCPU_DEFAULT), HV_SUCCESS,
                         "created vcpu");

	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_lock(&vcpus_ready_lock),
	    "acquire vcpus_ready_lock");
	T_QUIET; T_ASSERT_NE(vcpus_initializing, 0, "check for vcpus_ready underflow");
	vcpus_initializing--;
	if (vcpus_initializing == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_cond_signal(&ready_cond),
		    "signaling all VCPUs ready");
	}
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_unlock(&vcpus_ready_lock),
	    "release vcpus_ready_lock");

	// To cause the VCPU pointer to be cleared from the wrong thread, we need
	// to get threads onto the thread deallocate queue. One way to accomplish
	// this is to die while waiting for a lock.
	T_ASSERT_POSIX_SUCCESS(pthread_mutex_lock(&vcpus_hang_lock),
	    "acquire vcpus_hang_lock");

	// Do not allow the thread to terminate. Exactly one thread will acquire
	// the above lock successfully.
	while (true) {
		pause();
	}

	return NULL;
}

T_DECL(regression_55524541,
	"kill task with multiple VCPU threads waiting for lock")
{
	if (!hv_support()) {
		T_SKIP("no HV support");
	}

	int pipedesc[2];
	T_ASSERT_POSIX_SUCCESS(pipe(pipedesc), "create pipe");

	pid_t child = fork();
	if (child == 0) {
		const uint32_t vcpu_count = 8;
		pthread_t vcpu_threads[8];
		T_ASSERT_EQ(hv_vm_create(HV_VM_DEFAULT), HV_SUCCESS, "created vm");
		vcpus_initializing = vcpu_count;
		for (uint32_t i = 0; i < vcpu_count; i++) {
            hv_vcpuid_t vcpu;

			T_ASSERT_POSIX_SUCCESS(pthread_create(&vcpu_threads[i], NULL,
			    multikill_vcpu_thread_function, (void *)&vcpu),
				"create vcpu_threads[%u]", i);
		}

		T_ASSERT_POSIX_SUCCESS(pthread_mutex_lock(&vcpus_ready_lock),
		    "acquire vcpus_ready_lock");
		while (vcpus_initializing != 0) {
			T_ASSERT_POSIX_SUCCESS(pthread_cond_wait(&ready_cond,
			    &vcpus_ready_lock), "wait for all threads ready");
		}
		T_ASSERT_POSIX_SUCCESS(pthread_mutex_unlock(&vcpus_ready_lock),
		    "release vcpus_ready_lock");

		// Indicate readiness to die, meditiate peacefully.
		uint8_t byte = 0;
		T_ASSERT_EQ_LONG(write(pipedesc[1], &byte, 1), 1L, "notifying on pipe");
		while (true) {
			pause();
		}
	} else {
		T_ASSERT_GT(child, 0, "successful fork");
		// Wait for child to prepare.
		uint8_t byte;
		T_ASSERT_EQ_LONG(read(pipedesc[0], &byte, 1), 1L, "waiting on pipe");
		T_ASSERT_POSIX_SUCCESS(kill(child, SIGTERM), "kill child");
		// Hope for no panic...
		T_ASSERT_POSIX_SUCCESS(wait(NULL), "reap child");
	}
	T_ASSERT_POSIX_SUCCESS(close(pipedesc[0]), "close pipedesc[0]");
	T_ASSERT_POSIX_SUCCESS(close(pipedesc[1]), "close pipedesc[1]");
}

static void *
simple_long_mode_monitor(void *arg __unused, hv_vcpuid_t vcpu)
{
    setup_long_mode(vcpu);

    expect_vmcall_with_value(vcpu, 0x33456, true);

    return NULL;
}

T_DECL(simple_long_mode_guest, "simple long mode guest")
{
    vm_setup();

    pthread_t vcpu_thread = create_vcpu_thread(simple_long_mode_vcpu_entry, 0x10000, simple_long_mode_monitor, 0);
	T_ASSERT_POSIX_SUCCESS(pthread_join(vcpu_thread, NULL), "join vcpu");

	vm_cleanup();
}

static void *
smp_test_monitor(void *arg __unused, hv_vcpuid_t vcpu)
{
    setup_long_mode(vcpu);

	uint64_t value = expect_vmcall(vcpu, true);
	return (void *)(uintptr_t)value;
}

T_DECL(smp_sanity, "Multiple VCPUs in the same VM")
{
	vm_setup();

	// Use this region as shared memory between the VCPUs.
	void *shared = NULL;
    map_guest_phys((void**)&shared);

	atomic_uint *count_word = (atomic_uint *)shared;
	atomic_init(count_word, 0);

	pthread_t vcpu1_thread = create_vcpu_thread(smp_vcpu_entry,
	    (uintptr_t)count_word, smp_test_monitor, count_word);
	pthread_t vcpu2_thread = create_vcpu_thread(smp_vcpu_entry,
	    (uintptr_t)count_word, smp_test_monitor, count_word);

	void *r1, *r2;
	T_ASSERT_POSIX_SUCCESS(pthread_join(vcpu1_thread, &r1), "join vcpu1");
	T_ASSERT_POSIX_SUCCESS(pthread_join(vcpu2_thread, &r2), "join vcpu2");
	uint64_t v1 = (uint64_t)r1;
	uint64_t v2 = (uint64_t)r2;
	if (v1 == 0) {
		T_ASSERT_EQ_ULLONG(v2, 1ULL, "check count");
	} else if (v1 == 1) {
		T_ASSERT_EQ_ULLONG(v2, 0ULL, "check count");
	} else {
		T_FAIL("unexpected count: %llu", v1);
	}

	vm_cleanup();
}


extern void *hvtest_begin;
extern void *hvtest_end;

static void *
simple_protected_mode_test_monitor(void *arg __unused, hv_vcpuid_t vcpu)
{
    setup_protected_mode(vcpu);

    size_t guest_pages_size = round_page((uintptr_t)&hvtest_end - (uintptr_t)&hvtest_begin);

    const size_t mem_size = 1 * 1024 * 1024;
    uint8_t *guest_pages_shadow = valloc(mem_size);

    bzero(guest_pages_shadow, mem_size);
    memcpy(guest_pages_shadow+0x1000, &hvtest_begin, guest_pages_size);

    T_ASSERT_EQ(hv_vm_map(guest_pages_shadow, 0x40000000, mem_size, HV_MEMORY_READ | HV_MEMORY_EXEC),
                HV_SUCCESS, "map guest memory");

    expect_vmcall_with_value(vcpu, 0x23456, false);

    free(guest_pages_shadow);

    return NULL;
}

T_DECL(simple_protected_mode_guest, "simple protected mode guest")
{
    vm_setup();

    pthread_t vcpu_thread = create_vcpu_thread((vcpu_entry_function)
                                               (((uintptr_t)simple_protected_mode_vcpu_entry & PAGE_MASK) +
                                                0x40000000 + 0x1000),
                                               0, simple_protected_mode_test_monitor, 0);
	T_ASSERT_POSIX_SUCCESS(pthread_join(vcpu_thread, NULL), "join vcpu");

	vm_cleanup();
}

static void *
simple_real_mode_monitor(void *arg __unused, hv_vcpuid_t vcpu)
{
    setup_real_mode(vcpu);

    size_t guest_pages_size = round_page((uintptr_t)&hvtest_end - (uintptr_t)&hvtest_begin);

    const size_t mem_size = 1 * 1024 * 1024;
    uint8_t *guest_pages_shadow = valloc(mem_size);

    bzero(guest_pages_shadow, mem_size);
    memcpy(guest_pages_shadow+0x1000, &hvtest_begin, guest_pages_size);

    T_ASSERT_EQ(hv_vm_map(guest_pages_shadow, 0x0, mem_size, HV_MEMORY_READ | HV_MEMORY_EXEC), HV_SUCCESS,
                "map guest memory");

    expect_vmcall_with_value(vcpu, 0x23456, false);

    free(guest_pages_shadow);

    return NULL;
}

T_DECL(simple_real_mode_guest, "simple real mode guest")
{
    vm_setup();

    pthread_t vcpu_thread = create_vcpu_thread((vcpu_entry_function)
                                               (((uintptr_t)simple_real_mode_vcpu_entry & PAGE_MASK) +
                                                0x1000),
                                               0, simple_real_mode_monitor, 0);
	T_ASSERT_POSIX_SUCCESS(pthread_join(vcpu_thread, NULL), "join vcpu");

	vm_cleanup();
}

static void *
radar61961809_monitor(void *gpaddr, hv_vcpuid_t vcpu)
{
	uint32_t const gdt_template[] = {
		0, 0,                         /* Empty */
		0x0000ffff, 0x00cf9200,       /* 0x08 CPL0 4GB writable data, 32bit */
		0x0000ffff, 0x00cf9a00,       /* 0x10 CPL0 4GB readable code, 32bit */
		0x0000ffff, 0x00af9200,       /* 0x18 CPL0 4GB writable data, 64bit */
		0x0000ffff, 0x00af9a00,       /* 0x20 CPL0 4GB readable code, 64bit */
	};

	// We start the test in protected mode.
    setup_protected_mode(vcpu);

	// SAVE_EFER makes untrapped CR0.PG work.
    uint64_t exit_cap = get_cap(HV_VMX_CAP_EXIT);
	set_vmcs(vcpu, VMCS_CTRL_VMEXIT_CONTROLS, canonicalize(VMEXIT_SAVE_EFER, exit_cap));

	// Start with CR0.PG disabled.
	set_vmcs(vcpu, VMCS_GUEST_CR0, 0x00000021);
	set_vmcs(vcpu, VMCS_CTRL_CR0_SHADOW, 0x00000021);
	/*
	 * Don't trap on modifying CR0.PG to reproduce the problem.
	 * Otherwise, we'd have to handle the switch ourselves, and would
	 * just do it right.
	 */
	set_vmcs(vcpu, VMCS_CTRL_CR0_MASK, ~0x80000000UL);

	// PAE must be enabled for a switch into long mode to work.
	set_vmcs(vcpu, VMCS_GUEST_CR4, 0x2020);
	set_vmcs(vcpu, VMCS_CTRL_CR4_MASK, ~0u);
	set_vmcs(vcpu, VMCS_CTRL_CR4_SHADOW, 0x2020);

	// Will use the harness managed page tables in long mode.
	set_vmcs(vcpu, VMCS_GUEST_CR3, pml4_gpa);

	// Hypervisor fw wants this (for good, but unrelated reason).
	T_QUIET; T_ASSERT_EQ(hv_vcpu_enable_native_msr(vcpu, MSR_IA32_KERNEL_GS_BASE, true), HV_SUCCESS, "enable native GS_BASE");

	// Far pointer array for our far jumps.
	uint32_t *far_ptr = NULL;
	hv_gpaddr_t far_ptr_gpaddr = map_guest_phys((void**)&far_ptr);
	map_page(far_ptr, (void*)far_ptr_gpaddr);

	far_ptr[0] = (uint32_t)(((uintptr_t)&radar61961809_prepare - (uintptr_t)&hvtest_begin) + (uintptr_t)gpaddr);
	far_ptr[1] = 0x0010; // 32bit CS
	far_ptr[2] = (uint32_t)(((uintptr_t)&radar61961809_loop64 - (uintptr_t)&hvtest_begin) + (uintptr_t)gpaddr);
	far_ptr[3] = 0x0020; // 64bit CS

	set_reg(vcpu, HV_X86_RDI, far_ptr_gpaddr);

	// Setup GDT.
	uint32_t *gdt = valloc(vm_page_size);
	hv_gpaddr_t gdt_gpaddr = 0x70000000;
	map_page(gdt, (void*)gdt_gpaddr);
	bzero(gdt, vm_page_size);
	memcpy(gdt, gdt_template, sizeof(gdt_template));

	set_vmcs(vcpu, VMCS_GUEST_GDTR_BASE, gdt_gpaddr);
	set_vmcs(vcpu, VMCS_GUEST_GDTR_LIMIT, sizeof(gdt_template)+1);

	// Map test code (because we start in protected mode without
	// paging, we cannot use the harness's fault management yet.)
	size_t guest_pages_size = round_page((uintptr_t)&hvtest_end - (uintptr_t)&hvtest_begin);

	const size_t mem_size = 1 * 1024 * 1024;
	uint8_t *guest_pages_shadow = valloc(mem_size);

	bzero(guest_pages_shadow, mem_size);
	memcpy(guest_pages_shadow, &hvtest_begin, guest_pages_size);

	T_ASSERT_EQ(hv_vm_map(guest_pages_shadow, (hv_gpaddr_t)gpaddr, mem_size, HV_MEMORY_READ | HV_MEMORY_EXEC),
		HV_SUCCESS, "map guest memory");

	// Create entries in PML4.
	uint8_t *host_va = guest_pages_shadow;
	uint8_t *va = (uint8_t*)gpaddr;
	for (unsigned long i = 0; i < guest_pages_size / vm_page_size; i++, va += vm_page_size, host_va += vm_page_size) {
		map_page(host_va, va);
	}

	uint64_t reason = run_to_next_vm_fault(vcpu, false);
	T_ASSERT_EQ(reason, (uint64_t)VMX_REASON_RDMSR, "check for rdmsr");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_RCX), 0xc0000080LL, "expected EFER rdmsr");

	set_reg(vcpu, HV_X86_RDX, 0);
	set_reg(vcpu, HV_X86_RAX, 0);
    set_vmcs(vcpu, VMCS_GUEST_RIP, get_reg(vcpu, HV_X86_RIP)+get_vmcs(vcpu, VMCS_RO_VMEXIT_INSTR_LEN));

	reason = run_to_next_vm_fault(vcpu, false);
	T_ASSERT_EQ(reason, (uint64_t)VMX_REASON_WRMSR, "check for wrmsr");
	T_ASSERT_EQ(get_reg(vcpu, HV_X86_RCX), 0xc0000080LL, "expected EFER wrmsr");
	T_ASSERT_EQ(get_reg(vcpu, HV_X86_RDX), 0x0LL, "expected EFER wrmsr higher bits 0");
	T_ASSERT_EQ(get_reg(vcpu, HV_X86_RAX), 0x100LL, "expected EFER wrmsr lower bits LME");

	set_vmcs(vcpu, VMCS_GUEST_IA32_EFER, 0x100);
	set_vmcs(vcpu, VMCS_GUEST_RIP, get_reg(vcpu, HV_X86_RIP)+get_vmcs(vcpu, VMCS_RO_VMEXIT_INSTR_LEN));

	// See assembly part of the test for checkpoints.
	expect_vmcall_with_value(vcpu, 0x100, false /* PG disabled =>
												 * no PFs expected */);
	expect_vmcall_with_value(vcpu, 0x1111, true /* PG now enabled */);
	expect_vmcall_with_value(vcpu, 0x2222, true);

	free(guest_pages_shadow);
	free(gdt);

    return NULL;
}

T_DECL(radar61961809_guest,
	"rdar://61961809 (Unexpected guest faults with hv_vcpu_run_until, dropping out of long mode)")
{
    vm_setup();

	hv_gpaddr_t gpaddr = 0x80000000;
    pthread_t vcpu_thread = create_vcpu_thread((vcpu_entry_function)
		(((uintptr_t)radar61961809_entry & PAGE_MASK) +
			gpaddr),
		0, radar61961809_monitor, (void*)gpaddr);
	T_ASSERT_POSIX_SUCCESS(pthread_join(vcpu_thread, NULL), "join vcpu");

	vm_cleanup();
}

static void *
superpage_2mb_backed_guest_monitor(void *arg __unused, hv_vcpuid_t vcpu)
{
    setup_protected_mode(vcpu);

    size_t guest_pages_size = round_page((uintptr_t)&hvtest_end - (uintptr_t)&hvtest_begin);

    const size_t mem_size = 2 * 1024 * 1024;

    uint8_t *guest_pages_shadow = mmap(NULL, mem_size,
                                       PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE,
                                       VM_FLAGS_SUPERPAGE_SIZE_2MB, 0);

    if (guest_pages_shadow == MAP_FAILED) {
        /* Getting a 2MB superpage is hard in practice, because memory gets fragmented
         * easily.
         * T_META_REQUIRES_REBOOT in the T_DECL helps a lot in actually getting a page,
         * but in the case that it still fails, we don't want the test to fail through
         * no fault of the hypervisor.
         */
        T_SKIP("Unable to attain a 2MB superpage. Skipping.");
    }

    bzero(guest_pages_shadow, mem_size);
    memcpy(guest_pages_shadow+0x1000, &hvtest_begin, guest_pages_size);

    T_ASSERT_EQ(hv_vm_map(guest_pages_shadow, 0x40000000, mem_size, HV_MEMORY_READ | HV_MEMORY_EXEC),
                HV_SUCCESS, "map guest memory");

    expect_vmcall_with_value(vcpu, 0x23456, false);

    munmap(guest_pages_shadow, mem_size);

    return NULL;
}

T_DECL(superpage_2mb_backed_guest, "guest backed by a 2MB superpage",
       T_META_REQUIRES_REBOOT(true)) // Helps actually getting a superpage
{
    vm_setup();

    pthread_t vcpu_thread = create_vcpu_thread((vcpu_entry_function)
                                               (((uintptr_t)simple_protected_mode_vcpu_entry & PAGE_MASK) +
                                                0x40000000 + 0x1000),
                                               0, superpage_2mb_backed_guest_monitor, 0);
	T_ASSERT_POSIX_SUCCESS(pthread_join(vcpu_thread, NULL), "join vcpu");

	vm_cleanup();
}

static void *
save_restore_regs_monitor(void *arg __unused, hv_vcpuid_t vcpu)
{

    setup_long_mode(vcpu);

    uint64_t rsp = get_reg(vcpu, HV_X86_RSP);

    set_reg(vcpu, HV_X86_RAX, 0x0101010101010101);
    set_reg(vcpu, HV_X86_RBX, 0x0202020202020202);
    set_reg(vcpu, HV_X86_RCX, 0x0303030303030303);
    set_reg(vcpu, HV_X86_RDX, 0x0404040404040404);
    set_reg(vcpu, HV_X86_RSI, 0x0505050505050505);
    set_reg(vcpu, HV_X86_RDI, 0x0606060606060606);

    set_reg(vcpu, HV_X86_RBP, 0x0707070707070707);

    set_reg(vcpu, HV_X86_R8, 0x0808080808080808);
    set_reg(vcpu, HV_X86_R9, 0x0909090909090909);
    set_reg(vcpu, HV_X86_R10, 0x0a0a0a0a0a0a0a0a);
    set_reg(vcpu, HV_X86_R11, 0x0b0b0b0b0b0b0b0b);
    set_reg(vcpu, HV_X86_R12, 0x0c0c0c0c0c0c0c0c);
    set_reg(vcpu, HV_X86_R13, 0x0d0d0d0d0d0d0d0d);
    set_reg(vcpu, HV_X86_R14, 0x0e0e0e0e0e0e0e0e);
    set_reg(vcpu, HV_X86_R15, 0x0f0f0f0f0f0f0f0f);

    // invalid selectors: ok as long as we don't try to use them
    set_reg(vcpu, HV_X86_DS, 0x1010);
    set_reg(vcpu, HV_X86_ES, 0x2020);
    set_reg(vcpu, HV_X86_FS, 0x3030);
    set_reg(vcpu, HV_X86_GS, 0x4040);

    expect_vmcall_with_value(vcpu, (uint64_t)~0x0101010101010101LL, true);

    T_ASSERT_EQ(get_reg(vcpu, HV_X86_RSP), rsp-8, "check if push happened");

    T_ASSERT_EQ(get_reg(vcpu, HV_X86_RAX), (uint64_t)~0x0101010101010101LL, "check if RAX negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_RBX), (uint64_t)~0x0202020202020202LL, "check if RBX negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_RCX), (uint64_t)~0x0303030303030303LL, "check if RCX negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_RDX), (uint64_t)~0x0404040404040404LL, "check if RDX negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_RSI), (uint64_t)~0x0505050505050505LL, "check if RSI negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_RDI), (uint64_t)~0x0606060606060606LL, "check if RDI negated");

    T_ASSERT_EQ(get_reg(vcpu, HV_X86_RBP), (uint64_t)~0x0707070707070707LL, "check if RBP negated");

    T_ASSERT_EQ(get_reg(vcpu, HV_X86_R8), (uint64_t)~0x0808080808080808LL, "check if R8 negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_R9), (uint64_t)~0x0909090909090909LL, "check if R9 negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_R10), (uint64_t)~0x0a0a0a0a0a0a0a0aLL, "check if R10 negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_R11), (uint64_t)~0x0b0b0b0b0b0b0b0bLL, "check if R11 negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_R12), (uint64_t)~0x0c0c0c0c0c0c0c0cLL, "check if R12 negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_R13), (uint64_t)~0x0d0d0d0d0d0d0d0dLL, "check if R13 negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_R14), (uint64_t)~0x0e0e0e0e0e0e0e0eLL, "check if R14 negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_R15), (uint64_t)~0x0f0f0f0f0f0f0f0fLL, "check if R15 negated");

    T_ASSERT_EQ(get_reg(vcpu, HV_X86_RAX), (uint64_t)~0x0101010101010101LL, "check if RAX negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_RBX), (uint64_t)~0x0202020202020202LL, "check if RBX negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_RCX), (uint64_t)~0x0303030303030303LL, "check if RCX negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_RDX), (uint64_t)~0x0404040404040404LL, "check if RDX negated");

    // Cannot set selector to arbitrary value from the VM, but we have the RPL field to play with
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_DS), 1ULL, "check if DS == 1");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_ES), 2ULL, "check if ES == 2");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_FS), 3ULL, "check if FS == 3");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_GS), 1ULL, "check if GS == 1");

    expect_vmcall_with_value(vcpu, (uint64_t)~0x0101010101010101LL, true);

    T_ASSERT_EQ(get_reg(vcpu, HV_X86_RSP), rsp-16, "check if push happened again");

    return NULL;
}

T_DECL(save_restore_regs, "check if general purpose and segment registers are properly saved and restored")
{
    vm_setup();

    pthread_t vcpu_thread = create_vcpu_thread(save_restore_regs_entry, 0x10000, save_restore_regs_monitor, 0);
	T_ASSERT_POSIX_SUCCESS(pthread_join(vcpu_thread, NULL), "join vcpu");

	vm_cleanup();
}

static void *
save_restore_debug_regs_monitor(void *arg __unused, hv_vcpuid_t vcpu)
{

    setup_long_mode(vcpu);

    set_reg(vcpu, HV_X86_RAX, 0x0101010101010101);

    set_reg(vcpu, HV_X86_DR0, 0x1111111111111111);
    set_reg(vcpu, HV_X86_DR1, 0x2222222222222222);
    set_reg(vcpu, HV_X86_DR2, 0x3333333333333333);
    set_reg(vcpu, HV_X86_DR3, 0x4444444444444444);

    // debug status and control regs (some bits are reserved, one other bit would generate an exception)
    const uint64_t dr6_force_clear = 0xffffffff00001000ULL;
    const uint64_t dr6_force_set = 0xffff0ff0ULL;
    const uint64_t dr7_force_clear = 0xffffffff0000f000ULL;
    const uint64_t dr7_force_set = 0x0400ULL;

    set_reg(vcpu, HV_X86_DR6, (0x5555555555555555ULL | dr6_force_set) & ~(dr6_force_clear));
    set_reg(vcpu, HV_X86_DR7, (0x5555555555555555ULL | dr7_force_set) & ~(dr7_force_clear));

    expect_vmcall_with_value(vcpu, 0x0101010101010101LL, true);

    T_ASSERT_EQ(get_reg(vcpu, HV_X86_DR0), (uint64_t)~0x1111111111111111LL, "check if DR0 negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_DR1), (uint64_t)~0x2222222222222222LL, "check if DR1 negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_DR2), (uint64_t)~0x3333333333333333LL, "check if DR2 negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_DR3), (uint64_t)~0x4444444444444444LL, "check if DR3 negated");

    T_ASSERT_EQ(get_reg(vcpu, HV_X86_DR6), (0xaaaaaaaaaaaaaaaaULL | dr6_force_set) & ~(dr6_force_clear), "check if DR6 negated");
    T_ASSERT_EQ(get_reg(vcpu, HV_X86_DR7), (0xaaaaaaaaaaaaaaaaULL | dr7_force_set) & ~(dr7_force_clear), "check if DR7 negated");

    expect_vmcall_with_value(vcpu, 0x0101010101010101LL, true);

    return NULL;
}

T_DECL(save_restore_debug_regs, "check if debug registers are properly saved and restored",
       T_META_EXPECTFAIL("rdar://57433961 (SEED: Web: Writes to debug registers (DR0 etc.) are not saved)"))
{
    vm_setup();

    pthread_t vcpu_thread = create_vcpu_thread(save_restore_debug_regs_entry, 0x10000, save_restore_debug_regs_monitor, 0);
	T_ASSERT_POSIX_SUCCESS(pthread_join(vcpu_thread, NULL), "join vcpu");

	vm_cleanup();
}

#define T_NATIVE_MSR(msr)

static void *
native_msr_monitor(void *arg __unused, hv_vcpuid_t vcpu)
{
    const uint32_t msrs[] = {
        MSR_IA32_STAR,
        MSR_IA32_LSTAR,
        MSR_IA32_CSTAR,
        MSR_IA32_FMASK,
        MSR_IA32_KERNEL_GS_BASE,
        MSR_IA32_TSC,
        MSR_IA32_TSC_AUX,

        MSR_IA32_SYSENTER_CS,
        MSR_IA32_SYSENTER_ESP,
        MSR_IA32_SYSENTER_EIP,
        MSR_IA32_FS_BASE,
        MSR_IA32_GS_BASE,
    };
    const int msr_count = sizeof(msrs)/sizeof(uint32_t);

    setup_long_mode(vcpu);

    for (int i = 0; i < msr_count; i++) {
        T_ASSERT_EQ(hv_vcpu_enable_native_msr(vcpu, msrs[i], true), HV_SUCCESS, "enable native MSR %x", msrs[i]);
    }

    expect_vmcall_with_value(vcpu, 0x23456, true);

    return NULL;
}

T_DECL(native_msr_clobber, "enable and clobber native MSRs in the guest")
{
    vm_setup();

    pthread_t vcpu_thread = create_vcpu_thread(native_msr_vcpu_entry, 0x10000, native_msr_monitor, 0);
	T_ASSERT_POSIX_SUCCESS(pthread_join(vcpu_thread, NULL), "join vcpu");

	vm_cleanup();
}

static void *
radar60691363_monitor(void *arg __unused, hv_vcpuid_t vcpu)
{
    setup_long_mode(vcpu);

    uint64_t proc2_cap = get_cap(HV_VMX_CAP_PROCBASED2);
	set_vmcs(vcpu, VMCS_CTRL_CPU_BASED2, canonicalize(CPU_BASED2_VMCS_SHADOW, proc2_cap));

	T_ASSERT_EQ(hv_vmx_vcpu_set_shadow_access(vcpu, VMCS_GUEST_ES,
			HV_SHADOW_VMCS_READ | HV_SHADOW_VMCS_WRITE), HV_SUCCESS,
		"enable VMCS_GUEST_ES shadow access");
	T_ASSERT_EQ(hv_vmx_vcpu_write_shadow_vmcs(vcpu, VMCS_GUEST_ES, 0x1234), HV_SUCCESS,
		"set VMCS_GUEST_ES in shadow");

	T_ASSERT_EQ(hv_vmx_vcpu_set_shadow_access(vcpu, VMCS_RO_EXIT_QUALIFIC,
			HV_SHADOW_VMCS_READ | HV_SHADOW_VMCS_WRITE), HV_SUCCESS,
		"enable VMCS_RO_EXIT_QUALIFIC shadow access");
	T_ASSERT_EQ(hv_vmx_vcpu_write_shadow_vmcs(vcpu, VMCS_RO_EXIT_QUALIFIC, 0x111), HV_SUCCESS,
		"set VMCS_RO_EXIT_QUALIFIC in shadow");

	T_ASSERT_EQ(hv_vmx_vcpu_set_shadow_access(vcpu, VMCS_RO_IO_RCX,
			HV_SHADOW_VMCS_READ | HV_SHADOW_VMCS_WRITE), HV_SUCCESS,
		"enable VMCS_RO_IO_RCX shadow access");
	T_ASSERT_EQ(hv_vmx_vcpu_write_shadow_vmcs(vcpu, VMCS_RO_IO_RCX, 0x2323), HV_SUCCESS,
		"set VMCS_RO_IO_RCX in shadow");

    expect_vmcall_with_value(vcpu, 0x1234, true);
	expect_vmcall_with_value(vcpu, 0x111, true);
	expect_vmcall_with_value(vcpu, 0x2323, true);

	expect_vmcall_with_value(vcpu, 0x4567, true);

	uint64_t value;
	T_ASSERT_EQ(hv_vmx_vcpu_read_shadow_vmcs(vcpu, VMCS_GUEST_ES, &value), HV_SUCCESS,
		"read updated VMCS_GUEST_ES in shadow");
	T_ASSERT_EQ(value, 0x9191LL, "VMCS_GUEST_ES value is updated");
	T_ASSERT_EQ(hv_vmx_vcpu_read_shadow_vmcs(vcpu, VMCS_RO_EXIT_QUALIFIC, &value), HV_SUCCESS,
		"read updated VMCS_RO_EXIT_QUALIFIC in shadow");
	T_ASSERT_EQ(value, 0x9898LL, "VMCS_RO_EXIT_QUALIFIC value is updated");
	T_ASSERT_EQ(hv_vmx_vcpu_read_shadow_vmcs(vcpu, VMCS_RO_IO_RCX, &value), HV_SUCCESS,
		"read updated VMCS_RO_IO_RCX in shadow");
	T_ASSERT_EQ(value, 0x7979LL, "VMCS_RO_IO_RCX value is updated");

	// This must not work.
	T_ASSERT_EQ(hv_vmx_vcpu_set_shadow_access(vcpu, VMCS_CTRL_EPTP,
			HV_SHADOW_VMCS_READ | HV_SHADOW_VMCS_WRITE), HV_SUCCESS,
		"enable VMCS_CTRL_EPTP shadow access");
	T_ASSERT_EQ(hv_vmx_vcpu_read_vmcs(vcpu, VMCS_CTRL_EPTP, &value), HV_BAD_ARGUMENT,
		"accessing EPTP in ordinary VMCS fails");

    return NULL;
}

T_DECL(radar60691363, "rdar://60691363 (SEED: Web: Allow shadowing of read only VMCS fields)")
{
	vm_setup();

	uint64_t proc2_cap = get_cap(HV_VMX_CAP_PROCBASED2);

	if (!(proc2_cap & ((uint64_t)CPU_BASED2_VMCS_SHADOW << 32))) {
		T_SKIP("Device does not support shadow VMCS, skipping.");
	}

	pthread_t vcpu_thread = create_vcpu_thread(radar60691363_entry, 0x10000, radar60691363_monitor, 0);
	T_ASSERT_POSIX_SUCCESS(pthread_join(vcpu_thread, NULL), "join vcpu");

	vm_cleanup();
}

T_DECL(radar63641279, "rdar://63641279 (Evaluate \"no SMT\" scheduling option/sidechannel security mitigation for Hypervisor.framework VMs)")
{
	const uint64_t ALL_MITIGATIONS =
	    HV_VM_MITIGATION_A_ENABLE |
	    HV_VM_MITIGATION_B_ENABLE |
	    HV_VM_MITIGATION_C_ENABLE |
	    HV_VM_MITIGATION_D_ENABLE |
	    HV_VM_MITIGATION_E_ENABLE; // NO_SMT

	T_SETUPBEGIN;

	if (hv_support() < 1) {
		T_SKIP("Running on non-HV target, skipping...");
		return;
	}

	T_ASSERT_EQ(hv_vm_create( HV_VM_SPECIFY_MITIGATIONS | ALL_MITIGATIONS),
	    HV_SUCCESS, "Created vm");

	T_SETUPEND;

	pthread_t vcpu_thread = create_vcpu_thread(
	    (vcpu_entry_function) (((uintptr_t)simple_real_mode_vcpu_entry & PAGE_MASK) + 0x1000),
	    0, simple_real_mode_monitor, 0);
	T_ASSERT_POSIX_SUCCESS(pthread_join(vcpu_thread, NULL), "join vcpu");

	vm_cleanup();
}
