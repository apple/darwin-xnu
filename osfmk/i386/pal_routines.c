/*
 * Copyright (c) 2009-2010 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

/*
 * file: pal_routines.c
 *       Platform Abstraction Layer routines for bare-metal i386 and x86_64
 */


#include <kern/kern_types.h>
#include <mach/mach_types.h>
#include <kern/thread.h>
#include <kern/simple_lock.h>

#include <sys/kdebug.h>
#include <machine/pal_routines.h>
#include <i386/serial_io.h>
#include <i386/lapic.h>
#include <i386/proc_reg.h>
#include <i386/misc_protos.h>
#include <i386/machine_routines.h>
#include <i386/pmap.h>

//#define PAL_DEBUG 1
#ifdef PAL_DEBUG
#define DBG(x...)       kprintf("PAL_DBG: " x)
#else
#define DBG(x...)
#endif /* PAL_DEBUG */

extern void *gPEEFIRuntimeServices;
extern void *gPEEFISystemTable;

/* nanotime conversion information */
pal_rtc_nanotime_t pal_rtc_nanotime_info = {0, 0, 0, 0, 1, 0};

/* APIC kext may use this to access xnu internal state */
struct pal_apic_table *apic_table = NULL;

decl_simple_lock_data(static, pal_efi_lock);
#ifdef __x86_64__
static pml4_entry_t IDPML4[PTE_PER_PAGE] __attribute__ ((aligned(4096)));
uint64_t        pal_efi_saved_cr0;
uint64_t        pal_efi_saved_cr3;
#endif


/* Serial routines */
int
pal_serial_init(void)
{
	return serial_init();
}

void
pal_serial_putc_nocr(char c)
{
	serial_putc(c);
}

void
pal_serial_putc(char c)
{
	serial_putc(c);
	if (c == '\n') {
		serial_putc('\r');
	}
}

int
pal_serial_getc(void)
{
	return serial_getc();
}


/* Generic routines */
void
pal_i386_init(void)
{
	simple_lock_init(&pal_efi_lock, 0);
}

void
pal_get_control_registers( pal_cr_t *cr0, pal_cr_t *cr2,
    pal_cr_t *cr3, pal_cr_t *cr4 )
{
	*cr0 = get_cr0();
	*cr2 = get_cr2();
	*cr3 = get_cr3_raw();
	*cr4 = get_cr4();
}


/*
 * define functions below here to ensure we have symbols for these,
 * even though they're not used on this platform.
 */
#undef pal_dbg_page_fault
void
pal_dbg_page_fault( thread_t thread __unused,
    user_addr_t vaddr __unused,
    kern_return_t kr __unused )
{
}

#undef pal_dbg_set_task_name
void
pal_dbg_set_task_name( task_t task __unused )
{
}

#undef pal_set_signal_delivery
void
pal_set_signal_delivery(thread_t thread __unused)
{
}

/* EFI thunks */
extern void
_pal_efi_call_in_64bit_mode_asm(uint64_t func,
    struct pal_efi_registers *efi_reg,
    void *stack_contents,
    size_t stack_contents_size);

kern_return_t
pal_efi_call_in_64bit_mode(uint64_t func,
    struct pal_efi_registers *efi_reg,
    void *stack_contents,
    size_t stack_contents_size,                        /* 16-byte multiple */
    uint64_t *efi_status)
{
	DBG("pal_efi_call_in_64bit_mode(0x%016llx, %p, %p, %lu, %p)\n",
	    func, efi_reg, stack_contents, stack_contents_size, efi_status);

	if (func == 0) {
		return KERN_INVALID_ADDRESS;
	}

	if ((efi_reg == NULL)
	    || (stack_contents == NULL)
	    || (stack_contents_size % 16 != 0)) {
		return KERN_INVALID_ARGUMENT;
	}

	if (!gPEEFISystemTable || !gPEEFIRuntimeServices) {
		return KERN_NOT_SUPPORTED;
	}

	if (func < VM_MIN_KERNEL_ADDRESS) {
		/*
		 * EFI Runtime Services must be mapped in our address
		 * space at an appropriate location.
		 */
		return KERN_INVALID_ADDRESS;
	}

	_pal_efi_call_in_64bit_mode_asm(func,
	    efi_reg,
	    stack_contents,
	    stack_contents_size);

	*efi_status = efi_reg->rax;

	return KERN_SUCCESS;
}

extern void
_pal_efi_call_in_32bit_mode_asm(uint32_t func,
    struct pal_efi_registers *efi_reg,
    void *stack_contents,
    size_t stack_contents_size);

kern_return_t
pal_efi_call_in_32bit_mode(uint32_t func,
    struct pal_efi_registers *efi_reg,
    void *stack_contents,
    size_t stack_contents_size,                        /* 16-byte multiple */
    uint32_t *efi_status)
{
	DBG("pal_efi_call_in_32bit_mode(0x%08x, %p, %p, %lu, %p)\n",
	    func, efi_reg, stack_contents, stack_contents_size, efi_status);

	if (func == 0) {
		return KERN_INVALID_ADDRESS;
	}

	if ((efi_reg == NULL)
	    || (stack_contents == NULL)
	    || (stack_contents_size % 16 != 0)) {
		return KERN_INVALID_ARGUMENT;
	}

	if (!gPEEFISystemTable || !gPEEFIRuntimeServices) {
		return KERN_NOT_SUPPORTED;
	}

	DBG("pal_efi_call_in_32bit_mode() efi_reg:\n");
	DBG("  rcx: 0x%016llx\n", efi_reg->rcx);
	DBG("  rdx: 0x%016llx\n", efi_reg->rdx);
	DBG("   r8: 0x%016llx\n", efi_reg->r8);
	DBG("   r9: 0x%016llx\n", efi_reg->r9);
	DBG("  rax: 0x%016llx\n", efi_reg->rax);

	DBG("pal_efi_call_in_32bit_mode() stack:\n");
#if PAL_DEBUG
	size_t i;
	for (i = 0; i < stack_contents_size; i += sizeof(uint32_t)) {
		uint32_t *p = (uint32_t *) ((uintptr_t)stack_contents + i);
		DBG("  %p: 0x%08x\n", p, *p);
	}
#endif

#ifdef __x86_64__
	/*
	 * Ensure no interruptions.
	 * Taking a spinlock for serialization is technically unnecessary
	 * because the EFIRuntime kext should serialize.
	 */
	boolean_t istate = ml_set_interrupts_enabled(FALSE);
	simple_lock(&pal_efi_lock, LCK_GRP_NULL);

	/*
	 * Switch to special page tables with the entire high kernel space
	 * double-mapped into the bottom 4GB.
	 *
	 * NB: We assume that all data passed exchanged with RuntimeServices is
	 * located in the 4GB of KVA based at VM_MIN_ADDRESS. In particular, kexts
	 * loaded the basement (below VM_MIN_ADDRESS) cannot pass static data.
	 * Kernel stack and heap space is OK.
	 */
	MARK_CPU_IDLE(cpu_number());
	pal_efi_saved_cr3 = get_cr3_raw();
	pal_efi_saved_cr0 = get_cr0();
	IDPML4[KERNEL_PML4_INDEX] = IdlePML4[KERNEL_PML4_INDEX];
	IDPML4[0]                 = IdlePML4[KERNEL_PML4_INDEX];
	clear_ts();
	set_cr3_raw((uint64_t) ID_MAP_VTOP(IDPML4));

	swapgs();               /* Save kernel's GS base */

	/* Set segment state ready for compatibility mode */
	set_gs(NULL_SEG);
	set_fs(NULL_SEG);
	set_es(KERNEL_DS);
	set_ds(KERNEL_DS);
	set_ss(KERNEL_DS);

	_pal_efi_call_in_32bit_mode_asm(func,
	    efi_reg,
	    stack_contents,
	    stack_contents_size);

	/* Restore NULL segment state */
	set_ss(NULL_SEG);
	set_es(NULL_SEG);
	set_ds(NULL_SEG);

	swapgs();               /* Restore kernel's GS base */

	/* Restore the 64-bit user GS base we just destroyed */
	wrmsr64(MSR_IA32_KERNEL_GS_BASE,
	    current_cpu_datap()->cpu_uber.cu_user_gs_base);

	/* End of mapping games */
	set_cr3_raw(pal_efi_saved_cr3);
	set_cr0(pal_efi_saved_cr0);
	MARK_CPU_ACTIVE(cpu_number());

	simple_unlock(&pal_efi_lock);
	ml_set_interrupts_enabled(istate);
#else
	_pal_efi_call_in_32bit_mode_asm(func,
	    efi_reg,
	    stack_contents,
	    stack_contents_size);
#endif

	*efi_status = (uint32_t)efi_reg->rax;
	DBG("pal_efi_call_in_32bit_mode() efi_status: 0x%x\n", *efi_status);

	return KERN_SUCCESS;
}

/* wind-back a syscall instruction */
void
pal_syscall_restart(thread_t thread __unused, x86_saved_state_t *state)
{
	/* work out which flavour thread it is */
	if (is_saved_state32(state)) {
		x86_saved_state32_t     *regs32;
		regs32 = saved_state32(state);

		if (regs32->cs == SYSENTER_CS || regs32->cs == SYSENTER_TF_CS) {
			regs32->eip -= 5;
		} else {
			regs32->eip -= 2;
		}
	} else {
		x86_saved_state64_t     *regs64;

		assert( is_saved_state64(state));
		regs64 = saved_state64(state);

		/* Only one instruction for 64-bit threads */
		regs64->isf.rip -= 2;
	}
}

/* Helper function to put the machine to sleep (or shutdown) */

boolean_t
pal_machine_sleep(uint8_t type_a __unused, uint8_t type_b __unused, uint32_t bit_position __unused,
    uint32_t disable_mask __unused, uint32_t enable_mask __unused)
{
	return 0;
}


/* shouldn't be used on native */
void
pal_get_kern_regs( x86_saved_state_t *state )
{
	panic( "pal_get_kern_regs called. state %p\n", state );
}

void
pal_preemption_assert(void)
{
}
