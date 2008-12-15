/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */

#include <mach/mach_types.h>
#include <mach/kern_return.h>

#include <kern/kern_types.h>
#include <kern/cpu_number.h>
#include <kern/cpu_data.h>
#include <kern/assert.h>
#include <kern/machine.h>

#include <vm/vm_map.h>
#include <vm/vm_kern.h>

#include <i386/lapic.h>
#include <i386/cpuid.h>
#include <i386/proc_reg.h>
#include <i386/machine_cpu.h>
#include <i386/misc_protos.h>
#include <i386/mp.h>
#include <i386/mtrr.h>
#include <i386/postcode.h>
#include <i386/cpu_threads.h>
#include <i386/trap.h>
#include <i386/machine_routines.h>
#include <i386/machine_check.h>

#if MACH_KDB
#include <machine/db_machdep.h>
#endif

#include <sys/kdebug.h>

#if	MP_DEBUG
#define PAUSE		delay(1000000)
#define DBG(x...)	kprintf(x)
#else
#define DBG(x...)
#define PAUSE
#endif	/* MP_DEBUG */

/* Initialize lapic_id so cpu_number() works on non SMP systems */
unsigned long	lapic_id_initdata = 0;
unsigned long	lapic_id = (unsigned long)&lapic_id_initdata;
vm_offset_t	lapic_start;

static i386_intr_func_t	lapic_intr_func[LAPIC_FUNC_TABLE_SIZE];

/* TRUE if local APIC was enabled by the OS not by the BIOS */
static boolean_t lapic_os_enabled = FALSE;

/* Base vector for local APIC interrupt sources */
int lapic_interrupt_base = LAPIC_DEFAULT_INTERRUPT_BASE;

int		lapic_to_cpu[MAX_CPUS];
int		cpu_to_lapic[MAX_CPUS];

static void
lapic_cpu_map_init(void)
{
	int	i;

	for (i = 0; i < MAX_CPUS; i++) {
		lapic_to_cpu[i] = -1;
		cpu_to_lapic[i] = -1;
	}
}

void
lapic_cpu_map(int apic_id, int cpu)
{
	cpu_to_lapic[cpu] = apic_id;
	lapic_to_cpu[apic_id] = cpu;
}

/*
 * Retrieve the local apic ID a cpu.
 *
 * Returns the local apic ID for the given processor.
 * If the processor does not exist or apic not configured, returns -1.
 */

uint32_t
ml_get_apicid(uint32_t cpu)
{
	if(cpu >= (uint32_t)MAX_CPUS)
		return 0xFFFFFFFF;	/* Return -1 if cpu too big */
	
	/* Return the apic ID (or -1 if not configured) */
	return (uint32_t)cpu_to_lapic[cpu];

}

#ifdef MP_DEBUG
static void
lapic_cpu_map_dump(void)
{
	int	i;

	for (i = 0; i < MAX_CPUS; i++) {
		if (cpu_to_lapic[i] == -1)
			continue;
		kprintf("cpu_to_lapic[%d]: %d\n",
			i, cpu_to_lapic[i]);
	}
	for (i = 0; i < MAX_CPUS; i++) {
		if (lapic_to_cpu[i] == -1)
			continue;
		kprintf("lapic_to_cpu[%d]: %d\n",
			i, lapic_to_cpu[i]);
	}
}
#endif /* MP_DEBUG */

void
lapic_init(void)
{
	int		result;
	vm_map_entry_t	entry;
	uint32_t	lo;
	uint32_t	hi;
	boolean_t	is_boot_processor;
	boolean_t	is_lapic_enabled;
	vm_offset_t	lapic_base;

	/* Examine the local APIC state */
	rdmsr(MSR_IA32_APIC_BASE, lo, hi);
	is_boot_processor = (lo & MSR_IA32_APIC_BASE_BSP) != 0;
	is_lapic_enabled  = (lo & MSR_IA32_APIC_BASE_ENABLE) != 0;
	lapic_base = (lo &  MSR_IA32_APIC_BASE_BASE);
	kprintf("MSR_IA32_APIC_BASE 0x%x %s %s\n", lapic_base,
		is_lapic_enabled ? "enabled" : "disabled",
		is_boot_processor ? "BSP" : "AP");
	if (!is_boot_processor || !is_lapic_enabled)
		panic("Unexpected local APIC state\n");

	/* Establish a map to the local apic */
	lapic_start = vm_map_min(kernel_map);
	result = vm_map_find_space(kernel_map,
				   (vm_map_address_t *) &lapic_start,
				   round_page(LAPIC_SIZE), 0,
				   VM_MAKE_TAG(VM_MEMORY_IOKIT), &entry);
	if (result != KERN_SUCCESS) {
		panic("smp_init: vm_map_find_entry FAILED (err=%d)", result);
	}
	vm_map_unlock(kernel_map);
/* Map in the local APIC non-cacheable, as recommended by Intel
 * in section 8.4.1 of the "System Programming Guide".
 */
	pmap_enter(pmap_kernel(),
			lapic_start,
			(ppnum_t) i386_btop(lapic_base),
			VM_PROT_READ|VM_PROT_WRITE,
			VM_WIMG_IO,
			TRUE);
	lapic_id = (unsigned long)(lapic_start + LAPIC_ID);

	if ((LAPIC_READ(VERSION)&LAPIC_VERSION_MASK) < 0x14) {
		printf("Local APIC version 0x%x, 0x14 or greater expected\n",
			(LAPIC_READ(VERSION)&LAPIC_VERSION_MASK));
	}

	/* Set up the lapic_id <-> cpu_number map and add this boot processor */
	lapic_cpu_map_init();
	lapic_cpu_map((LAPIC_READ(ID)>>LAPIC_ID_SHIFT)&LAPIC_ID_MASK, 0);
	kprintf("Boot cpu local APIC id 0x%x\n", cpu_to_lapic[0]);
}


static int
lapic_esr_read(void)
{
	/* write-read register */
	LAPIC_WRITE(ERROR_STATUS, 0);
	return LAPIC_READ(ERROR_STATUS);
}

static void 
lapic_esr_clear(void)
{
	LAPIC_WRITE(ERROR_STATUS, 0);
	LAPIC_WRITE(ERROR_STATUS, 0);
}

static const char *DM_str[8] = {
	"Fixed",
	"Lowest Priority",
	"Invalid",
	"Invalid",
	"NMI",
	"Reset",
	"Invalid",
	"ExtINT"};

void
lapic_dump(void)
{
	int	i;

#define BOOL(a) ((a)?' ':'!')
#define VEC(lvt) \
	LAPIC_READ(lvt)&LAPIC_LVT_VECTOR_MASK
#define	DS(lvt)	\
	(LAPIC_READ(lvt)&LAPIC_LVT_DS_PENDING)?" SendPending" : "Idle"
#define DM(lvt) \
	DM_str[(LAPIC_READ(lvt)>>LAPIC_LVT_DM_SHIFT)&LAPIC_LVT_DM_MASK]
#define MASK(lvt) \
	BOOL(LAPIC_READ(lvt)&LAPIC_LVT_MASKED)
#define TM(lvt) \
	(LAPIC_READ(lvt)&LAPIC_LVT_TM_LEVEL)? "Level" : "Edge"
#define IP(lvt) \
	(LAPIC_READ(lvt)&LAPIC_LVT_IP_PLRITY_LOW)? "Low " : "High"

	kprintf("LAPIC %d at 0x%x version 0x%x\n", 
		(LAPIC_READ(ID)>>LAPIC_ID_SHIFT)&LAPIC_ID_MASK,
		lapic_start,
		LAPIC_READ(VERSION)&LAPIC_VERSION_MASK);
	kprintf("Priorities: Task 0x%x  Arbitration 0x%x  Processor 0x%x\n",
		LAPIC_READ(TPR)&LAPIC_TPR_MASK,
		LAPIC_READ(APR)&LAPIC_APR_MASK,
		LAPIC_READ(PPR)&LAPIC_PPR_MASK);
	kprintf("Destination Format 0x%x Logical Destination 0x%x\n",
		LAPIC_READ(DFR)>>LAPIC_DFR_SHIFT,
		LAPIC_READ(LDR)>>LAPIC_LDR_SHIFT);
	kprintf("%cEnabled %cFocusChecking SV 0x%x\n",
		BOOL(LAPIC_READ(SVR)&LAPIC_SVR_ENABLE),
		BOOL(!(LAPIC_READ(SVR)&LAPIC_SVR_FOCUS_OFF)),
		LAPIC_READ(SVR) & LAPIC_SVR_MASK);
	kprintf("LVT_TIMER:   Vector 0x%02x %s %cmasked %s\n",
		VEC(LVT_TIMER),
		DS(LVT_TIMER),
		MASK(LVT_TIMER),
		(LAPIC_READ(LVT_TIMER)&LAPIC_LVT_PERIODIC)?"Periodic":"OneShot");
	kprintf("  Initial Count: 0x%08x \n", LAPIC_READ(TIMER_INITIAL_COUNT));
	kprintf("  Current Count: 0x%08x \n", LAPIC_READ(TIMER_CURRENT_COUNT));
	kprintf("  Divide Config: 0x%08x \n", LAPIC_READ(TIMER_DIVIDE_CONFIG));
	kprintf("LVT_PERFCNT: Vector 0x%02x [%s] %s %cmasked\n",
		VEC(LVT_PERFCNT),
		DM(LVT_PERFCNT),
		DS(LVT_PERFCNT),
		MASK(LVT_PERFCNT));
	kprintf("LVT_THERMAL: Vector 0x%02x [%s] %s %cmasked\n",
		VEC(LVT_THERMAL),
		DM(LVT_THERMAL),
		DS(LVT_THERMAL),
		MASK(LVT_THERMAL));
	kprintf("LVT_LINT0:   Vector 0x%02x [%s][%s][%s] %s %cmasked\n",
		VEC(LVT_LINT0),
		DM(LVT_LINT0),
		TM(LVT_LINT0),
		IP(LVT_LINT0),
		DS(LVT_LINT0),
		MASK(LVT_LINT0));
	kprintf("LVT_LINT1:   Vector 0x%02x [%s][%s][%s] %s %cmasked\n",
		VEC(LVT_LINT1),
		DM(LVT_LINT1),
		TM(LVT_LINT1),
		IP(LVT_LINT1),
		DS(LVT_LINT1),
		MASK(LVT_LINT1));
	kprintf("LVT_ERROR:   Vector 0x%02x %s %cmasked\n",
		VEC(LVT_ERROR),
		DS(LVT_ERROR),
		MASK(LVT_ERROR));
	kprintf("ESR: %08x \n", lapic_esr_read());
	kprintf("       ");
	for(i=0xf; i>=0; i--)
		kprintf("%x%x%x%x",i,i,i,i);
	kprintf("\n");
	kprintf("TMR: 0x");
	for(i=7; i>=0; i--)
		kprintf("%08x",LAPIC_READ_OFFSET(TMR_BASE, i*0x10));
	kprintf("\n");
	kprintf("IRR: 0x");
	for(i=7; i>=0; i--)
		kprintf("%08x",LAPIC_READ_OFFSET(IRR_BASE, i*0x10));
	kprintf("\n");
	kprintf("ISR: 0x");
	for(i=7; i >= 0; i--)
		kprintf("%08x",LAPIC_READ_OFFSET(ISR_BASE, i*0x10));
	kprintf("\n");
}

#if MACH_KDB
/*
 *	Displays apic junk
 *
 *	da
 */
void 
db_apic(__unused db_expr_t addr,
	__unused int have_addr,
	__unused db_expr_t count,
	__unused char *modif)
{

	lapic_dump();

	return;
}

#endif

boolean_t
lapic_probe(void)
{
	uint32_t	lo;
	uint32_t	hi;

	if (cpuid_features() & CPUID_FEATURE_APIC)
		return TRUE;

	if (cpuid_family() == 6 || cpuid_family() == 15) {
		/*
		 * Mobile Pentiums:
		 * There may be a local APIC which wasn't enabled by BIOS.
		 * So we try to enable it explicitly.
		 */
		rdmsr(MSR_IA32_APIC_BASE, lo, hi);
		lo &= ~MSR_IA32_APIC_BASE_BASE;
		lo |= MSR_IA32_APIC_BASE_ENABLE | LAPIC_START;
		lo |= MSR_IA32_APIC_BASE_ENABLE;
		wrmsr(MSR_IA32_APIC_BASE, lo, hi);

		/*
		 * Re-initialize cpu features info and re-check.
		 */
		cpuid_set_info();
		if (cpuid_features() & CPUID_FEATURE_APIC) {
			printf("Local APIC discovered and enabled\n");
			lapic_os_enabled = TRUE;
			lapic_interrupt_base = LAPIC_REDUCED_INTERRUPT_BASE;
			return TRUE;
		}
	}

	return FALSE;
}

void
lapic_shutdown(void)
{
	uint32_t lo;
	uint32_t hi;
	uint32_t value;

	/* Shutdown if local APIC was enabled by OS */
	if (lapic_os_enabled == FALSE)
		return;

	mp_disable_preemption();

	/* ExtINT: masked */
	if (get_cpu_number() == master_cpu) {
		value = LAPIC_READ(LVT_LINT0);
		value |= LAPIC_LVT_MASKED;
		LAPIC_WRITE(LVT_LINT0, value);
	}

	/* Timer: masked */
	LAPIC_WRITE(LVT_TIMER, LAPIC_READ(LVT_TIMER) | LAPIC_LVT_MASKED);

	/* Perfmon: masked */
	LAPIC_WRITE(LVT_PERFCNT, LAPIC_READ(LVT_PERFCNT) | LAPIC_LVT_MASKED);

	/* Error: masked */
	LAPIC_WRITE(LVT_ERROR, LAPIC_READ(LVT_ERROR) | LAPIC_LVT_MASKED);

	/* APIC software disabled */
	LAPIC_WRITE(SVR, LAPIC_READ(SVR) & ~LAPIC_SVR_ENABLE);

	/* Bypass the APIC completely and update cpu features */
	rdmsr(MSR_IA32_APIC_BASE, lo, hi);
	lo &= ~MSR_IA32_APIC_BASE_ENABLE;
	wrmsr(MSR_IA32_APIC_BASE, lo, hi);
	cpuid_set_info();

	mp_enable_preemption();
}

void
lapic_configure(void)
{
	int	value;

	/* Set flat delivery model, logical processor id */
	LAPIC_WRITE(DFR, LAPIC_DFR_FLAT);
	LAPIC_WRITE(LDR, (get_cpu_number()) << LAPIC_LDR_SHIFT);

	/* Accept all */
	LAPIC_WRITE(TPR, 0);

	LAPIC_WRITE(SVR, LAPIC_VECTOR(SPURIOUS) | LAPIC_SVR_ENABLE);

	/* ExtINT */
	if (get_cpu_number() == master_cpu) {
		value = LAPIC_READ(LVT_LINT0);
		value &= ~LAPIC_LVT_MASKED;
		value |= LAPIC_LVT_DM_EXTINT;
		LAPIC_WRITE(LVT_LINT0, value);
	}

	/* Timer: unmasked, one-shot */
	LAPIC_WRITE(LVT_TIMER, LAPIC_VECTOR(TIMER));

	/* Perfmon: unmasked */
	LAPIC_WRITE(LVT_PERFCNT, LAPIC_VECTOR(PERFCNT));

	/* Thermal: unmasked */
	LAPIC_WRITE(LVT_THERMAL, LAPIC_VECTOR(THERMAL));

	lapic_esr_clear();

	LAPIC_WRITE(LVT_ERROR, LAPIC_VECTOR(ERROR));
}

void
lapic_set_timer(
	boolean_t		interrupt,
	lapic_timer_mode_t	mode,
	lapic_timer_divide_t	divisor,
	lapic_timer_count_t	initial_count)
{
	boolean_t	state;
	uint32_t	timer_vector;

	state = ml_set_interrupts_enabled(FALSE);
	timer_vector = LAPIC_READ(LVT_TIMER);
	timer_vector &= ~(LAPIC_LVT_MASKED|LAPIC_LVT_PERIODIC);;
	timer_vector |= interrupt ? 0 : LAPIC_LVT_MASKED;
	timer_vector |= (mode == periodic) ? LAPIC_LVT_PERIODIC : 0;
	LAPIC_WRITE(LVT_TIMER, timer_vector);
	LAPIC_WRITE(TIMER_DIVIDE_CONFIG, divisor);
	LAPIC_WRITE(TIMER_INITIAL_COUNT, initial_count);
	ml_set_interrupts_enabled(state);
}

void
lapic_get_timer(
	lapic_timer_mode_t	*mode,
	lapic_timer_divide_t	*divisor,
	lapic_timer_count_t	*initial_count,
	lapic_timer_count_t	*current_count)
{
	boolean_t	state;

	state = ml_set_interrupts_enabled(FALSE);
	if (mode)
		*mode = (LAPIC_READ(LVT_TIMER) & LAPIC_LVT_PERIODIC) ?
				periodic : one_shot;
	if (divisor)
		*divisor = LAPIC_READ(TIMER_DIVIDE_CONFIG) & LAPIC_TIMER_DIVIDE_MASK;
	if (initial_count)
		*initial_count = LAPIC_READ(TIMER_INITIAL_COUNT);
	if (current_count)
		*current_count = LAPIC_READ(TIMER_CURRENT_COUNT);
	ml_set_interrupts_enabled(state);
} 

static inline void
_lapic_end_of_interrupt(void)
{
	LAPIC_WRITE(EOI, 0);
}

void
lapic_end_of_interrupt(void)
{
	_lapic_end_of_interrupt();
}

void
lapic_set_intr_func(int vector, i386_intr_func_t func)
{
	if (vector > lapic_interrupt_base)
		vector -= lapic_interrupt_base;

	switch (vector) {
	case LAPIC_NMI_INTERRUPT:
	case LAPIC_INTERPROCESSOR_INTERRUPT:
	case LAPIC_TIMER_INTERRUPT:
	case LAPIC_THERMAL_INTERRUPT:
	case LAPIC_PERFCNT_INTERRUPT:
		lapic_intr_func[vector] = func;
		break;
	default:
		panic("lapic_set_intr_func(%d,%p) invalid vector\n",
			vector, func);
	}
}

int
lapic_interrupt(int interrupt, x86_saved_state_t *state)
{
	int	retval = 0;

	interrupt -= lapic_interrupt_base;
	if (interrupt < 0) {
		if (interrupt == (LAPIC_NMI_INTERRUPT - lapic_interrupt_base) &&
		    lapic_intr_func[LAPIC_NMI_INTERRUPT] != NULL) {
			retval = (*lapic_intr_func[LAPIC_NMI_INTERRUPT])(state);
			_lapic_end_of_interrupt();
			return retval;
		}
		else
			return 0;
	}

	switch(interrupt) {
	case LAPIC_TIMER_INTERRUPT:
	case LAPIC_THERMAL_INTERRUPT:
	case LAPIC_INTERPROCESSOR_INTERRUPT:
		if (lapic_intr_func[interrupt] != NULL)
			(void) (*lapic_intr_func[interrupt])(state);
		if (interrupt == LAPIC_PERFCNT_INTERRUPT)
			LAPIC_WRITE(LVT_PERFCNT, LAPIC_VECTOR(PERFCNT));
		_lapic_end_of_interrupt();
		retval = 1;
		break;
	case LAPIC_ERROR_INTERRUPT:
		lapic_dump();
		panic("Local APIC error\n");
		_lapic_end_of_interrupt();
		retval = 1;
		break;
	case LAPIC_SPURIOUS_INTERRUPT:
		kprintf("SPIV\n");
		/* No EOI required here */
		retval = 1;
		break;
	}

	return retval;
}

void
lapic_smm_restore(void)
{
	boolean_t state;

	if (lapic_os_enabled == FALSE)
		return;

	state = ml_set_interrupts_enabled(FALSE);

 	if (LAPIC_ISR_IS_SET(LAPIC_REDUCED_INTERRUPT_BASE, TIMER)) {
		/*
		 * Bogus SMI handler enables interrupts but does not know about
		 * local APIC interrupt sources. When APIC timer counts down to
		 * zero while in SMM, local APIC will end up waiting for an EOI
		 * but no interrupt was delivered to the OS.
 		 */
		_lapic_end_of_interrupt();

		/*
		 * timer is one-shot, trigger another quick countdown to trigger
		 * another timer interrupt.
		 */
		if (LAPIC_READ(TIMER_CURRENT_COUNT) == 0) {
			LAPIC_WRITE(TIMER_INITIAL_COUNT, 1);
		}

		kprintf("lapic_smm_restore\n");
	}

	ml_set_interrupts_enabled(state);
}

