/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */

#include <mach_rt.h>
#include <mach_kdb.h>
#include <mach_kdp.h>
#include <mach_ldebug.h>
#include <gprof.h>

#include <mach/mach_types.h>
#include <mach/kern_return.h>

#include <kern/kern_types.h>
#include <kern/startup.h>
#include <kern/processor.h>
#include <kern/cpu_number.h>
#include <kern/cpu_data.h>
#include <kern/assert.h>
#include <kern/machine.h>

#include <vm/vm_map.h>
#include <vm/vm_kern.h>

#include <profiling/profile-mk.h>

#include <i386/mp.h>
#include <i386/mp_events.h>
#include <i386/mp_slave_boot.h>
#include <i386/apic.h>
#include <i386/ipl.h>
#include <i386/fpu.h>
#include <i386/pio.h>
#include <i386/cpuid.h>
#include <i386/proc_reg.h>
#include <i386/machine_cpu.h>
#include <i386/misc_protos.h>
#include <i386/mtrr.h>
#include <i386/postcode.h>
#include <i386/perfmon.h>
#include <i386/cpu_threads.h>
#include <i386/mp_desc.h>

#if	MP_DEBUG
#define PAUSE		delay(1000000)
#define DBG(x...)	kprintf(x)
#else
#define DBG(x...)
#define PAUSE
#endif	/* MP_DEBUG */

/*
 * By default, use high vectors to leave vector space for systems
 * with multiple I/O APIC's. However some systems that boot with
 * local APIC disabled will hang in SMM when vectors greater than
 * 0x5F are used. Those systems are not expected to have I/O APIC
 * so 16 (0x50 - 0x40) vectors for legacy PIC support is perfect.
 */
#define LAPIC_DEFAULT_INTERRUPT_BASE	0xD0
#define LAPIC_REDUCED_INTERRUPT_BASE	0x50
/*
 * Specific lapic interrupts are relative to this base:
 */ 
#define LAPIC_PERFCNT_INTERRUPT		0xB
#define LAPIC_TIMER_INTERRUPT		0xC
#define LAPIC_SPURIOUS_INTERRUPT	0xD	
#define LAPIC_INTERPROCESSOR_INTERRUPT	0xE
#define LAPIC_ERROR_INTERRUPT		0xF

/* Initialize lapic_id so cpu_number() works on non SMP systems */
unsigned long	lapic_id_initdata = 0;
unsigned long	lapic_id = (unsigned long)&lapic_id_initdata;
vm_offset_t	lapic_start;

static i386_intr_func_t	lapic_timer_func;
static i386_intr_func_t	lapic_pmi_func;

/* TRUE if local APIC was enabled by the OS not by the BIOS */
static boolean_t lapic_os_enabled = FALSE;

/* Base vector for local APIC interrupt sources */
int lapic_interrupt_base = LAPIC_DEFAULT_INTERRUPT_BASE;

void 		slave_boot_init(void);

static void	mp_kdp_wait(void);
static void	mp_rendezvous_action(void);

boolean_t 	smp_initialized = FALSE;

decl_simple_lock_data(,mp_kdp_lock);

decl_mutex_data(static, mp_cpu_boot_lock);

/* Variables needed for MP rendezvous. */
static void		(*mp_rv_setup_func)(void *arg);
static void		(*mp_rv_action_func)(void *arg);
static void		(*mp_rv_teardown_func)(void *arg);
static void		*mp_rv_func_arg;
static int		mp_rv_ncpus;
static long		mp_rv_waiters[2];
decl_simple_lock_data(,mp_rv_lock);

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
#define LAPIC_CPU_MAP_DUMP()	lapic_cpu_map_dump()
#define LAPIC_DUMP()		lapic_dump()
#else
#define LAPIC_CPU_MAP_DUMP()
#define LAPIC_DUMP()
#endif /* MP_DEBUG */

#define LAPIC_REG(reg) \
	(*((volatile int *)(lapic_start + LAPIC_##reg)))
#define LAPIC_REG_OFFSET(reg,off) \
	(*((volatile int *)(lapic_start + LAPIC_##reg + (off))))

#define LAPIC_VECTOR(src) \
	(lapic_interrupt_base + LAPIC_##src##_INTERRUPT)

#define LAPIC_ISR_IS_SET(base,src) \
	(LAPIC_REG_OFFSET(ISR_BASE,((base+LAPIC_##src##_INTERRUPT)/32)*0x10) & \
		(1 <<((base + LAPIC_##src##_INTERRUPT)%32)))

#if GPROF
/*
 * Initialize dummy structs for profiling. These aren't used but
 * allows hertz_tick() to be built with GPROF defined.
 */
struct profile_vars _profile_vars;
struct profile_vars *_profile_vars_cpus[MAX_CPUS] = { &_profile_vars };
#define GPROF_INIT()							\
{									\
	int	i;							\
									\
	/* Hack to initialize pointers to unused profiling structs */	\
	for (i = 1; i < MAX_CPUS; i++)				\
		_profile_vars_cpus[i] = &_profile_vars;			\
}
#else
#define GPROF_INIT()
#endif /* GPROF */

extern void	master_up(void);

void
smp_init(void)
{
	int		result;
	vm_map_entry_t	entry;
	uint32_t	lo;
	uint32_t	hi;
	boolean_t	is_boot_processor;
	boolean_t	is_lapic_enabled;
	vm_offset_t	lapic_base;

	simple_lock_init(&mp_kdp_lock, 0);
	simple_lock_init(&mp_rv_lock, 0);
	mutex_init(&mp_cpu_boot_lock, 0);
	console_init();

	/* Local APIC? */
	if (!lapic_probe())
		return;

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
	result = vm_map_find_space(kernel_map, &lapic_start,
				   round_page(LAPIC_SIZE), 0, &entry);
	if (result != KERN_SUCCESS) {
		panic("smp_init: vm_map_find_entry FAILED (err=%d)", result);
	}
	vm_map_unlock(kernel_map);
	pmap_enter(pmap_kernel(),
			lapic_start,
			(ppnum_t) i386_btop(lapic_base),
		   	VM_PROT_READ|VM_PROT_WRITE,
			VM_WIMG_USE_DEFAULT,
			TRUE);
	lapic_id = (unsigned long)(lapic_start + LAPIC_ID);

	if ((LAPIC_REG(VERSION)&LAPIC_VERSION_MASK) != 0x14) {
		printf("Local APIC version not 0x14 as expected\n");
	}

	/* Set up the lapic_id <-> cpu_number map and add this boot processor */
	lapic_cpu_map_init();
	lapic_cpu_map((LAPIC_REG(ID)>>LAPIC_ID_SHIFT)&LAPIC_ID_MASK, 0);

	lapic_init();

	cpu_thread_init();

	if (pmc_init() != KERN_SUCCESS)
		printf("Performance counters not available\n");

	GPROF_INIT();
	DBGLOG_CPU_INIT(master_cpu);

	slave_boot_init();
	master_up();

	smp_initialized = TRUE;

	return;
}


static int
lapic_esr_read(void)
{
	/* write-read register */
	LAPIC_REG(ERROR_STATUS) = 0;
	return LAPIC_REG(ERROR_STATUS);
}

static void 
lapic_esr_clear(void)
{
	LAPIC_REG(ERROR_STATUS) = 0;
	LAPIC_REG(ERROR_STATUS) = 0;
}

static const char *DM[8] = {
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

	kprintf("LAPIC %d at 0x%x version 0x%x\n", 
		(LAPIC_REG(ID)>>LAPIC_ID_SHIFT)&LAPIC_ID_MASK,
		lapic_start,
		LAPIC_REG(VERSION)&LAPIC_VERSION_MASK);
	kprintf("Priorities: Task 0x%x  Arbitration 0x%x  Processor 0x%x\n",
		LAPIC_REG(TPR)&LAPIC_TPR_MASK,
		LAPIC_REG(APR)&LAPIC_APR_MASK,
		LAPIC_REG(PPR)&LAPIC_PPR_MASK);
	kprintf("Destination Format 0x%x Logical Destination 0x%x\n",
		LAPIC_REG(DFR)>>LAPIC_DFR_SHIFT,
		LAPIC_REG(LDR)>>LAPIC_LDR_SHIFT);
	kprintf("%cEnabled %cFocusChecking SV 0x%x\n",
		BOOL(LAPIC_REG(SVR)&LAPIC_SVR_ENABLE),
		BOOL(!(LAPIC_REG(SVR)&LAPIC_SVR_FOCUS_OFF)),
		LAPIC_REG(SVR) & LAPIC_SVR_MASK);
	kprintf("LVT_TIMER:   Vector 0x%02x %s %cmasked %s\n",
		LAPIC_REG(LVT_TIMER)&LAPIC_LVT_VECTOR_MASK,
		(LAPIC_REG(LVT_TIMER)&LAPIC_LVT_DS_PENDING)?"SendPending":"Idle",
		BOOL(LAPIC_REG(LVT_TIMER)&LAPIC_LVT_MASKED),
		(LAPIC_REG(LVT_TIMER)&LAPIC_LVT_PERIODIC)?"Periodic":"OneShot");
	kprintf("  Initial Count: 0x%08x \n", LAPIC_REG(TIMER_INITIAL_COUNT));
	kprintf("  Current Count: 0x%08x \n", LAPIC_REG(TIMER_CURRENT_COUNT));
	kprintf("  Divide Config: 0x%08x \n", LAPIC_REG(TIMER_DIVIDE_CONFIG));
	kprintf("LVT_PERFCNT: Vector 0x%02x [%s] %s %cmasked\n",
		LAPIC_REG(LVT_PERFCNT)&LAPIC_LVT_VECTOR_MASK,
		DM[(LAPIC_REG(LVT_PERFCNT)>>LAPIC_LVT_DM_SHIFT)&LAPIC_LVT_DM_MASK],
		(LAPIC_REG(LVT_PERFCNT)&LAPIC_LVT_DS_PENDING)?"SendPending":"Idle",
		BOOL(LAPIC_REG(LVT_PERFCNT)&LAPIC_LVT_MASKED));
	kprintf("LVT_LINT0:   Vector 0x%02x [%s][%s][%s] %s %cmasked\n",
		LAPIC_REG(LVT_LINT0)&LAPIC_LVT_VECTOR_MASK,
		DM[(LAPIC_REG(LVT_LINT0)>>LAPIC_LVT_DM_SHIFT)&LAPIC_LVT_DM_MASK],
		(LAPIC_REG(LVT_LINT0)&LAPIC_LVT_TM_LEVEL)?"Level":"Edge ",
		(LAPIC_REG(LVT_LINT0)&LAPIC_LVT_IP_PLRITY_LOW)?"Low ":"High",
		(LAPIC_REG(LVT_LINT0)&LAPIC_LVT_DS_PENDING)?"SendPending":"Idle",
		BOOL(LAPIC_REG(LVT_LINT0)&LAPIC_LVT_MASKED));
	kprintf("LVT_LINT1:   Vector 0x%02x [%s][%s][%s] %s %cmasked\n",
		LAPIC_REG(LVT_LINT1)&LAPIC_LVT_VECTOR_MASK,
		DM[(LAPIC_REG(LVT_LINT1)>>LAPIC_LVT_DM_SHIFT)&LAPIC_LVT_DM_MASK],
		(LAPIC_REG(LVT_LINT1)&LAPIC_LVT_TM_LEVEL)?"Level":"Edge ",
		(LAPIC_REG(LVT_LINT1)&LAPIC_LVT_IP_PLRITY_LOW)?"Low ":"High",
		(LAPIC_REG(LVT_LINT1)&LAPIC_LVT_DS_PENDING)?"SendPending":"Idle",
		BOOL(LAPIC_REG(LVT_LINT1)&LAPIC_LVT_MASKED));
	kprintf("LVT_ERROR:   Vector 0x%02x %s %cmasked\n",
		LAPIC_REG(LVT_ERROR)&LAPIC_LVT_VECTOR_MASK,
		(LAPIC_REG(LVT_ERROR)&LAPIC_LVT_DS_PENDING)?"SendPending":"Idle",
		BOOL(LAPIC_REG(LVT_ERROR)&LAPIC_LVT_MASKED));
	kprintf("ESR: %08x \n", lapic_esr_read());
	kprintf("       ");
	for(i=0xf; i>=0; i--)
		kprintf("%x%x%x%x",i,i,i,i);
	kprintf("\n");
	kprintf("TMR: 0x");
	for(i=7; i>=0; i--)
		kprintf("%08x",LAPIC_REG_OFFSET(TMR_BASE, i*0x10));
	kprintf("\n");
	kprintf("IRR: 0x");
	for(i=7; i>=0; i--)
		kprintf("%08x",LAPIC_REG_OFFSET(IRR_BASE, i*0x10));
	kprintf("\n");
	kprintf("ISR: 0x");
	for(i=7; i >= 0; i--)
		kprintf("%08x",LAPIC_REG_OFFSET(ISR_BASE, i*0x10));
	kprintf("\n");
}

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
		set_cpu_model();
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
		value = LAPIC_REG(LVT_LINT0);
		value |= LAPIC_LVT_MASKED;
		LAPIC_REG(LVT_LINT0) = value;
	}

	/* Timer: masked */
	LAPIC_REG(LVT_TIMER) |= LAPIC_LVT_MASKED;

	/* Perfmon: masked */
	LAPIC_REG(LVT_PERFCNT) |= LAPIC_LVT_MASKED;

	/* Error: masked */
	LAPIC_REG(LVT_ERROR) |= LAPIC_LVT_MASKED;

	/* APIC software disabled */
	LAPIC_REG(SVR) &= ~LAPIC_SVR_ENABLE;

	/* Bypass the APIC completely and update cpu features */
	rdmsr(MSR_IA32_APIC_BASE, lo, hi);
	lo &= ~MSR_IA32_APIC_BASE_ENABLE;
	wrmsr(MSR_IA32_APIC_BASE, lo, hi);
	set_cpu_model();

	mp_enable_preemption();
}

void
lapic_init(void)
{
	int	value;

	/* Set flat delivery model, logical processor id */
	LAPIC_REG(DFR) = LAPIC_DFR_FLAT;
	LAPIC_REG(LDR) = (get_cpu_number()) << LAPIC_LDR_SHIFT;

	/* Accept all */
	LAPIC_REG(TPR) =  0;

	LAPIC_REG(SVR) = LAPIC_VECTOR(SPURIOUS) | LAPIC_SVR_ENABLE;

	/* ExtINT */
	if (get_cpu_number() == master_cpu) {
		value = LAPIC_REG(LVT_LINT0);
		value &= ~LAPIC_LVT_MASKED;
		value |= LAPIC_LVT_DM_EXTINT;
		LAPIC_REG(LVT_LINT0) = value;
	}

	/* Timer: unmasked, one-shot */
	LAPIC_REG(LVT_TIMER) = LAPIC_VECTOR(TIMER);

	/* Perfmon: unmasked */
	LAPIC_REG(LVT_PERFCNT) = LAPIC_VECTOR(PERFCNT);

	lapic_esr_clear();

	LAPIC_REG(LVT_ERROR) = LAPIC_VECTOR(ERROR);

}

void
lapic_set_timer_func(i386_intr_func_t func)
{
	lapic_timer_func = func;
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
	timer_vector = LAPIC_REG(LVT_TIMER);
	timer_vector &= ~(LAPIC_LVT_MASKED|LAPIC_LVT_PERIODIC);;
	timer_vector |= interrupt ? 0 : LAPIC_LVT_MASKED;
	timer_vector |= (mode == periodic) ? LAPIC_LVT_PERIODIC : 0;
	LAPIC_REG(LVT_TIMER) = timer_vector;
	LAPIC_REG(TIMER_DIVIDE_CONFIG) = divisor;
	LAPIC_REG(TIMER_INITIAL_COUNT) = initial_count;
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
		*mode = (LAPIC_REG(LVT_TIMER) & LAPIC_LVT_PERIODIC) ?
				periodic : one_shot;
	if (divisor)
		*divisor = LAPIC_REG(TIMER_DIVIDE_CONFIG) & LAPIC_TIMER_DIVIDE_MASK;
	if (initial_count)
		*initial_count = LAPIC_REG(TIMER_INITIAL_COUNT);
	if (current_count)
		*current_count = LAPIC_REG(TIMER_CURRENT_COUNT);
	ml_set_interrupts_enabled(state);
} 

void
lapic_set_pmi_func(i386_intr_func_t func)
{
	lapic_pmi_func = func;
}

static inline void
_lapic_end_of_interrupt(void)
{
	LAPIC_REG(EOI) = 0;
}

void
lapic_end_of_interrupt(void)
{
	_lapic_end_of_interrupt();
}

int
lapic_interrupt(int interrupt, void *state)
{
	interrupt -= lapic_interrupt_base;
	if (interrupt < 0)
		return 0;

	switch(interrupt) {
	case LAPIC_PERFCNT_INTERRUPT:
		if (lapic_pmi_func != NULL)
			(*lapic_pmi_func)(
				(struct i386_interrupt_state *) state);
		/* Clear interrupt masked */
		LAPIC_REG(LVT_PERFCNT) = LAPIC_VECTOR(PERFCNT);
		_lapic_end_of_interrupt();
		return 1;
	case LAPIC_TIMER_INTERRUPT:
		_lapic_end_of_interrupt();
		if (lapic_timer_func != NULL)
			(*lapic_timer_func)(
				(struct i386_interrupt_state *) state);
		return 1;
	case LAPIC_ERROR_INTERRUPT:
		lapic_dump();
		panic("Local APIC error\n");
		_lapic_end_of_interrupt();
		return 1;
	case LAPIC_SPURIOUS_INTERRUPT:
		kprintf("SPIV\n");
		/* No EOI required here */
		return 1;
	case LAPIC_INTERPROCESSOR_INTERRUPT:
		cpu_signal_handler((struct i386_interrupt_state *) state);
		_lapic_end_of_interrupt();
		return 1;
	}
	return 0;
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
		if (LAPIC_REG(TIMER_CURRENT_COUNT) == 0) {
			LAPIC_REG(TIMER_INITIAL_COUNT) = 1;
		}

		kprintf("lapic_smm_restore\n");
	}

	ml_set_interrupts_enabled(state);
}

kern_return_t
intel_startCPU(
	int	slot_num)
{

	int	i = 1000;
	int	lapic = cpu_to_lapic[slot_num];

	assert(lapic != -1);

	DBGLOG_CPU_INIT(slot_num);

	DBG("intel_startCPU(%d) lapic_id=%d\n", slot_num, lapic);
	DBG("IdlePTD(%p): 0x%x\n", &IdlePTD, (int) IdlePTD);

	/* Initialize (or re-initialize) the descriptor tables for this cpu. */
	mp_desc_init(cpu_datap(slot_num), FALSE);

	/* Serialize use of the slave boot stack. */
	mutex_lock(&mp_cpu_boot_lock);

	mp_disable_preemption();
	if (slot_num == get_cpu_number()) {
		mp_enable_preemption();
		mutex_unlock(&mp_cpu_boot_lock);
		return KERN_SUCCESS;
	}

	LAPIC_REG(ICRD) = lapic << LAPIC_ICRD_DEST_SHIFT;
	LAPIC_REG(ICR) = LAPIC_ICR_DM_INIT;
	delay(10000);

	LAPIC_REG(ICRD) = lapic << LAPIC_ICRD_DEST_SHIFT;
	LAPIC_REG(ICR) = LAPIC_ICR_DM_STARTUP|(MP_BOOT>>12);
	delay(200);

	LAPIC_REG(ICRD) = lapic << LAPIC_ICRD_DEST_SHIFT;
	LAPIC_REG(ICR) = LAPIC_ICR_DM_STARTUP|(MP_BOOT>>12);
	delay(200);

#ifdef	POSTCODE_DELAY
	/* Wait much longer if postcodes are displayed for a delay period. */
	i *= 10000;
#endif
	while(i-- > 0) {
		if (cpu_datap(slot_num)->cpu_running)
			break;
		delay(10000);
	}

	mp_enable_preemption();
	mutex_unlock(&mp_cpu_boot_lock);

	if (!cpu_datap(slot_num)->cpu_running) {
		DBG("Failed to start CPU %02d\n", slot_num);
		printf("Failed to start CPU %02d, rebooting...\n", slot_num);
		delay(1000000);
		cpu_shutdown();
		return KERN_SUCCESS;
	} else {
		DBG("Started CPU %02d\n", slot_num);
		printf("Started CPU %02d\n", slot_num);
		return KERN_SUCCESS;
	}
}

extern char	slave_boot_base[];
extern char	slave_boot_end[];
extern void	pstart(void);

void
slave_boot_init(void)
{
	DBG("V(slave_boot_base)=%p P(slave_boot_base)=%p MP_BOOT=%p sz=0x%x\n",
		slave_boot_base,
		kvtophys((vm_offset_t) slave_boot_base),
		MP_BOOT,
		slave_boot_end-slave_boot_base);

	/*
	 * Copy the boot entry code to the real-mode vector area MP_BOOT.
	 * This is in page 1 which has been reserved for this purpose by
	 * machine_startup() from the boot processor.
	 * The slave boot code is responsible for switching to protected
	 * mode and then jumping to the common startup, _start().
	 */
	bcopy_phys((addr64_t) kvtophys((vm_offset_t) slave_boot_base),
		   (addr64_t) MP_BOOT,
		   slave_boot_end-slave_boot_base);

	/*
	 * Zero a stack area above the boot code.
	 */
	DBG("bzero_phys 0x%x sz 0x%x\n",MP_BOOTSTACK+MP_BOOT-0x400, 0x400);
	bzero_phys((addr64_t)MP_BOOTSTACK+MP_BOOT-0x400, 0x400);

	/*
	 * Set the location at the base of the stack to point to the
	 * common startup entry.
	 */
	DBG("writing 0x%x at phys 0x%x\n",
		kvtophys((vm_offset_t) &pstart), MP_MACH_START+MP_BOOT);
	ml_phys_write_word(MP_MACH_START+MP_BOOT,
			   kvtophys((vm_offset_t) &pstart));
	
	/* Flush caches */
	__asm__("wbinvd");
}

#if	MP_DEBUG
cpu_signal_event_log_t	*cpu_signal[MAX_CPUS];
cpu_signal_event_log_t	*cpu_handle[MAX_CPUS];

MP_EVENT_NAME_DECL();

#endif	/* MP_DEBUG */

void
cpu_signal_handler(__unused struct i386_interrupt_state *regs)
{
	int		my_cpu;
	volatile int	*my_word;
#if	MACH_KDB && MACH_ASSERT
	int		i=100;
#endif	/* MACH_KDB && MACH_ASSERT */

	mp_disable_preemption();

	my_cpu = cpu_number();
	my_word = &current_cpu_datap()->cpu_signals;

	do {
#if	MACH_KDB && MACH_ASSERT
		if (i-- <= 0)
		    Debugger("cpu_signal_handler");
#endif	/* MACH_KDB && MACH_ASSERT */
#if	MACH_KDP
		if (i_bit(MP_KDP, my_word)) {
			DBGLOG(cpu_handle,my_cpu,MP_KDP);
			i_bit_clear(MP_KDP, my_word);
			mp_kdp_wait();
		} else
#endif	/* MACH_KDP */
		if (i_bit(MP_TLB_FLUSH, my_word)) {
			DBGLOG(cpu_handle,my_cpu,MP_TLB_FLUSH);
			i_bit_clear(MP_TLB_FLUSH, my_word);
			pmap_update_interrupt();
		} else if (i_bit(MP_AST, my_word)) {
			DBGLOG(cpu_handle,my_cpu,MP_AST);
			i_bit_clear(MP_AST, my_word);
			ast_check(cpu_to_processor(my_cpu));
#if	MACH_KDB
		} else if (i_bit(MP_KDB, my_word)) {
			extern kdb_is_slave[];

			i_bit_clear(MP_KDB, my_word);
			kdb_is_slave[my_cpu]++;
			kdb_kintr();
#endif	/* MACH_KDB */
		} else if (i_bit(MP_RENDEZVOUS, my_word)) {
			DBGLOG(cpu_handle,my_cpu,MP_RENDEZVOUS);
			i_bit_clear(MP_RENDEZVOUS, my_word);
			mp_rendezvous_action();
		}
	} while (*my_word);

	mp_enable_preemption();

}

#ifdef	MP_DEBUG
extern int	max_lock_loops;
#endif	/* MP_DEBUG */
void
cpu_interrupt(int cpu)
{
	boolean_t	state;

	if (smp_initialized) {

		/* Wait for previous interrupt to be delivered... */
#ifdef	MP_DEBUG
		int	pending_busy_count = 0;
		while (LAPIC_REG(ICR) & LAPIC_ICR_DS_PENDING) {
			if (++pending_busy_count > max_lock_loops)
				panic("cpus_interrupt() deadlock\n");
#else
		while (LAPIC_REG(ICR) & LAPIC_ICR_DS_PENDING) {
#endif	/* MP_DEBUG */
			cpu_pause();
		}

		state = ml_set_interrupts_enabled(FALSE);
		LAPIC_REG(ICRD) =
			cpu_to_lapic[cpu] << LAPIC_ICRD_DEST_SHIFT;
		LAPIC_REG(ICR)  =
			LAPIC_VECTOR(INTERPROCESSOR) | LAPIC_ICR_DM_FIXED;
		(void) ml_set_interrupts_enabled(state);
	}

}

void
i386_signal_cpu(int cpu, mp_event_t event, mp_sync_t mode)
{
	volatile int	*signals = &cpu_datap(cpu)->cpu_signals;
	uint64_t	tsc_timeout;
	

	if (!cpu_datap(cpu)->cpu_running)
		return;

	DBGLOG(cpu_signal, cpu, event);

	i_bit_set(event, signals);
	cpu_interrupt(cpu);
	if (mode == SYNC) {
	   again:
		tsc_timeout = rdtsc64() + (1000*1000*1000);
		while (i_bit(event, signals) && rdtsc64() < tsc_timeout) {
			cpu_pause();
		}
		if (i_bit(event, signals)) {
			DBG("i386_signal_cpu(%d, 0x%x, SYNC) timed out\n",
				cpu, event);
			goto again;
		}
	}
}

void
i386_signal_cpus(mp_event_t event, mp_sync_t mode)
{
	unsigned int	cpu;
	unsigned int	my_cpu = cpu_number();

	for (cpu = 0; cpu < real_ncpus; cpu++) {
		if (cpu == my_cpu || !cpu_datap(cpu)->cpu_running)
			continue;
		i386_signal_cpu(cpu, event, mode);
	}
}

int
i386_active_cpus(void)
{
	unsigned int	cpu;
	unsigned int	ncpus = 0;

	for (cpu = 0; cpu < real_ncpus; cpu++) {
		if (cpu_datap(cpu)->cpu_running)
			ncpus++;
	}
	return(ncpus);
}

/*
 * All-CPU rendezvous:
 * 	- CPUs are signalled,
 *	- all execute the setup function (if specified),
 *	- rendezvous (i.e. all cpus reach a barrier),
 *	- all execute the action function (if specified),
 *	- rendezvous again,
 *	- execute the teardown function (if specified), and then
 *	- resume.
 *
 * Note that the supplied external functions _must_ be reentrant and aware
 * that they are running in parallel and in an unknown lock context.
 */

static void
mp_rendezvous_action(void)
{

	/* setup function */
	if (mp_rv_setup_func != NULL)
		mp_rv_setup_func(mp_rv_func_arg);
	/* spin on entry rendezvous */
	atomic_incl(&mp_rv_waiters[0], 1);
	while (*((volatile long *) &mp_rv_waiters[0]) < mp_rv_ncpus)
		cpu_pause();
	/* action function */
	if (mp_rv_action_func != NULL)
		mp_rv_action_func(mp_rv_func_arg);
	/* spin on exit rendezvous */
	atomic_incl(&mp_rv_waiters[1], 1);
	while (*((volatile long *) &mp_rv_waiters[1]) < mp_rv_ncpus)
		cpu_pause();
	/* teardown function */
	if (mp_rv_teardown_func != NULL)
		mp_rv_teardown_func(mp_rv_func_arg);
}

void
mp_rendezvous(void (*setup_func)(void *), 
	      void (*action_func)(void *),
	      void (*teardown_func)(void *),
	      void *arg)
{

	if (!smp_initialized) {
		if (setup_func != NULL)
			setup_func(arg);
		if (action_func != NULL)
			action_func(arg);
		if (teardown_func != NULL)
			teardown_func(arg);
		return;
	}
		
	/* obtain rendezvous lock */
	simple_lock(&mp_rv_lock);

	/* set static function pointers */
	mp_rv_setup_func = setup_func;
	mp_rv_action_func = action_func;
	mp_rv_teardown_func = teardown_func;
	mp_rv_func_arg = arg;

	mp_rv_waiters[0] = 0;		/* entry rendezvous count */
	mp_rv_waiters[1] = 0;		/* exit  rendezvous count */
	mp_rv_ncpus = i386_active_cpus();

	/*
	 * signal other processors, which will call mp_rendezvous_action()
	 * with interrupts disabled
	 */
	i386_signal_cpus(MP_RENDEZVOUS, ASYNC);

	/* call executor function on this cpu */
	mp_rendezvous_action();

	/* release lock */
	simple_unlock(&mp_rv_lock);
}

#if	MACH_KDP
volatile boolean_t	mp_kdp_trap = FALSE;
long			mp_kdp_ncpus;
boolean_t		mp_kdp_state;


void
mp_kdp_enter(void)
{
	unsigned int	cpu;
	unsigned int	ncpus;
	unsigned int	my_cpu = cpu_number();
	uint64_t	tsc_timeout;

	DBG("mp_kdp_enter()\n");

	/*
	 * Here to enter the debugger.
	 * In case of races, only one cpu is allowed to enter kdp after
	 * stopping others.
	 */
	mp_kdp_state = ml_set_interrupts_enabled(FALSE);
	simple_lock(&mp_kdp_lock);
	while (mp_kdp_trap) {
		simple_unlock(&mp_kdp_lock);
		DBG("mp_kdp_enter() race lost\n");
		mp_kdp_wait();
		simple_lock(&mp_kdp_lock);
	}
	mp_kdp_ncpus = 1;	/* self */
	mp_kdp_trap = TRUE;
	simple_unlock(&mp_kdp_lock);

	/* Deliver a nudge to other cpus, counting how many */
	DBG("mp_kdp_enter() signaling other processors\n");
	for (ncpus = 1, cpu = 0; cpu < real_ncpus; cpu++) {
		if (cpu == my_cpu || !cpu_datap(cpu)->cpu_running)
			continue;
		ncpus++;
		i386_signal_cpu(cpu, MP_KDP, ASYNC); 
	}

	/* Wait other processors to spin. */
	DBG("mp_kdp_enter() waiting for (%d) processors to suspend\n", ncpus);
	tsc_timeout = rdtsc64() + (1000*1000*1000);
	while (*((volatile unsigned int *) &mp_kdp_ncpus) != ncpus
		&& rdtsc64() < tsc_timeout) {
		cpu_pause();
	}
	DBG("mp_kdp_enter() %d processors done %s\n",
		mp_kdp_ncpus, (mp_kdp_ncpus == ncpus) ? "OK" : "timed out");
	postcode(MP_KDP_ENTER);
}

static void
mp_kdp_wait(void)
{
	boolean_t	state;

	state = ml_set_interrupts_enabled(TRUE);
	DBG("mp_kdp_wait()\n");
	atomic_incl(&mp_kdp_ncpus, 1);
	while (mp_kdp_trap) {
		cpu_pause();
	}
	atomic_decl(&mp_kdp_ncpus, 1);
	DBG("mp_kdp_wait() done\n");
	(void) ml_set_interrupts_enabled(state);
}

void
mp_kdp_exit(void)
{
	DBG("mp_kdp_exit()\n");
	atomic_decl(&mp_kdp_ncpus, 1);
	mp_kdp_trap = FALSE;

	/* Wait other processors to stop spinning. XXX needs timeout */
	DBG("mp_kdp_exit() waiting for processors to resume\n");
	while (*((volatile long *) &mp_kdp_ncpus) > 0) {
		cpu_pause();
	}
	DBG("mp_kdp_exit() done\n");
	(void) ml_set_interrupts_enabled(mp_kdp_state);
	postcode(0);
}
#endif	/* MACH_KDP */

/*ARGSUSED*/
void
init_ast_check(
	__unused processor_t	processor)
{
}

void
cause_ast_check(
	processor_t	processor)
{
	int	cpu = PROCESSOR_DATA(processor, slot_num);

	if (cpu != cpu_number()) {
		i386_signal_cpu(cpu, MP_AST, ASYNC);
	}
}

/*
 * invoke kdb on slave processors 
 */

void
remote_kdb(void)
{
	unsigned int	my_cpu = cpu_number();
	unsigned int	cpu;
	
	mp_disable_preemption();
	for (cpu = 0; cpu < real_ncpus; cpu++) {
		if (cpu == my_cpu || !cpu_datap(cpu)->cpu_running)
			continue;
		i386_signal_cpu(cpu, MP_KDB, SYNC);
	}
	mp_enable_preemption();
}

/*
 * Clear kdb interrupt
 */

void
clear_kdb_intr(void)
{
	mp_disable_preemption();
	i_bit_clear(MP_KDB, &current_cpu_datap()->cpu_signals);
	mp_enable_preemption();
}

/*
 * i386_init_slave() is called from pstart.
 * We're in the cpu's interrupt stack with interrupts disabled.
 */
void
i386_init_slave(void)
{
	postcode(I386_INIT_SLAVE);

	/* Ensure that caching and write-through are enabled */
	set_cr0(get_cr0() & ~(CR0_NW|CR0_CD));

	DBG("i386_init_slave() CPU%d: phys (%d) active.\n",
		get_cpu_number(), get_cpu_phys_number());

	lapic_init();

	LAPIC_DUMP();
	LAPIC_CPU_MAP_DUMP();

	mtrr_update_cpu();

	pat_init();

	cpu_init();

	slave_main();

	panic("i386_init_slave() returned from slave_main()");
}

void
slave_machine_init(void)
{
	/*
 	 * Here in process context.
	 */
	DBG("slave_machine_init() CPU%d\n", get_cpu_number());

	init_fpu();

	cpu_thread_init();

	pmc_init();

	cpu_machine_init();

	clock_init();
}

#undef cpu_number()
int cpu_number(void)
{
	return get_cpu_number();
}

#if	MACH_KDB
#include <ddb/db_output.h>

#define TRAP_DEBUG 0 /* Must match interrupt.s and spl.s */


#if	TRAP_DEBUG
#define MTRAPS 100
struct mp_trap_hist_struct {
	unsigned char type;
	unsigned char data[5];
} trap_hist[MTRAPS], *cur_trap_hist = trap_hist,
    *max_trap_hist = &trap_hist[MTRAPS];

void db_trap_hist(void);

/*
 * SPL:
 *	1: new spl
 *	2: old spl
 *	3: new tpr
 *	4: old tpr
 * INT:
 * 	1: int vec
 *	2: old spl
 *	3: new spl
 *	4: post eoi tpr
 *	5: exit tpr
 */

void
db_trap_hist(void)
{
	int i,j;
	for(i=0;i<MTRAPS;i++)
	    if (trap_hist[i].type == 1 || trap_hist[i].type == 2) {
		    db_printf("%s%s",
			      (&trap_hist[i]>=cur_trap_hist)?"*":" ",
			      (trap_hist[i].type == 1)?"SPL":"INT");
		    for(j=0;j<5;j++)
			db_printf(" %02x", trap_hist[i].data[j]);
		    db_printf("\n");
	    }
		
}
#endif	/* TRAP_DEBUG */

void db_lapic(int cpu);
unsigned int db_remote_read(int cpu, int reg);
void db_ioapic(unsigned int);
void kdb_console(void);

void
kdb_console(void)
{
}

#define BOOLP(a) ((a)?' ':'!')

static char *DM[8] = {
	"Fixed",
	"Lowest Priority",
	"Invalid",
	"Invalid",
	"NMI",
	"Reset",
	"Invalid",
	"ExtINT"};

unsigned int
db_remote_read(int cpu, int reg)
{
	return -1;
}

void
db_lapic(int cpu)
{
}

void
db_ioapic(unsigned int ind)
{
}

#endif	/* MACH_KDB */

