/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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

#include <cpus.h>
#include <mach_rt.h>
#include <mach_kdb.h>
#include <mach_kdp.h>
#include <mach_ldebug.h>

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
#include <vm/vm_kern.h>
#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <kern/startup.h>
#include <kern/processor.h>
#include <kern/cpu_number.h>
#include <kern/cpu_data.h>
#include <kern/assert.h>

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
vm_offset_t 	lapic_start;

void 		lapic_init(void);
void 		slave_boot_init(void);

static void	mp_kdp_wait(void);
static void	mp_rendezvous_action(void);

boolean_t 	smp_initialized = FALSE;

decl_simple_lock_data(,mp_kdp_lock);
decl_simple_lock_data(,mp_putc_lock);

/* Variables needed for MP rendezvous. */
static void		(*mp_rv_setup_func)(void *arg);
static void		(*mp_rv_action_func)(void *arg);
static void		(*mp_rv_teardown_func)(void *arg);
static void		*mp_rv_func_arg;
static int		mp_rv_ncpus;
static volatile long	mp_rv_waiters[2];
decl_simple_lock_data(,mp_rv_lock);

int		lapic_to_cpu[LAPIC_ID_MAX+1];
int		cpu_to_lapic[NCPUS];

static void
lapic_cpu_map_init(void)
{
	int	i;

	for (i = 0; i < NCPUS; i++)
		cpu_to_lapic[i] = -1;
	for (i = 0; i <= LAPIC_ID_MAX; i++)
		lapic_to_cpu[i] = -1;
}

void
lapic_cpu_map(int apic_id, int cpu_number)
{
	cpu_to_lapic[cpu_number] = apic_id;
	lapic_to_cpu[apic_id] = cpu_number;
}

#ifdef MP_DEBUG
static void
lapic_cpu_map_dump(void)
{
	int	i;

	for (i = 0; i < NCPUS; i++) {
		if (cpu_to_lapic[i] == -1)
			continue;
		kprintf("cpu_to_lapic[%d]: %d\n",
			i, cpu_to_lapic[i]);
	}
	for (i = 0; i <= LAPIC_ID_MAX; i++) {
		if (lapic_to_cpu[i] == -1)
			continue;
		kprintf("lapic_to_cpu[%d]: %d\n",
			i, lapic_to_cpu[i]);
	}
}
#endif /* MP_DEBUG */

#define LAPIC_REG(reg) \
	(*((volatile int *)(lapic_start + LAPIC_##reg)))
#define LAPIC_REG_OFFSET(reg,off) \
	(*((volatile int *)(lapic_start + LAPIC_##reg + (off))))


void
smp_init(void)

{
	int		result;
	vm_map_entry_t	entry;
	uint32_t	lo;
	uint32_t	hi;
	boolean_t	is_boot_processor;
	boolean_t	is_lapic_enabled;

	/* Local APIC? */
	if ((cpuid_features() & CPUID_FEATURE_APIC) == 0)
		return;

	simple_lock_init(&mp_kdp_lock, ETAP_MISC_PRINTF);
	simple_lock_init(&mp_rv_lock, ETAP_MISC_PRINTF);
	simple_lock_init(&mp_putc_lock, ETAP_MISC_PRINTF);

	/* Examine the local APIC state */
	rdmsr(MSR_IA32_APIC_BASE, lo, hi);
	is_boot_processor = (lo & MSR_IA32_APIC_BASE_BSP) != 0;
	is_lapic_enabled  = (lo & MSR_IA32_APIC_BASE_ENABLE) != 0;
	DBG("MSR_IA32_APIC_BASE 0x%x:0x%x %s %s\n", hi, lo,
		is_lapic_enabled ? "enabled" : "disabled",
		is_boot_processor ? "BSP" : "AP");
	assert(is_boot_processor);
	assert(is_lapic_enabled);

	/* Establish a map to the local apic */
	lapic_start = vm_map_min(kernel_map);
	result = vm_map_find_space(kernel_map, &lapic_start,
				   round_page(LAPIC_SIZE), 0, &entry);
	if (result != KERN_SUCCESS) {
		printf("smp_init: vm_map_find_entry FAILED (err=%d). "
			"Only supporting ONE cpu.\n", result);
		return;
	}
	vm_map_unlock(kernel_map);
	pmap_enter(pmap_kernel(),
			lapic_start,
			(ppnum_t) i386_btop(i386_trunc_page(LAPIC_START)),
		   	VM_PROT_READ|VM_PROT_WRITE,
			VM_WIMG_USE_DEFAULT,
			TRUE);
	lapic_id = (unsigned long)(lapic_start + LAPIC_ID);

	/* Set up the lapic_id <-> cpu_number map and add this boot processor */
	lapic_cpu_map_init();
	lapic_cpu_map((LAPIC_REG(ID)>>LAPIC_ID_SHIFT)&LAPIC_ID_MASK, 0);

	lapic_init();

	slave_boot_init();
	master_up();

	smp_initialized = TRUE;

	return;
}


int
lapic_esr_read(void)
{
	/* write-read register */
	LAPIC_REG(ERROR_STATUS) = 0;
	return LAPIC_REG(ERROR_STATUS);
}

void 
lapic_esr_clear(void)
{
	LAPIC_REG(ERROR_STATUS) = 0;
	LAPIC_REG(ERROR_STATUS) = 0;
}

static char *DM[8] = {
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
	char	buf[128];

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
	kprintf("LVT_PERFCNT: Vector 0x%02x [%s][%s][%s] %s %cmasked\n",
		LAPIC_REG(LVT_PERFCNT)&LAPIC_LVT_VECTOR_MASK,
		DM[(LAPIC_REG(LVT_PERFCNT)>>LAPIC_LVT_DM_SHIFT)&LAPIC_LVT_DM_MASK],
		(LAPIC_REG(LVT_PERFCNT)&LAPIC_LVT_TM_LEVEL)?"Level":"Edge ",
		(LAPIC_REG(LVT_PERFCNT)&LAPIC_LVT_IP_PLRITY_LOW)?"Low ":"High",
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

void
lapic_init(void)
{
	int	value;

	mp_disable_preemption();

	/* Set flat delivery model, logical processor id */
	LAPIC_REG(DFR) = LAPIC_DFR_FLAT;
	LAPIC_REG(LDR) = (get_cpu_number()) << LAPIC_LDR_SHIFT;

	/* Accept all */
	LAPIC_REG(TPR) =  0;

	LAPIC_REG(SVR) = SPURIOUS_INTERRUPT | LAPIC_SVR_ENABLE;

	/* ExtINT */
	if (get_cpu_number() == master_cpu) {
		value = LAPIC_REG(LVT_LINT0);
		value |= LAPIC_LVT_DM_EXTINT;
		LAPIC_REG(LVT_LINT0) = value;
	}

	lapic_esr_clear();

	LAPIC_REG(LVT_ERROR) = APIC_ERROR_INTERRUPT;

	mp_enable_preemption();
}


void
lapic_end_of_interrupt(void)
{
	LAPIC_REG(EOI) = 0;
}

void
lapic_interrupt(int interrupt, void *state)
{

	switch(interrupt) {
	case APIC_ERROR_INTERRUPT:
		panic("Local APIC error\n");
		break;
	case SPURIOUS_INTERRUPT:
		kprintf("SPIV\n");
		break;
	case INTERPROCESS_INTERRUPT:
		cpu_signal_handler((struct i386_interrupt_state *) state);
		break;
	}
	lapic_end_of_interrupt();
}

kern_return_t
intel_startCPU(
	int	slot_num)
{

	int	i = 1000;
	int	lapic_id = cpu_to_lapic[slot_num];

	if (slot_num == get_cpu_number())
		return KERN_SUCCESS;

	assert(lapic_id != -1);

	DBG("intel_startCPU(%d) lapic_id=%d\n", slot_num, lapic_id);

	mp_disable_preemption();

	LAPIC_REG(ICRD) = lapic_id << LAPIC_ICRD_DEST_SHIFT;
	LAPIC_REG(ICR) = LAPIC_ICR_DM_INIT;
	delay(10000);

	LAPIC_REG(ICRD) = lapic_id << LAPIC_ICRD_DEST_SHIFT;
	LAPIC_REG(ICR) = LAPIC_ICR_DM_STARTUP|(MP_BOOT>>12);
	delay(200);

	while(i-- > 0) {
		delay(10000);
		if (machine_slot[slot_num].running)
			break;
	}

	mp_enable_preemption();

	if (!machine_slot[slot_num].running) {
		DBG("Failed to start CPU %02d\n", slot_num);
		printf("Failed to start CPU %02d\n", slot_num);
		return KERN_SUCCESS;
	} else {
		DBG("Started CPU %02d\n", slot_num);
		printf("Started CPU %02d\n", slot_num);
		return KERN_SUCCESS;
	}
}

void
slave_boot_init(void)
{
	extern char	slave_boot_base[];
	extern char	slave_boot_end[];
	extern void	pstart(void);

	DBG("slave_base=%p slave_end=%p MP_BOOT P=%p V=%p\n",
		slave_boot_base, slave_boot_end, MP_BOOT, phystokv(MP_BOOT));

	/*
	 * Copy the boot entry code to the real-mode vector area MP_BOOT.
	 * This is in page 1 which has been reserved for this purpose by
	 * machine_startup() from the boot processor.
	 * The slave boot code is responsible for switching to protected
	 * mode and then jumping to the common startup, pstart().
	 */
	bcopy(slave_boot_base,
	      (char *)phystokv(MP_BOOT),
	      slave_boot_end-slave_boot_base);

	/*
	 * Zero a stack area above the boot code.
	 */
	bzero((char *)(phystokv(MP_BOOTSTACK+MP_BOOT)-0x400), 0x400);

	/*
	 * Set the location at the base of the stack to point to the
	 * common startup entry.
	 */
	*((vm_offset_t *) phystokv(MP_MACH_START+MP_BOOT)) =
						kvtophys((vm_offset_t)&pstart);
	
	/* Flush caches */
	__asm__("wbinvd");
}

#if	MP_DEBUG
cpu_signal_event_log_t	cpu_signal[NCPUS] = { 0, 0, 0 };
cpu_signal_event_log_t	cpu_handle[NCPUS] = { 0, 0, 0 };

MP_EVENT_NAME_DECL();

void
cpu_signal_dump_last(int cpu)
{
	cpu_signal_event_log_t	*logp = &cpu_signal[cpu];
	int			last;
	cpu_signal_event_t	*eventp;

	last = (logp->next_entry == 0) ? 
			LOG_NENTRIES - 1 : logp->next_entry - 1;
	
	eventp = &logp->entry[last];

	kprintf("cpu%d: tsc=%lld cpu_signal(%d,%s)\n",
		cpu, eventp->time, eventp->cpu, mp_event_name[eventp->event]);
}

void
cpu_handle_dump_last(int cpu)
{
	cpu_signal_event_log_t	*logp = &cpu_handle[cpu];
	int			last;
	cpu_signal_event_t	*eventp;

	last = (logp->next_entry == 0) ? 
			LOG_NENTRIES - 1 : logp->next_entry - 1;
	
	eventp = &logp->entry[last];

	kprintf("cpu%d: tsc=%lld cpu_signal_handle%s\n",
		cpu, eventp->time, mp_event_name[eventp->event]);
}
#endif	/* MP_DEBUG */

void
cpu_signal_handler(struct i386_interrupt_state *regs)
{
	register	my_cpu;
	volatile int	*my_word;
#if	MACH_KDB && MACH_ASSERT
	int		i=100;
#endif	/* MACH_KDB && MACH_ASSERT */

	mp_disable_preemption();

	my_cpu = cpu_number();
	my_word = &cpu_data[my_cpu].cpu_signals;

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
		if (i_bit(MP_CLOCK, my_word)) {
			DBGLOG(cpu_handle,my_cpu,MP_CLOCK);
			i_bit_clear(MP_CLOCK, my_word);
			hardclock(regs);
		} else if (i_bit(MP_TLB_FLUSH, my_word)) {
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

void
cpu_interrupt(int cpu)
{
	boolean_t	state;

	if (smp_initialized) {

		/* Wait for previous interrupt to be delivered... */
		while (LAPIC_REG(ICR) & LAPIC_ICR_DS_PENDING)
			cpu_pause();

		state = ml_set_interrupts_enabled(FALSE);
		LAPIC_REG(ICRD) =
			cpu_to_lapic[cpu] << LAPIC_ICRD_DEST_SHIFT;
		LAPIC_REG(ICR)  =
			INTERPROCESS_INTERRUPT | LAPIC_ICR_DM_FIXED;
		(void) ml_set_interrupts_enabled(state);
	}

}

void
slave_clock(void)
{
	int	cpu;

	/*
	 * Clock interrupts are chained from the boot processor
	 * to the next logical processor that is running and from
	 * there on to any further running processor etc.
	 */
	mp_disable_preemption();
	for (cpu=cpu_number()+1; cpu<NCPUS; cpu++)
		if (machine_slot[cpu].running) {
			i386_signal_cpu(cpu, MP_CLOCK, ASYNC);
			mp_enable_preemption();
			return;
		}
	mp_enable_preemption();

}

void
i386_signal_cpu(int cpu, mp_event_t event, mp_sync_t mode)
{
	volatile int	*signals = &cpu_data[cpu].cpu_signals;
	uint64_t	timeout;
	

	if (!cpu_data[cpu].cpu_status)
		return;

	DBGLOG(cpu_signal, cpu, event);

	i_bit_set(event, signals);
	cpu_interrupt(cpu);
	if (mode == SYNC) {
	   again:
		timeout = rdtsc64() + (1000*1000*1000);
		while (i_bit(event, signals) && rdtsc64() < timeout) {
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
	int	cpu;
	int	my_cpu = cpu_number();

	for (cpu = 0; cpu < NCPUS; cpu++) {
		if (cpu == my_cpu || !machine_slot[cpu].running)
			continue;
		i386_signal_cpu(cpu, event, mode);
	}
}

int
i386_active_cpus(void)
{
	int	cpu;
	int	ncpus = 0;

	for (cpu = 0; cpu < NCPUS; cpu++) {
		if (machine_slot[cpu].running)
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
	while (mp_rv_waiters[0] < mp_rv_ncpus)
		cpu_pause();
	/* action function */
	if (mp_rv_action_func != NULL)
		mp_rv_action_func(mp_rv_func_arg);
	/* spin on exit rendezvous */
	atomic_incl(&mp_rv_waiters[1], 1);
	while (mp_rv_waiters[1] < mp_rv_ncpus)
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

void
mp_kdp_enter(void)
{
	int		cpu;
	int		ncpus;
	int		my_cpu = cpu_number();
	boolean_t	state;
	uint64_t	timeout;

	DBG("mp_kdp_enter()\n");

	/*
	 * Here to enter the debugger.
	 * In case of races, only one cpu is allowed to enter kdp after
	 * stopping others.
	 */
	state = ml_set_interrupts_enabled(FALSE);
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
	(void) ml_set_interrupts_enabled(state);

	/* Deliver a nudge to other cpus, counting how many */
	DBG("mp_kdp_enter() signaling other processors\n");
	for (ncpus = 1, cpu = 0; cpu < NCPUS; cpu++) {
		if (cpu == my_cpu || !machine_slot[cpu].running)
			continue;
		ncpus++;
		i386_signal_cpu(cpu, MP_KDP, ASYNC); 
	}

	/* Wait other processors to spin. */
	DBG("mp_kdp_enter() waiting for (%d) processors to suspend\n", ncpus);
	timeout = rdtsc64() + (1000*1000*1000);
	while (*((volatile long *) &mp_kdp_ncpus) != ncpus
		&& rdtsc64() < timeout) {
		cpu_pause();
	}
	DBG("mp_kdp_enter() %d processors done %s\n",
		mp_kdp_ncpus, (mp_kdp_ncpus == ncpus) ? "OK" : "timed out");
}

static void
mp_kdp_wait(void)
{
	DBG("mp_kdp_wait()\n");
	atomic_incl(&mp_kdp_ncpus, 1);
	while (mp_kdp_trap) {
		cpu_pause();
	}
	atomic_decl(&mp_kdp_ncpus, 1);
	DBG("mp_kdp_wait() done\n");
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
}
#endif	/* MACH_KDP */

void
lapic_test(void)
{
	int	cpu = 1;

	lapic_dump();
	i_bit_set(0, &cpu_data[cpu].cpu_signals);
	cpu_interrupt(1);
}

/*ARGSUSED*/
void
init_ast_check(
	processor_t	processor)
{
}

void
cause_ast_check(
	processor_t	processor)
{
	int	cpu = processor->slot_num;

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
	int	my_cpu = cpu_number();
	int	cpu;
	
	mp_disable_preemption();
	for (cpu = 0; cpu < NCPUS; cpu++) {
		if (cpu == my_cpu || !machine_slot[cpu].running)
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
	i_bit_clear(MP_KDB, &cpu_data[cpu_number()].cpu_signals);
	mp_enable_preemption();
}

void
slave_machine_init(void)
{
	int	my_cpu;

	/* Ensure that caching and write-through are enabled */
	set_cr0(get_cr0() & ~(CR0_NW|CR0_CD));

	mp_disable_preemption();
	my_cpu = get_cpu_number();

	DBG("slave_machine_init() CPU%d: phys (%d) active.\n",
		my_cpu, get_cpu_phys_number());

	lapic_init();

	init_fpu();

	cpu_machine_init();

	mp_enable_preemption();

#ifdef MP_DEBUG
	lapic_dump();
	lapic_cpu_map_dump();
#endif /* MP_DEBUG */

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

