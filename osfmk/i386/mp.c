/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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

#include <mach_rt.h>
#include <mach_kdb.h>
#include <mach_kdp.h>
#include <mach_ldebug.h>
#include <gprof.h>

#include <mach/mach_types.h>
#include <mach/kern_return.h>

#include <kern/kern_types.h>
#include <kern/startup.h>
#include <kern/timer_queue.h>
#include <kern/processor.h>
#include <kern/cpu_number.h>
#include <kern/cpu_data.h>
#include <kern/assert.h>
#include <kern/machine.h>
#include <kern/pms.h>
#include <kern/misc_protos.h>

#include <vm/vm_map.h>
#include <vm/vm_kern.h>

#include <profiling/profile-mk.h>

#include <i386/proc_reg.h>
#include <i386/cpu_threads.h>
#include <i386/mp_desc.h>
#include <i386/misc_protos.h>
#include <i386/trap.h>
#include <i386/postcode.h>
#include <i386/machine_routines.h>
#include <i386/mp.h>
#include <i386/mp_events.h>
#include <i386/lapic.h>
#include <i386/ipl.h>
#include <i386/cpuid.h>
#include <i386/fpu.h>
#include <i386/machine_cpu.h>
#include <i386/mtrr.h>
#include <i386/pmCPU.h>
#if CONFIG_MCA
#include <i386/machine_check.h>
#endif
#include <i386/acpi.h>

#include <chud/chud_xnu.h>
#include <chud/chud_xnu_private.h>

#include <sys/kdebug.h>
#if MACH_KDB
#include <machine/db_machdep.h>
#include <ddb/db_aout.h>
#include <ddb/db_access.h>
#include <ddb/db_sym.h>
#include <ddb/db_variables.h>
#include <ddb/db_command.h>
#include <ddb/db_output.h>
#include <ddb/db_expr.h>
#endif

#if	MP_DEBUG
#define PAUSE		delay(1000000)
#define DBG(x...)	kprintf(x)
#else
#define DBG(x...)
#define PAUSE
#endif	/* MP_DEBUG */


void 		slave_boot_init(void);

#if MACH_KDB
static void	mp_kdb_wait(void);
volatile boolean_t	mp_kdb_trap = FALSE;
volatile long	mp_kdb_ncpus = 0;
#endif

static void	mp_kdp_wait(boolean_t flush, boolean_t isNMI);
static void	mp_rendezvous_action(void);
static void 	mp_broadcast_action(void);

static boolean_t	cpu_signal_pending(int cpu, mp_event_t event);
static int		cpu_signal_handler(x86_saved_state_t *regs);
static int		NMIInterruptHandler(x86_saved_state_t *regs);

boolean_t 		smp_initialized = FALSE;
volatile boolean_t	force_immediate_debugger_NMI = FALSE;
volatile boolean_t	pmap_tlb_flush_timeout = FALSE;
decl_simple_lock_data(,mp_kdp_lock);

decl_lck_mtx_data(static, mp_cpu_boot_lock);
lck_mtx_ext_t	mp_cpu_boot_lock_ext;

/* Variables needed for MP rendezvous. */
decl_simple_lock_data(,mp_rv_lock);
static void	(*mp_rv_setup_func)(void *arg);
static void	(*mp_rv_action_func)(void *arg);
static void	(*mp_rv_teardown_func)(void *arg);
static void	*mp_rv_func_arg;
static volatile int	mp_rv_ncpus;
			/* Cache-aligned barriers: */
static volatile long	mp_rv_entry    __attribute__((aligned(64)));
static volatile long	mp_rv_exit     __attribute__((aligned(64)));
static volatile long	mp_rv_complete __attribute__((aligned(64)));

volatile	uint64_t	debugger_entry_time;
volatile	uint64_t	debugger_exit_time;
#if MACH_KDP

static struct _kdp_xcpu_call_func {
	kdp_x86_xcpu_func_t func;
	void     *arg0, *arg1;
	volatile long     ret;
	volatile uint16_t cpu;
} kdp_xcpu_call_func = {
	.cpu  = KDP_XCPU_NONE
};

#endif

/* Variables needed for MP broadcast. */
static void        (*mp_bc_action_func)(void *arg);
static void        *mp_bc_func_arg;
static int     	mp_bc_ncpus;
static volatile long   mp_bc_count;
decl_lck_mtx_data(static, mp_bc_lock);
lck_mtx_ext_t	mp_bc_lock_ext;
static	volatile int 	debugger_cpu = -1;

static void	mp_cpus_call_action(void); 
static void	mp_call_PM(void);

char		mp_slave_stack[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE))); // Temp stack for slave init


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

static lck_grp_t 	smp_lck_grp;
static lck_grp_attr_t	smp_lck_grp_attr;

extern void	slave_pstart(void);

void
smp_init(void)
{
	simple_lock_init(&mp_kdp_lock, 0);
	simple_lock_init(&mp_rv_lock, 0);
	lck_grp_attr_setdefault(&smp_lck_grp_attr);
	lck_grp_init(&smp_lck_grp, "i386_smp", &smp_lck_grp_attr);
	lck_mtx_init_ext(&mp_cpu_boot_lock, &mp_cpu_boot_lock_ext, &smp_lck_grp, LCK_ATTR_NULL);
	lck_mtx_init_ext(&mp_bc_lock, &mp_bc_lock_ext, &smp_lck_grp, LCK_ATTR_NULL);
	console_init();

	/* Local APIC? */
	if (!lapic_probe())
		return;

	lapic_init();
	lapic_configure();
	lapic_set_intr_func(LAPIC_NMI_INTERRUPT,  NMIInterruptHandler);
	lapic_set_intr_func(LAPIC_VECTOR(INTERPROCESSOR), cpu_signal_handler);

	cpu_thread_init();

	GPROF_INIT();
	DBGLOG_CPU_INIT(master_cpu);

	install_real_mode_bootstrap(slave_pstart);

	smp_initialized = TRUE;

	return;
}

/*
 * Poll a CPU to see when it has marked itself as running.
 */
static void
mp_wait_for_cpu_up(int slot_num, unsigned int iters, unsigned int usecdelay)
{
    	while (iters-- > 0) {
		if (cpu_datap(slot_num)->cpu_running)
	    		break;
		delay(usecdelay);
	}
}

/*
 * Quickly bring a CPU back online which has been halted.
 */
kern_return_t
intel_startCPU_fast(int slot_num)
{
    	kern_return_t	rc;

	/*
	 * Try to perform a fast restart
	 */
	rc = pmCPUExitHalt(slot_num);
	if (rc != KERN_SUCCESS)
		/*
		 * The CPU was not eligible for a fast restart.
		 */
		return(rc);

	/*
	 * Wait until the CPU is back online.
	 */
	mp_disable_preemption();
    
	/*
	 * We use short pauses (1us) for low latency.  30,000 iterations is
	 * longer than a full restart would require so it should be more
	 * than long enough.
	 */
	mp_wait_for_cpu_up(slot_num, 30000, 1);
	mp_enable_preemption();

	/*
	 * Check to make sure that the CPU is really running.  If not,
	 * go through the slow path.
	 */
	if (cpu_datap(slot_num)->cpu_running)
		return(KERN_SUCCESS);
    	else
		return(KERN_FAILURE);
}

typedef struct {
	int	target_cpu;
	int	target_lapic;
	int	starter_cpu;
} processor_start_info_t;

static processor_start_info_t start_info;

static void
start_cpu(void *arg)
{
	int			i = 1000;
	processor_start_info_t	*psip = (processor_start_info_t *) arg;

	/* Ignore this if the current processor is not the starter */
	if (cpu_number() != psip->starter_cpu)
		return;

	LAPIC_WRITE(ICRD, psip->target_lapic << LAPIC_ICRD_DEST_SHIFT);
	LAPIC_WRITE(ICR, LAPIC_ICR_DM_INIT);
	delay(100);

	LAPIC_WRITE(ICRD, psip->target_lapic << LAPIC_ICRD_DEST_SHIFT);
	LAPIC_WRITE(ICR, LAPIC_ICR_DM_STARTUP|(REAL_MODE_BOOTSTRAP_OFFSET>>12));

#ifdef	POSTCODE_DELAY
	/* Wait much longer if postcodes are displayed for a delay period. */
	i *= 10000;
#endif
	mp_wait_for_cpu_up(psip->target_cpu, i*100, 100);
}

extern char	prot_mode_gdt[];
extern char	slave_boot_base[];
extern char real_mode_bootstrap_base[];
extern char real_mode_bootstrap_end[];
extern char	slave_boot_end[];

kern_return_t
intel_startCPU(
	int	slot_num)
{
	int		lapic = cpu_to_lapic[slot_num];
	boolean_t	istate;

	assert(lapic != -1);

	DBGLOG_CPU_INIT(slot_num);

	DBG("intel_startCPU(%d) lapic_id=%d\n", slot_num, lapic);
	DBG("IdlePTD(%p): 0x%x\n", &IdlePTD, (int) IdlePTD);

	/*
	 * Initialize (or re-initialize) the descriptor tables for this cpu.
	 * Propagate processor mode to slave.
	 */
	if (cpu_mode_is64bit())
		cpu_desc_init64(cpu_datap(slot_num));
	else
		cpu_desc_init(cpu_datap(slot_num));

	/* Serialize use of the slave boot stack, etc. */
	lck_mtx_lock(&mp_cpu_boot_lock);

	istate = ml_set_interrupts_enabled(FALSE);
	if (slot_num == get_cpu_number()) {
		ml_set_interrupts_enabled(istate);
		lck_mtx_unlock(&mp_cpu_boot_lock);
		return KERN_SUCCESS;
	}

	start_info.starter_cpu  = cpu_number();
	start_info.target_cpu   = slot_num;
	start_info.target_lapic = lapic;

	/*
	 * Perform the processor startup sequence with all running
	 * processors rendezvous'ed. This is required during periods when
	 * the cache-disable bit is set for MTRR/PAT initialization.
	 */
	mp_rendezvous_no_intrs(start_cpu, (void *) &start_info);

	ml_set_interrupts_enabled(istate);
	lck_mtx_unlock(&mp_cpu_boot_lock);

	if (!cpu_datap(slot_num)->cpu_running) {
		kprintf("Failed to start CPU %02d\n", slot_num);
		printf("Failed to start CPU %02d, rebooting...\n", slot_num);
		delay(1000000);
		halt_cpu();
		return KERN_SUCCESS;
	} else {
		kprintf("Started cpu %d (lapic id %08x)\n", slot_num, lapic);
		return KERN_SUCCESS;
	}
}

#if	MP_DEBUG
cpu_signal_event_log_t	*cpu_signal[MAX_CPUS];
cpu_signal_event_log_t	*cpu_handle[MAX_CPUS];

MP_EVENT_NAME_DECL();

#endif	/* MP_DEBUG */

int
cpu_signal_handler(x86_saved_state_t *regs)
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
		    Debugger("cpu_signal_handler: signals did not clear");
#endif	/* MACH_KDB && MACH_ASSERT */
#if	MACH_KDP
		if (i_bit(MP_KDP, my_word)) {
			DBGLOG(cpu_handle,my_cpu,MP_KDP);
			i_bit_clear(MP_KDP, my_word);
/* Ensure that the i386_kernel_state at the base of the
 * current thread's stack (if any) is synchronized with the
 * context at the moment of the interrupt, to facilitate
 * access through the debugger.
 */
			sync_iss_to_iks(regs);
			mp_kdp_wait(TRUE, FALSE);
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

			i_bit_clear(MP_KDB, my_word);
			current_cpu_datap()->cpu_kdb_is_slave++;
			mp_kdb_wait();
			current_cpu_datap()->cpu_kdb_is_slave--;
#endif	/* MACH_KDB */
		} else if (i_bit(MP_RENDEZVOUS, my_word)) {
			DBGLOG(cpu_handle,my_cpu,MP_RENDEZVOUS);
			i_bit_clear(MP_RENDEZVOUS, my_word);
			mp_rendezvous_action();
		} else if (i_bit(MP_BROADCAST, my_word)) {
			DBGLOG(cpu_handle,my_cpu,MP_BROADCAST);
			i_bit_clear(MP_BROADCAST, my_word);
			mp_broadcast_action();
		} else if (i_bit(MP_CHUD, my_word)) {
			DBGLOG(cpu_handle,my_cpu,MP_CHUD);
			i_bit_clear(MP_CHUD, my_word);
			chudxnu_cpu_signal_handler();
		} else if (i_bit(MP_CALL, my_word)) {
			DBGLOG(cpu_handle,my_cpu,MP_CALL);
			i_bit_clear(MP_CALL, my_word);
			mp_cpus_call_action();
		} else if (i_bit(MP_CALL_PM, my_word)) {
			DBGLOG(cpu_handle,my_cpu,MP_CALL_PM);
			i_bit_clear(MP_CALL_PM, my_word);
			mp_call_PM();
		}
	} while (*my_word);

	mp_enable_preemption();

	return 0;
}

static int
NMIInterruptHandler(x86_saved_state_t *regs)
{
	void 	*stackptr;
	
	sync_iss_to_iks_unconditionally(regs);
#if defined (__i386__)
	__asm__ volatile("movl %%ebp, %0" : "=m" (stackptr));
#elif defined (__x86_64__)
	__asm__ volatile("movq %%rbp, %0" : "=m" (stackptr));
#endif

	if (cpu_number() == debugger_cpu)
			goto NMExit;

	if (pmap_tlb_flush_timeout == TRUE && current_cpu_datap()->cpu_tlb_invalid) {
		char pstr[128];
		snprintf(&pstr[0], sizeof(pstr), "Panic(CPU %d): Unresponsive processor\n", cpu_number());
		panic_i386_backtrace(stackptr, 16, &pstr[0], TRUE, regs);
	}

#if MACH_KDP
	mp_kdp_wait(FALSE, pmap_tlb_flush_timeout);
#endif
NMExit:	
	return 1;
}

#ifdef	MP_DEBUG
int	max_lock_loops = 100000000;
int		trappedalready = 0;	/* (BRINGUP) */
#endif	/* MP_DEBUG */

static void
i386_cpu_IPI(int cpu)
{
	boolean_t	state;
	
#ifdef	MP_DEBUG
	if(cpu_datap(cpu)->cpu_signals & 6) {	/* (BRINGUP) */
		kprintf("i386_cpu_IPI: sending enter debugger signal (%08X) to cpu %d\n", cpu_datap(cpu)->cpu_signals, cpu);
	}
#endif	/* MP_DEBUG */

#if MACH_KDB
#ifdef	MP_DEBUG
	if(!trappedalready && (cpu_datap(cpu)->cpu_signals & 6)) {	/* (BRINGUP) */
		if(kdb_cpu != cpu_number()) {
			trappedalready = 1;
			panic("i386_cpu_IPI: sending enter debugger signal (%08X) to cpu %d and I do not own debugger, owner = %08X\n", 
				cpu_datap(cpu)->cpu_signals, cpu, kdb_cpu);
		}
	}
#endif	/* MP_DEBUG */
#endif

	/* Wait for previous interrupt to be delivered... */
#ifdef	MP_DEBUG
	int     pending_busy_count = 0;
	while (LAPIC_READ(ICR) & LAPIC_ICR_DS_PENDING) {
		if (++pending_busy_count > max_lock_loops)
			panic("i386_cpu_IPI() deadlock\n");
#else
	while (LAPIC_READ(ICR) & LAPIC_ICR_DS_PENDING) {
#endif	/* MP_DEBUG */
		cpu_pause();
	}

	state = ml_set_interrupts_enabled(FALSE);
	LAPIC_WRITE(ICRD, cpu_to_lapic[cpu] << LAPIC_ICRD_DEST_SHIFT);
	LAPIC_WRITE(ICR, LAPIC_VECTOR(INTERPROCESSOR) | LAPIC_ICR_DM_FIXED);
	(void) ml_set_interrupts_enabled(state);
}

/*
 * cpu_interrupt is really just to be used by the scheduler to
 * get a CPU's attention it may not always issue an IPI.  If an
 * IPI is always needed then use i386_cpu_IPI.
 */
void
cpu_interrupt(int cpu)
{
	if (smp_initialized
	    && pmCPUExitIdle(cpu_datap(cpu))) {
		i386_cpu_IPI(cpu);
	}
}

/*
 * Send a true NMI via the local APIC to the specified CPU.
 */
void
cpu_NMI_interrupt(int cpu)
{
	boolean_t	state;

	if (smp_initialized) {
		state = ml_set_interrupts_enabled(FALSE);
/* Program the interrupt command register */
		LAPIC_WRITE(ICRD, cpu_to_lapic[cpu] << LAPIC_ICRD_DEST_SHIFT);
/* The vector is ignored in this case--the target CPU will enter on the
 * NMI vector.
 */
		LAPIC_WRITE(ICR, LAPIC_VECTOR(INTERPROCESSOR)|LAPIC_ICR_DM_NMI);
		(void) ml_set_interrupts_enabled(state);
	}
}

static void	(* volatile mp_PM_func)(void) = NULL;

static void
mp_call_PM(void)
{
	assert(!ml_get_interrupts_enabled());

	if (mp_PM_func != NULL)
		mp_PM_func();
}

void
cpu_PM_interrupt(int cpu)
{
	assert(!ml_get_interrupts_enabled());

	if (mp_PM_func != NULL) {
		if (cpu == cpu_number())
			mp_PM_func();
		else
			i386_signal_cpu(cpu, MP_CALL_PM, ASYNC);
	}
}

void
PM_interrupt_register(void (*fn)(void))
{
	mp_PM_func = fn;
}

void
i386_signal_cpu(int cpu, mp_event_t event, mp_sync_t mode)
{
	volatile int	*signals = &cpu_datap(cpu)->cpu_signals;
	uint64_t	tsc_timeout;

	
	if (!cpu_datap(cpu)->cpu_running)
		return;

	if (event == MP_TLB_FLUSH)
	        KERNEL_DEBUG(0xef800020 | DBG_FUNC_START, cpu, 0, 0, 0, 0);

	DBGLOG(cpu_signal, cpu, event);
	
	i_bit_set(event, signals);
	i386_cpu_IPI(cpu);
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
	if (event == MP_TLB_FLUSH)
	        KERNEL_DEBUG(0xef800020 | DBG_FUNC_END, cpu, 0, 0, 0, 0);
}

/*
 * Send event to all running cpus.
 * Called with the topology locked.
 */
void
i386_signal_cpus(mp_event_t event, mp_sync_t mode)
{
	unsigned int	cpu;
	unsigned int	my_cpu = cpu_number();

	assert(hw_lock_held((hw_lock_t)&x86_topo_lock));

	for (cpu = 0; cpu < real_ncpus; cpu++) {
		if (cpu == my_cpu || !cpu_datap(cpu)->cpu_running)
			continue;
		i386_signal_cpu(cpu, event, mode);
	}
}

/*
 * Return the number of running cpus.
 * Called with the topology locked.
 */
int
i386_active_cpus(void)
{
	unsigned int	cpu;
	unsigned int	ncpus = 0;

	assert(hw_lock_held((hw_lock_t)&x86_topo_lock));

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
	boolean_t intrs_enabled;

	/* setup function */
	if (mp_rv_setup_func != NULL)
		mp_rv_setup_func(mp_rv_func_arg);

	intrs_enabled = ml_get_interrupts_enabled();


	/* spin on entry rendezvous */
	atomic_incl(&mp_rv_entry, 1);
	while (mp_rv_entry < mp_rv_ncpus) {
		/* poll for pesky tlb flushes if interrupts disabled */
		if (!intrs_enabled)
			handle_pending_TLB_flushes();
		cpu_pause();
	}
	/* action function */
	if (mp_rv_action_func != NULL)
		mp_rv_action_func(mp_rv_func_arg);
	/* spin on exit rendezvous */
	atomic_incl(&mp_rv_exit, 1);
	while (mp_rv_exit < mp_rv_ncpus) {
		if (!intrs_enabled)
			handle_pending_TLB_flushes();
		cpu_pause();
	}
	/* teardown function */
	if (mp_rv_teardown_func != NULL)
		mp_rv_teardown_func(mp_rv_func_arg);

	/* Bump completion count */
	atomic_incl(&mp_rv_complete, 1);
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

	mp_rv_entry    = 0;
	mp_rv_exit     = 0;
	mp_rv_complete = 0;

	/*
	 * signal other processors, which will call mp_rendezvous_action()
	 * with interrupts disabled
	 */
	simple_lock(&x86_topo_lock);
	mp_rv_ncpus = i386_active_cpus();
	i386_signal_cpus(MP_RENDEZVOUS, ASYNC);
	simple_unlock(&x86_topo_lock);

	/* call executor function on this cpu */
	mp_rendezvous_action();

	/*
	 * Spin for everyone to complete.
	 * This is necessary to ensure that all processors have proceeded
	 * from the exit barrier before we release the rendezvous structure.
	 */
	while (mp_rv_complete < mp_rv_ncpus) {
		cpu_pause();
	}
	
	/* Tidy up */
	mp_rv_setup_func = NULL;
	mp_rv_action_func = NULL;
	mp_rv_teardown_func = NULL;
	mp_rv_func_arg = NULL;

	/* release lock */
	simple_unlock(&mp_rv_lock);
}

void
mp_rendezvous_break_lock(void)
{
	simple_lock_init(&mp_rv_lock, 0);
}

static void
setup_disable_intrs(__unused void * param_not_used)
{
	/* disable interrupts before the first barrier */
	boolean_t intr = ml_set_interrupts_enabled(FALSE);

	current_cpu_datap()->cpu_iflag = intr;
	DBG("CPU%d: %s\n", get_cpu_number(), __FUNCTION__);
}

static void
teardown_restore_intrs(__unused void * param_not_used)
{
	/* restore interrupt flag following MTRR changes */
	ml_set_interrupts_enabled(current_cpu_datap()->cpu_iflag);
	DBG("CPU%d: %s\n", get_cpu_number(), __FUNCTION__);
}

/*
 * A wrapper to mp_rendezvous() to call action_func() with interrupts disabled.
 * This is exported for use by kexts.
 */
void
mp_rendezvous_no_intrs(
	      void (*action_func)(void *),
	      void *arg)
{
	mp_rendezvous(setup_disable_intrs,
		      action_func,
		      teardown_restore_intrs,
		      arg);	
}

void
handle_pending_TLB_flushes(void)
{
	volatile int	*my_word = &current_cpu_datap()->cpu_signals;

	if (i_bit(MP_TLB_FLUSH, my_word)) {
		DBGLOG(cpu_handle, cpu_number(), MP_TLB_FLUSH);
		i_bit_clear(MP_TLB_FLUSH, my_word);
		pmap_update_interrupt();
	}
}

/*
 * This is called from cpu_signal_handler() to process an MP_CALL signal.
 */
static void
mp_cpus_call_action(void)
{
	if (mp_rv_action_func != NULL)
		mp_rv_action_func(mp_rv_func_arg);
	atomic_incl(&mp_rv_complete, 1);
}

/*
 * mp_cpus_call() runs a given function on cpus specified in a given cpu mask.
 * If the mode is SYNC, the function is called serially on the target cpus
 * in logical cpu order. If the mode is ASYNC, the function is called in
 * parallel over the specified cpus.
 * The action function may be NULL.
 * The cpu mask may include the local cpu. Offline cpus are ignored.
 * Return does not occur until the function has completed on all cpus.
 * The return value is the number of cpus on which the function was called.
 */
cpu_t
mp_cpus_call(
	cpumask_t	cpus,
	mp_sync_t	mode,
        void		(*action_func)(void *),
        void		*arg)
{
	cpu_t		cpu;
	boolean_t	intrs_enabled = ml_get_interrupts_enabled();
	boolean_t	call_self = FALSE;

	if (!smp_initialized) {
		if ((cpus & CPUMASK_SELF) == 0)
			return 0;
		if (action_func != NULL) {
			(void) ml_set_interrupts_enabled(FALSE);
			action_func(arg);
			ml_set_interrupts_enabled(intrs_enabled);
		}
		return 1;
	}
		
	/* obtain rendezvous lock */
	simple_lock(&mp_rv_lock);

	/* Use the rendezvous data structures for this call */
	mp_rv_action_func = action_func;
	mp_rv_func_arg = arg;
	mp_rv_ncpus = 0;
	mp_rv_complete = 0;

	simple_lock(&x86_topo_lock);
	for (cpu = 0; cpu < (cpu_t) real_ncpus; cpu++) {
		if (((cpu_to_cpumask(cpu) & cpus) == 0) ||
		    !cpu_datap(cpu)->cpu_running)
			continue;
		if (cpu == (cpu_t) cpu_number()) {
			/*
			 * We don't IPI ourself and if calling asynchronously,
			 * we defer our call until we have signalled all others.
			 */
			call_self = TRUE;
			if (mode == SYNC && action_func != NULL) {
				(void) ml_set_interrupts_enabled(FALSE);
				action_func(arg);
				ml_set_interrupts_enabled(intrs_enabled);
			}
		} else {
			/*
			 * Bump count of other cpus called and signal this cpu.
			 * Note: we signal asynchronously regardless of mode
			 * because we wait on mp_rv_complete either here
			 * (if mode == SYNC) or later (if mode == ASYNC).
			 * While spinning, poll for TLB flushes if interrupts
			 * are disabled.
			 */
			mp_rv_ncpus++;
			i386_signal_cpu(cpu, MP_CALL, ASYNC);
			if (mode == SYNC) {
				simple_unlock(&x86_topo_lock);
				while (mp_rv_complete < mp_rv_ncpus) {
					if (!intrs_enabled)
						handle_pending_TLB_flushes();
					cpu_pause();
				}
				simple_lock(&x86_topo_lock);
			}
		}
	}
	simple_unlock(&x86_topo_lock);

	/*
	 * If calls are being made asynchronously,
	 * make the local call now if needed, and then
	 * wait for all other cpus to finish their calls.
	 */
	if (mode == ASYNC) {
		if (call_self && action_func != NULL) {
			(void) ml_set_interrupts_enabled(FALSE);
			action_func(arg);
			ml_set_interrupts_enabled(intrs_enabled);
		}
		while (mp_rv_complete < mp_rv_ncpus) {
			if (!intrs_enabled)
				handle_pending_TLB_flushes();
			cpu_pause();
		}
	}
	
	/* Determine the number of cpus called */
	cpu = mp_rv_ncpus + (call_self ? 1 : 0);

	simple_unlock(&mp_rv_lock);

	return cpu;
}

static void
mp_broadcast_action(void)
{
   /* call action function */
   if (mp_bc_action_func != NULL)
       mp_bc_action_func(mp_bc_func_arg);

   /* if we're the last one through, wake up the instigator */
   if (atomic_decl_and_test(&mp_bc_count, 1))
       thread_wakeup(((event_t)(uintptr_t) &mp_bc_count));
}

/*
 * mp_broadcast() runs a given function on all active cpus.
 * The caller blocks until the functions has run on all cpus.
 * The caller will also block if there is another pending braodcast.
 */
void
mp_broadcast(
         void (*action_func)(void *),
         void *arg)
{
   if (!smp_initialized) {
       if (action_func != NULL)
	           action_func(arg);
       return;
   }
       
   /* obtain broadcast lock */
   lck_mtx_lock(&mp_bc_lock);

   /* set static function pointers */
   mp_bc_action_func = action_func;
   mp_bc_func_arg = arg;

   assert_wait((event_t)(uintptr_t)&mp_bc_count, THREAD_UNINT);

   /*
    * signal other processors, which will call mp_broadcast_action()
    */
   simple_lock(&x86_topo_lock);
   mp_bc_ncpus = i386_active_cpus();   /* total including this cpu */
   mp_bc_count = mp_bc_ncpus;
   i386_signal_cpus(MP_BROADCAST, ASYNC);

   /* call executor function on this cpu */
   mp_broadcast_action();
   simple_unlock(&x86_topo_lock);

   /* block for all cpus to have run action_func */
   if (mp_bc_ncpus > 1)
       thread_block(THREAD_CONTINUE_NULL);
   else
       clear_wait(current_thread(), THREAD_AWAKENED);
       
   /* release lock */
   lck_mtx_unlock(&mp_bc_lock);
}

void
i386_activate_cpu(void)
{
	cpu_data_t	*cdp = current_cpu_datap();

	assert(!ml_get_interrupts_enabled());

	if (!smp_initialized) {
		cdp->cpu_running = TRUE;
		return;
	}

	simple_lock(&x86_topo_lock);
	cdp->cpu_running = TRUE;
	simple_unlock(&x86_topo_lock);
}

extern void etimer_timer_expire(void	*arg);

void
i386_deactivate_cpu(void)
{
	cpu_data_t	*cdp = current_cpu_datap();

	assert(!ml_get_interrupts_enabled());

	simple_lock(&x86_topo_lock);
	cdp->cpu_running = FALSE;
	simple_unlock(&x86_topo_lock);

	timer_queue_shutdown(&cdp->rtclock_timer.queue);
	cdp->rtclock_timer.deadline = EndOfAllTime;
	mp_cpus_call(cpu_to_cpumask(master_cpu), ASYNC, etimer_timer_expire, NULL);

	/*
	 * In case a rendezvous/braodcast/call was initiated to this cpu
	 * before we cleared cpu_running, we must perform any actions due.
	 */
	if (i_bit(MP_RENDEZVOUS, &cdp->cpu_signals))
		mp_rendezvous_action();
	if (i_bit(MP_BROADCAST, &cdp->cpu_signals))
		mp_broadcast_action();
	if (i_bit(MP_CALL, &cdp->cpu_signals))
		mp_cpus_call_action();
	cdp->cpu_signals = 0;			/* all clear */
}

int	pmsafe_debug	= 1;

#if	MACH_KDP
volatile boolean_t	mp_kdp_trap = FALSE;
volatile unsigned long	mp_kdp_ncpus;
boolean_t		mp_kdp_state;


void
mp_kdp_enter(void)
{
	unsigned int	cpu;
	unsigned int	ncpus;
	unsigned int	my_cpu;
	uint64_t	tsc_timeout;

	DBG("mp_kdp_enter()\n");

	/*
	 * Here to enter the debugger.
	 * In case of races, only one cpu is allowed to enter kdp after
	 * stopping others.
	 */
	mp_kdp_state = ml_set_interrupts_enabled(FALSE);
	simple_lock(&mp_kdp_lock);
	debugger_entry_time = mach_absolute_time();
	if (pmsafe_debug)
	    pmSafeMode(&current_cpu_datap()->lcpu, PM_SAFE_FL_SAFE);

	while (mp_kdp_trap) {
		simple_unlock(&mp_kdp_lock);
		DBG("mp_kdp_enter() race lost\n");
#if MACH_KDP
		mp_kdp_wait(TRUE, FALSE);
#endif
		simple_lock(&mp_kdp_lock);
	}
	my_cpu = cpu_number();
	debugger_cpu = my_cpu;
	mp_kdp_ncpus = 1;	/* self */
	mp_kdp_trap = TRUE;
	simple_unlock(&mp_kdp_lock);

	/*
	 * Deliver a nudge to other cpus, counting how many
	 */
	DBG("mp_kdp_enter() signaling other processors\n");
	if (force_immediate_debugger_NMI == FALSE) {
		for (ncpus = 1, cpu = 0; cpu < real_ncpus; cpu++) {
			if (cpu == my_cpu || !cpu_datap(cpu)->cpu_running)
				continue;
			ncpus++;
			i386_signal_cpu(cpu, MP_KDP, ASYNC);
		}
		/*
		 * Wait other processors to synchronize
		 */
		DBG("mp_kdp_enter() waiting for (%d) processors to suspend\n", ncpus);

		/*
		 * This timeout is rather arbitrary; we don't want to NMI
		 * processors that are executing at potentially
		 * "unsafe-to-interrupt" points such as the trampolines,
		 * but neither do we want to lose state by waiting too long.
		 */
		tsc_timeout = rdtsc64() + (ncpus * 1000 * 1000);

		while (mp_kdp_ncpus != ncpus && rdtsc64() < tsc_timeout) {
			/*
			 * A TLB shootdown request may be pending--this would
			 * result in the requesting processor waiting in
			 * PMAP_UPDATE_TLBS() until this processor deals with it.
			 * Process it, so it can now enter mp_kdp_wait()
			 */
			handle_pending_TLB_flushes();
			cpu_pause();
		}
		/* If we've timed out, and some processor(s) are still unresponsive,
		 * interrupt them with an NMI via the local APIC.
		 */
		if (mp_kdp_ncpus != ncpus) {
			for (cpu = 0; cpu < real_ncpus; cpu++) {
				if (cpu == my_cpu || !cpu_datap(cpu)->cpu_running)
					continue;
				if (cpu_signal_pending(cpu, MP_KDP))
					cpu_NMI_interrupt(cpu);
			}
		}
	}
	else
		for (cpu = 0; cpu < real_ncpus; cpu++) {
			if (cpu == my_cpu || !cpu_datap(cpu)->cpu_running)
				continue;
			cpu_NMI_interrupt(cpu);
		}

	DBG("mp_kdp_enter() %u processors done %s\n",
	    mp_kdp_ncpus, (mp_kdp_ncpus == ncpus) ? "OK" : "timed out");
	
	postcode(MP_KDP_ENTER);
}

static boolean_t
cpu_signal_pending(int cpu, mp_event_t event)
{
	volatile int	*signals = &cpu_datap(cpu)->cpu_signals;
	boolean_t retval = FALSE;

	if (i_bit(event, signals))
		retval = TRUE;
	return retval;
}

long kdp_x86_xcpu_invoke(const uint16_t lcpu, kdp_x86_xcpu_func_t func,
			 void *arg0, void *arg1)
{
	if (lcpu > (real_ncpus - 1))
		return -1;

        if (func == NULL)
		return -1;

	kdp_xcpu_call_func.func = func;
        kdp_xcpu_call_func.ret  = -1;
	kdp_xcpu_call_func.arg0 = arg0;
	kdp_xcpu_call_func.arg1 = arg1;
	kdp_xcpu_call_func.cpu  = lcpu;
	DBG("Invoking function %p on CPU %d\n", func, (int32_t)lcpu);
	while (kdp_xcpu_call_func.cpu != KDP_XCPU_NONE)
		cpu_pause();
        return kdp_xcpu_call_func.ret;
}

static void
kdp_x86_xcpu_poll(void)
{
	if ((uint16_t)cpu_number() == kdp_xcpu_call_func.cpu) {
            kdp_xcpu_call_func.ret = 
		    kdp_xcpu_call_func.func(kdp_xcpu_call_func.arg0,
					    kdp_xcpu_call_func.arg1,
					    cpu_number());
		kdp_xcpu_call_func.cpu = KDP_XCPU_NONE;
	}
}

static void
mp_kdp_wait(boolean_t flush, boolean_t isNMI)
{
	DBG("mp_kdp_wait()\n");
	/* If an I/O port has been specified as a debugging aid, issue a read */
	panic_io_port_read();

#if CONFIG_MCA
	/* If we've trapped due to a machine-check, save MCA registers */
	mca_check_save();
#endif

	if (pmsafe_debug)
	    pmSafeMode(&current_cpu_datap()->lcpu, PM_SAFE_FL_SAFE);

	atomic_incl((volatile long *)&mp_kdp_ncpus, 1);
	while (mp_kdp_trap || (isNMI == TRUE)) {
	        /*
		 * A TLB shootdown request may be pending--this would result
		 * in the requesting processor waiting in PMAP_UPDATE_TLBS()
		 * until this processor handles it.
		 * Process it, so it can now enter mp_kdp_wait()
		 */
		if (flush)
			handle_pending_TLB_flushes();

		kdp_x86_xcpu_poll();
		cpu_pause();
	}

	if (pmsafe_debug)
	    pmSafeMode(&current_cpu_datap()->lcpu, PM_SAFE_FL_NORMAL);

	atomic_decl((volatile long *)&mp_kdp_ncpus, 1);
	DBG("mp_kdp_wait() done\n");
}

void
mp_kdp_exit(void)
{
	DBG("mp_kdp_exit()\n");
	debugger_cpu = -1;
	atomic_decl((volatile long *)&mp_kdp_ncpus, 1);

	debugger_exit_time = mach_absolute_time();

	mp_kdp_trap = FALSE;
	__asm__ volatile("mfence");

	/* Wait other processors to stop spinning. XXX needs timeout */
	DBG("mp_kdp_exit() waiting for processors to resume\n");
	while (mp_kdp_ncpus > 0) {
	        /*
		 * a TLB shootdown request may be pending... this would result in the requesting
		 * processor waiting in PMAP_UPDATE_TLBS() until this processor deals with it.
		 * Process it, so it can now enter mp_kdp_wait()
		 */
	        handle_pending_TLB_flushes();

		cpu_pause();
	}

	if (pmsafe_debug)
	    pmSafeMode(&current_cpu_datap()->lcpu, PM_SAFE_FL_NORMAL);

	DBG("mp_kdp_exit() done\n");
	(void) ml_set_interrupts_enabled(mp_kdp_state);
	postcode(0);
}
#endif	/* MACH_KDP */

boolean_t
mp_recent_debugger_activity() {
	return (((mach_absolute_time() - debugger_entry_time) < LastDebuggerEntryAllowance) ||
	    ((mach_absolute_time() - debugger_exit_time) < LastDebuggerEntryAllowance));
}

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
	int	cpu = processor->cpu_id;

	if (cpu != cpu_number()) {
		i386_signal_cpu(cpu, MP_AST, ASYNC);
	}
}

#if MACH_KDB
/*
 * invoke kdb on slave processors 
 */

void
remote_kdb(void)
{
	unsigned int	my_cpu = cpu_number();
	unsigned int	cpu;
	int kdb_ncpus;
	uint64_t tsc_timeout = 0;
	
	mp_kdb_trap = TRUE;
	mp_kdb_ncpus = 1;
	for (kdb_ncpus = 1, cpu = 0; cpu < real_ncpus; cpu++) {
		if (cpu == my_cpu || !cpu_datap(cpu)->cpu_running)
			continue;
		kdb_ncpus++;
		i386_signal_cpu(cpu, MP_KDB, ASYNC);
	}
	DBG("remote_kdb() waiting for (%d) processors to suspend\n",kdb_ncpus);

	tsc_timeout = rdtsc64() + (kdb_ncpus * 100 * 1000 * 1000);

	while (mp_kdb_ncpus != kdb_ncpus && rdtsc64() < tsc_timeout) {
	        /*
		 * a TLB shootdown request may be pending... this would result in the requesting
		 * processor waiting in PMAP_UPDATE_TLBS() until this processor deals with it.
		 * Process it, so it can now enter mp_kdp_wait()
		 */
	        handle_pending_TLB_flushes();

		cpu_pause();
	}
	DBG("mp_kdp_enter() %d processors done %s\n",
		mp_kdb_ncpus, (mp_kdb_ncpus == kdb_ncpus) ? "OK" : "timed out");
}

static void
mp_kdb_wait(void)
{
	DBG("mp_kdb_wait()\n");

	/* If an I/O port has been specified as a debugging aid, issue a read */
	panic_io_port_read();

	atomic_incl(&mp_kdb_ncpus, 1);
	while (mp_kdb_trap) {
	        /*
		 * a TLB shootdown request may be pending... this would result in the requesting
		 * processor waiting in PMAP_UPDATE_TLBS() until this processor deals with it.
		 * Process it, so it can now enter mp_kdp_wait()
		 */
	        handle_pending_TLB_flushes();

		cpu_pause();
	}
	atomic_decl((volatile long *)&mp_kdb_ncpus, 1);
	DBG("mp_kdb_wait() done\n");
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

void
mp_kdb_exit(void)
{
	DBG("mp_kdb_exit()\n");
	atomic_decl((volatile long *)&mp_kdb_ncpus, 1);
	mp_kdb_trap = FALSE;
	__asm__ volatile("mfence");

	while (mp_kdb_ncpus > 0) {
	        /*
		 * a TLB shootdown request may be pending... this would result in the requesting
		 * processor waiting in PMAP_UPDATE_TLBS() until this processor deals with it.
		 * Process it, so it can now enter mp_kdp_wait()
		 */
	        handle_pending_TLB_flushes();

		cpu_pause();
	}

	DBG("mp_kdb_exit() done\n");
}

#endif /* MACH_KDB */

void
slave_machine_init(void *param)
{
	/*
 	 * Here in process context, but with interrupts disabled.
	 */
	DBG("slave_machine_init() CPU%d\n", get_cpu_number());

	if (param == FULL_SLAVE_INIT) {
		/*
		 * Cold start
		 */
		clock_init();

		cpu_machine_init();	/* Interrupts enabled hereafter */
	}
}

#undef cpu_number
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
#endif	/* MACH_KDB */

