/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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
 * 
 */

#ifndef	I386_CPU_DATA
#define I386_CPU_DATA

#include <mach_assert.h>

#include <kern/assert.h>
#include <kern/kern_types.h>
#include <kern/queue.h>
#include <kern/processor.h>
#include <kern/pms.h>
#include <pexpert/pexpert.h>
#include <mach/i386/thread_status.h>
#include <mach/i386/vm_param.h>
#include <i386/locks.h>
#include <i386/rtclock_protos.h>
#include <i386/pmCPU.h>
#include <i386/cpu_topology.h>

#if CONFIG_VMX
#include <i386/vmx/vmx_cpu.h>
#endif

#include <machine/pal_routines.h>

/*
 * Data structures referenced (anonymously) from per-cpu data:
 */
struct cpu_cons_buffer;
struct cpu_desc_table;
struct mca_state;
struct prngContext;

/*
 * Data structures embedded in per-cpu data:
 */
typedef struct rtclock_timer {
	mpqueue_head_t		queue;
	uint64_t		deadline;
	uint64_t		when_set;
	boolean_t		has_expired;
} rtclock_timer_t;


typedef struct {
	struct x86_64_tss	*cdi_ktss;
	struct __attribute__((packed)) {
		uint16_t size;
		void *ptr;
	} cdi_gdt, cdi_idt;
	struct fake_descriptor	*cdi_ldt;
	vm_offset_t		cdi_sstk;
} cpu_desc_index_t;

typedef enum {
	TASK_MAP_32BIT,			/* 32-bit user, compatibility mode */ 
	TASK_MAP_64BIT,			/* 64-bit user thread, shared space */ 
} task_map_t;


/*
 * This structure is used on entry into the (uber-)kernel on syscall from
 * a 64-bit user. It contains the address of the machine state save area
 * for the current thread and a temporary place to save the user's rsp
 * before loading this address into rsp.
 */
typedef struct {
	addr64_t	cu_isf;		/* thread->pcb->iss.isf */
	uint64_t	cu_tmp;		/* temporary scratch */	
	addr64_t	cu_user_gs_base;
} cpu_uber_t;

typedef	uint16_t	pcid_t;
typedef	uint8_t		pcid_ref_t;

#define CPU_RTIME_BINS (12)
#define CPU_ITIME_BINS (CPU_RTIME_BINS)

#define MAXPLFRAMES (32)
typedef struct {
	boolean_t pltype;
	int plevel;
	uint64_t plbt[MAXPLFRAMES];
} plrecord_t;

/*
 * Per-cpu data.
 *
 * Each processor has a per-cpu data area which is dereferenced through the
 * current_cpu_datap() macro. For speed, the %gs segment is based here, and
 * using this, inlines provides single-instruction access to frequently used
 * members - such as get_cpu_number()/cpu_number(), and get_active_thread()/
 * current_thread(). 
 * 
 * Cpu data owned by another processor can be accessed using the
 * cpu_datap(cpu_number) macro which uses the cpu_data_ptr[] array of per-cpu
 * pointers.
 */
typedef struct cpu_data
{
	struct pal_cpu_data	cpu_pal_data;		/* PAL-specific data */
#define				cpu_pd cpu_pal_data	/* convenience alias */
	struct cpu_data		*cpu_this;		/* pointer to myself */
	thread_t		cpu_active_thread;
	thread_t		cpu_nthread;
	volatile int		cpu_preemption_level;
	int			cpu_number;		/* Logical CPU */
	void			*cpu_int_state;		/* interrupt state */
	vm_offset_t		cpu_active_stack;	/* kernel stack base */
	vm_offset_t		cpu_kernel_stack;	/* kernel stack top */
	vm_offset_t		cpu_int_stack_top;
	int			cpu_interrupt_level;
	int			cpu_phys_number;	/* Physical CPU */
	cpu_id_t		cpu_id;			/* Platform Expert */
	volatile int		cpu_signals;		/* IPI events */
	volatile int		cpu_prior_signals;	/* Last set of events,
							 * debugging
							 */
	ast_t			cpu_pending_ast;
	volatile int		cpu_running;
	boolean_t		cpu_fixed_pmcs_enabled;
	rtclock_timer_t		rtclock_timer;
	volatile addr64_t	cpu_active_cr3 __attribute((aligned(64)));
	union {
		volatile uint32_t cpu_tlb_invalid;
		struct {
			volatile uint16_t cpu_tlb_invalid_local;
			volatile uint16_t cpu_tlb_invalid_global;
		};
	};
	volatile task_map_t	cpu_task_map;
	volatile addr64_t	cpu_task_cr3;
	addr64_t		cpu_kernel_cr3;
	boolean_t		cpu_pagezero_mapped;
	cpu_uber_t		cpu_uber;
	void			*cpu_chud;
	void			*cpu_console_buf;
	struct x86_lcpu		lcpu;
	struct processor	*cpu_processor;
#if NCOPY_WINDOWS > 0
	struct cpu_pmap		*cpu_pmap;
#endif
	struct cpu_desc_table	*cpu_desc_tablep;
	struct fake_descriptor	*cpu_ldtp;
	cpu_desc_index_t	cpu_desc_index;
	int			cpu_ldt;
#if NCOPY_WINDOWS > 0
	vm_offset_t		cpu_copywindow_base;
	uint64_t		*cpu_copywindow_pdp;

	vm_offset_t		cpu_physwindow_base;
	uint64_t		*cpu_physwindow_ptep;
#endif

#define HWINTCNT_SIZE 256
	uint32_t		cpu_hwIntCnt[HWINTCNT_SIZE];	/* Interrupt counts */
 	uint64_t		cpu_hwIntpexits[HWINTCNT_SIZE];
	uint64_t		cpu_hwIntcexits[HWINTCNT_SIZE];
	uint64_t		cpu_dr7; /* debug control register */
	uint64_t		cpu_int_event_time;	/* intr entry/exit time */
	pal_rtc_nanotime_t	*cpu_nanotime;		/* Nanotime info */
#if KPC
	/* double-buffered performance counter data */
	uint64_t                *cpu_kpc_buf[2];
	/* PMC shadow and reload value buffers */
	uint64_t                *cpu_kpc_shadow;
	uint64_t                *cpu_kpc_reload;
#endif
	uint32_t		cpu_pmap_pcid_enabled;
	pcid_t			cpu_active_pcid;
	pcid_t			cpu_last_pcid;
	pcid_t			cpu_kernel_pcid;
	volatile pcid_ref_t	*cpu_pmap_pcid_coherentp;
	volatile pcid_ref_t	*cpu_pmap_pcid_coherentp_kernel;
#define	PMAP_PCID_MAX_PCID      (0x1000)
	pcid_t			cpu_pcid_free_hint;
	pcid_ref_t		cpu_pcid_refcounts[PMAP_PCID_MAX_PCID];
	pmap_t			cpu_pcid_last_pmap_dispatched[PMAP_PCID_MAX_PCID];
#ifdef	PCID_STATS
	uint64_t		cpu_pmap_pcid_flushes;
	uint64_t		cpu_pmap_pcid_preserves;
#endif
	uint64_t		cpu_aperf;
	uint64_t		cpu_mperf;
	uint64_t		cpu_c3res;
	uint64_t		cpu_c6res;
	uint64_t		cpu_c7res;
	uint64_t		cpu_itime_total;
	uint64_t		cpu_rtime_total;
	uint64_t		cpu_ixtime;
	uint64_t                cpu_idle_exits;
 	uint64_t		cpu_rtimes[CPU_RTIME_BINS];
 	uint64_t		cpu_itimes[CPU_ITIME_BINS];
 	uint64_t		cpu_cur_insns;
 	uint64_t		cpu_cur_ucc;
 	uint64_t		cpu_cur_urc;
	uint64_t		cpu_gpmcs[4];
	uint64_t                cpu_max_observed_int_latency;
	int                     cpu_max_observed_int_latency_vector;
	volatile boolean_t	cpu_NMI_acknowledged;
	uint64_t		debugger_entry_time;
	uint64_t		debugger_ipi_time;
	/* A separate nested interrupt stack flag, to account
	 * for non-nested interrupts arriving while on the interrupt stack
	 * Currently only occurs when AICPM enables interrupts on the
	 * interrupt stack during processor offlining.
	 */
	uint32_t		cpu_nested_istack;
	uint32_t		cpu_nested_istack_events;
	x86_saved_state64_t	*cpu_fatal_trap_state;
	x86_saved_state64_t	*cpu_post_fatal_trap_state;
#if CONFIG_VMX
	vmx_cpu_t		cpu_vmx;		/* wonderful world of virtualization */
#endif
#if CONFIG_MCA
	struct mca_state	*cpu_mca_state;		/* State at MC fault */
#endif
	struct prngContext	*cpu_prng;		/* PRNG's context */
 	int			cpu_type;
 	int			cpu_subtype;
 	int			cpu_threadtype;
 	boolean_t		cpu_iflag;
 	boolean_t		cpu_boot_complete;
	int			cpu_hibernate;
#define MAX_PREEMPTION_RECORDS (128)
#if	DEVELOPMENT || DEBUG
	int			cpu_plri;
	plrecord_t		plrecords[MAX_PREEMPTION_RECORDS];
#endif
} cpu_data_t;

extern cpu_data_t	*cpu_data_ptr[];  

/* Macro to generate inline bodies to retrieve per-cpu data fields. */
#if defined(__clang__)
#define GS_RELATIVE volatile __attribute__((address_space(256)))
#ifndef offsetof
#define offsetof(TYPE,MEMBER) __builtin_offsetof(TYPE,MEMBER)
#endif

#define CPU_DATA_GET(member,type)										\
	cpu_data_t GS_RELATIVE *cpu_data =							\
		(cpu_data_t GS_RELATIVE *)0UL;									\
	type ret;															\
	ret = cpu_data->member;												\
	return ret;

#define CPU_DATA_GET_INDEX(member,index,type)							\
	cpu_data_t GS_RELATIVE *cpu_data =							\
		(cpu_data_t GS_RELATIVE *)0UL;									\
	type ret;															\
	ret = cpu_data->member[index];										\
	return ret;

#define CPU_DATA_SET(member,value)										\
	cpu_data_t GS_RELATIVE *cpu_data =							\
		(cpu_data_t GS_RELATIVE *)0UL;									\
	cpu_data->member = value;

#define CPU_DATA_XCHG(member,value,type)								\
	cpu_data_t GS_RELATIVE *cpu_data =							\
		(cpu_data_t GS_RELATIVE *)0UL;									\
	type ret;															\
	ret = cpu_data->member;												\
	cpu_data->member = value;											\
	return ret;

#else /* !defined(__clang__) */

#ifndef offsetof
#define offsetof(TYPE,MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif /* offsetof */
#define CPU_DATA_GET(member,type)					\
	type ret;							\
	__asm__ volatile ("mov %%gs:%P1,%0"				\
		: "=r" (ret)						\
		: "i" (offsetof(cpu_data_t,member)));			\
	return ret;

#define CPU_DATA_GET_INDEX(member,index,type)	\
	type ret;							\
	__asm__ volatile ("mov %%gs:(%1),%0"				\
		: "=r" (ret)						\
		: "r" (offsetof(cpu_data_t,member[index])));			\
	return ret;

#define CPU_DATA_SET(member,value)					\
	__asm__ volatile ("mov %0,%%gs:%P1"				\
		:							\
		: "r" (value), "i" (offsetof(cpu_data_t,member)));

#define CPU_DATA_XCHG(member,value,type)				\
	type ret;							\
	__asm__ volatile ("xchg %0,%%gs:%P1"				\
		: "=r" (ret)						\
		: "i" (offsetof(cpu_data_t,member)), "0" (value));	\
	return ret;

#endif /* !defined(__clang__) */

/*
 * Everyone within the osfmk part of the kernel can use the fast
 * inline versions of these routines.  Everyone outside, must call
 * the real thing,
 */
static inline thread_t
get_active_thread(void)
{
	CPU_DATA_GET(cpu_active_thread,thread_t)
}
#define current_thread_fast()		get_active_thread()
#define current_thread()		current_thread_fast()

#define cpu_mode_is64bit()		TRUE

static inline int
get_preemption_level(void)
{
	CPU_DATA_GET(cpu_preemption_level,int)
}
static inline int
get_interrupt_level(void)
{
	CPU_DATA_GET(cpu_interrupt_level,int)
}
static inline int
get_cpu_number(void)
{
	CPU_DATA_GET(cpu_number,int)
}
static inline int
get_cpu_phys_number(void)
{
	CPU_DATA_GET(cpu_phys_number,int)
}

static inline cpu_data_t *
current_cpu_datap(void) {
	CPU_DATA_GET(cpu_this, cpu_data_t *);
}

/*
 * Facility to diagnose preemption-level imbalances, which are otherwise
 * challenging to debug. On each operation that enables or disables preemption,
 * we record a backtrace into a per-CPU ring buffer, along with the current
 * preemption level and operation type. Thus, if an imbalance is observed,
 * one can examine these per-CPU records to determine which codepath failed
 * to re-enable preemption, enabled premption without a corresponding
 * disablement etc. The backtracer determines which stack is currently active,
 * and uses that to perform bounds checks on unterminated stacks.
 * To enable, sysctl -w machdep.pltrace=1 on DEVELOPMENT or DEBUG kernels (DRK '15)
 * The bounds check currently doesn't account for non-default thread stack sizes.
 */
#if DEVELOPMENT || DEBUG
static inline void pltrace_bt(uint64_t *rets, int maxframes, uint64_t stacklo, uint64_t stackhi) {
	uint64_t *cfp = (uint64_t *) __builtin_frame_address(0);
	int plbtf;

	assert(stacklo !=0  && stackhi !=0);

	for (plbtf = 0; plbtf < maxframes; plbtf++) {
		if (((uint64_t)cfp == 0) || (((uint64_t)cfp < stacklo) || ((uint64_t)cfp > stackhi))) {
			rets[plbtf] = 0;
			continue;
		}
		rets[plbtf] = *(cfp + 1);
		cfp = (uint64_t *) (*cfp);
	}
}


extern uint32_t		low_intstack[];		/* bottom */
extern uint32_t		low_eintstack[];	/* top */
extern char		mp_slave_stack[PAGE_SIZE];

static inline void pltrace_internal(boolean_t enable) {
	cpu_data_t *cdata = current_cpu_datap();
	int cpli = cdata->cpu_preemption_level;
	int cplrecord = cdata->cpu_plri;
	uint64_t kstackb, kstackt, *plbts;

	assert(cpli >= 0);

	cdata->plrecords[cplrecord].pltype = enable;
	cdata->plrecords[cplrecord].plevel = cpli;

	plbts = &cdata->plrecords[cplrecord].plbt[0];

	cplrecord++;

	if (cplrecord >= MAX_PREEMPTION_RECORDS) {
		cplrecord = 0;
	}

	cdata->cpu_plri = cplrecord;
	/* Obtain the 'current' program counter, initial backtrace
	 * element. This will also indicate if we were unable to
	 * trace further up the stack for some reason
	 */
	__asm__ volatile("leaq 1f(%%rip), %%rax; mov %%rax, %0\n1:"
	    : "=m" (plbts[0])
	    :
	    : "rax");


	thread_t cplthread = cdata->cpu_active_thread;
	if (cplthread) {
		uintptr_t csp;
		__asm__ __volatile__ ("movq %%rsp, %0": "=r" (csp):);
		/* Determine which stack we're on to populate stack bounds.
		 * We don't need to trace across stack boundaries for this
		 * routine.
		 */
		kstackb = cdata->cpu_active_stack;
		kstackt = kstackb + KERNEL_STACK_SIZE;
		if (csp < kstackb || csp > kstackt) {
			kstackt = cdata->cpu_kernel_stack;
			kstackb = kstackb - KERNEL_STACK_SIZE;
			if (csp < kstackb || csp > kstackt) {
				kstackt = cdata->cpu_int_stack_top;
				kstackb = kstackt - INTSTACK_SIZE;
				if (csp < kstackb || csp > kstackt) {
					kstackt = (uintptr_t)low_eintstack;
					kstackb = (uintptr_t)low_eintstack - INTSTACK_SIZE;
					if (csp < kstackb || csp > kstackt) {
						kstackb = (uintptr_t) mp_slave_stack;
						kstackt = (uintptr_t) mp_slave_stack + PAGE_SIZE;
					}
				}
			}
		}

		if (kstackb) {
			pltrace_bt(&plbts[1], MAXPLFRAMES - 1, kstackb, kstackt);
		}
	}
}

extern int plctrace_enabled;
#endif /* DEVELOPMENT || DEBUG */

static inline void pltrace(boolean_t plenable) {
#if DEVELOPMENT || DEBUG
	if (__improbable(plctrace_enabled != 0)) {
		pltrace_internal(plenable);
	}
#else
	(void)plenable;
#endif
}

static inline void
disable_preemption_internal(void) {
	assert(get_preemption_level() >= 0);

#if defined(__clang__)
	cpu_data_t GS_RELATIVE *cpu_data = (cpu_data_t GS_RELATIVE *)0UL;
	cpu_data->cpu_preemption_level++;
#else
	__asm__ volatile ("incl %%gs:%P0"
	    :
	    : "i" (offsetof(cpu_data_t, cpu_preemption_level)));
#endif
	pltrace(FALSE);
}

static inline void
enable_preemption_internal(void) {
	assert(get_preemption_level() > 0);
	pltrace(TRUE);
#if defined(__clang__)
	cpu_data_t GS_RELATIVE *cpu_data = (cpu_data_t GS_RELATIVE *)0UL;
	if (0 == --cpu_data->cpu_preemption_level)
		kernel_preempt_check();
#else
	__asm__ volatile ("decl %%gs:%P0		\n\t"
			  "jne 1f			\n\t"
			  "call _kernel_preempt_check	\n\t"
			  "1:"
			: /* no outputs */
			: "i" (offsetof(cpu_data_t, cpu_preemption_level))
			: "eax", "ecx", "edx", "cc", "memory");
#endif
}

static inline void
enable_preemption_no_check(void)
{
	assert(get_preemption_level() > 0);

	pltrace(TRUE);
#if defined(__clang__)
	cpu_data_t GS_RELATIVE *cpu_data = (cpu_data_t GS_RELATIVE *)0UL;
	cpu_data->cpu_preemption_level--;
#else
	__asm__ volatile ("decl %%gs:%P0"
			: /* no outputs */
			: "i" (offsetof(cpu_data_t, cpu_preemption_level))
			: "cc", "memory");
#endif
}

static inline void
_enable_preemption_no_check(void) {
	enable_preemption_no_check();
}

static inline void
mp_disable_preemption(void)
{
	disable_preemption_internal();
}

static inline void
_mp_disable_preemption(void)
{
	disable_preemption_internal();
}

static inline void
mp_enable_preemption(void)
{
	enable_preemption_internal();
}

static inline void
_mp_enable_preemption(void) {
	enable_preemption_internal();
}

static inline void
mp_enable_preemption_no_check(void) {
	enable_preemption_no_check();
}

static inline void
_mp_enable_preemption_no_check(void) {
	enable_preemption_no_check();
}

#ifdef XNU_KERNEL_PRIVATE
#define disable_preemption() disable_preemption_internal()
#define enable_preemption() enable_preemption_internal()
#define MACHINE_PREEMPTION_MACROS (1)
#endif


static inline cpu_data_t *
cpu_datap(int cpu) {
	return cpu_data_ptr[cpu];
}

extern cpu_data_t *cpu_data_alloc(boolean_t is_boot_cpu);
extern void cpu_data_realloc(void);

#endif	/* I386_CPU_DATA */
