/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 * 
 */

#ifndef	I386_CPU_DATA
#define I386_CPU_DATA

#include <cpus.h>
#include <mach_assert.h>

#if	defined(__GNUC__)

#include <kern/assert.h>
#include <kern/kern_types.h>
#include <pexpert/pexpert.h>

typedef struct
{
	thread_act_t	*active_thread;
	int		preemption_level;
	int		simple_lock_count;
	int		interrupt_level;
	int		cpu_number;		/* Logical CPU number */
	int		cpu_phys_number;	/* Physical CPU Number */
	cpu_id_t	cpu_id;			/* Platform Expert handle */
	int		cpu_status;		/* Boot Status */
	int		cpu_signals;		/* IPI events */
	int		mcount_off;		/* mcount recursion flag */
} cpu_data_t;

extern cpu_data_t	cpu_data[NCPUS];  

/* Macro to generate inline bodies to retrieve per-cpu data fields. */
#define offsetof(TYPE,MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define CPU_DATA_GET(field,type)					\
	type ret;							\
	__asm__ volatile ("movl %%gs:%P1,%0"				\
		: "=r" (ret)						\
		: "i" (offsetof(cpu_data_t,field)));			\
	return ret;

/*
 * Everyone within the osfmk part of the kernel can use the fast
 * inline versions of these routines.  Everyone outside, must call
 * the real thing,
 */
extern thread_act_t __inline__ get_active_thread(void)
{
	CPU_DATA_GET(active_thread,thread_act_t)
}
#define current_act_fast()	get_active_thread()
#define	current_act()		current_act_fast()
#define current_thread()	current_act_fast()->thread

extern int __inline__ get_preemption_level(void)
{
	CPU_DATA_GET(preemption_level,int)
}
extern int __inline__ get_simple_lock_count(void)
{
	CPU_DATA_GET(simple_lock_count,int)
}
extern int __inline__ get_interrupt_level(void)
{
	CPU_DATA_GET(interrupt_level,int)
}
extern int __inline__ get_cpu_number(void)
{
	CPU_DATA_GET(cpu_number,int)
}
extern int __inline__ get_cpu_phys_number(void)
{
	CPU_DATA_GET(cpu_phys_number,int)
}

extern void __inline__		disable_preemption(void)
{
	register int	idx = (int)&((cpu_data_t *)0)->preemption_level;

	__asm__ volatile ("	incl %%gs:(%0)" : : "r" (idx));
}

extern void __inline__		enable_preemption(void)
{
	extern void		kernel_preempt_check (void);
	register int	idx = (int)&((cpu_data_t *)0)->preemption_level;
	register void (*kpc)(void)=	kernel_preempt_check;

	assert(get_preemption_level() > 0);

	__asm__ volatile ("decl %%gs:(%0); jne 1f; \
			call %1; 1:"
			: /* no outputs */
			: "r" (idx), "r" (kpc)
			: "%eax", "%ecx", "%edx", "cc", "memory");
}

extern void __inline__		enable_preemption_no_check(void)
{
	register int	idx = (int)&((cpu_data_t *)0)->preemption_level;

	assert(get_preemption_level() > 0);

	__asm__ volatile ("decl %%gs:(%0)"
			: /* no outputs */
			: "r" (idx)
			: "cc", "memory");
}

extern void __inline__		mp_disable_preemption(void)
{
#if	NCPUS > 1
	disable_preemption();
#endif	/* NCPUS > 1 */
}

extern void __inline__		mp_enable_preemption(void)
{
#if	NCPUS > 1
	enable_preemption();
#endif	/* NCPUS > 1 */
}

extern void __inline__		mp_enable_preemption_no_check(void)
{
#if	NCPUS > 1
	enable_preemption_no_check();
#endif	/* NCPUS > 1 */
}

#if 0
#ifndef	__OPTIMIZE__
#undef 	extern 
#endif
#endif

#else	/* !defined(__GNUC__) */

#endif	/* defined(__GNUC__) */

#endif	/* I386_CPU_DATA */
