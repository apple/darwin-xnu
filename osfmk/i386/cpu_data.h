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

#if 0
#ifndef	__OPTIMIZE__
#define extern static
#endif
#endif

/*
 * Everyone within the osfmk part of the kernel can use the fast
 * inline versions of these routines.  Everyone outside, must call
 * the real thing,
 */
extern thread_t	__inline__ current_thread_fast(void);
extern thread_t __inline__ current_thread_fast(void)
{
	register thread_t	ct;
	register int		idx = (int)&((cpu_data_t *)0)->active_thread;

	__asm__ volatile ("	movl %%gs:(%1),%0" : "=r" (ct) : "r" (idx));

	return (ct);
}

#define current_thread()	current_thread_fast()

extern int 	__inline__	get_preemption_level(void);
extern void 	__inline__	disable_preemption(void);
extern void 	__inline__      enable_preemption(void);
extern void 	__inline__      enable_preemption_no_check(void);
extern void 	__inline__	mp_disable_preemption(void);
extern void 	__inline__      mp_enable_preemption(void);
extern void 	__inline__      mp_enable_preemption_no_check(void);
extern int 	__inline__      get_simple_lock_count(void);
extern int 	__inline__      get_interrupt_level(void);

extern int __inline__		get_preemption_level(void)
{
	register int	idx = (int)&((cpu_data_t *)0)->preemption_level;
	register int	pl;

	__asm__ volatile ("	movl %%gs:(%1),%0" : "=r" (pl) : "r" (idx));

	return (pl);
}

extern void __inline__		disable_preemption(void)
{
#if	MACH_ASSERT
	extern void _disable_preemption(void);

	_disable_preemption();
#else	/* MACH_ASSERT */
	register int	idx = (int)&((cpu_data_t *)0)->preemption_level;

	__asm__ volatile ("	incl %%gs:(%0)" : : "r" (idx));
#endif	/* MACH_ASSERT */
}

extern void __inline__		enable_preemption(void)
{
#if	MACH_ASSERT
	extern void _enable_preemption(void);

	assert(get_preemption_level() > 0);
	_enable_preemption();
#else	/* MACH_ASSERT */
	extern void		kernel_preempt_check (void);
	register int	idx = (int)&((cpu_data_t *)0)->preemption_level;
	register void (*kpc)(void)=	kernel_preempt_check;

	__asm__ volatile ("decl %%gs:(%0); jne 1f; \
			call %1; 1:"
			: /* no outputs */
			: "r" (idx), "r" (kpc)
			: "%eax", "%ecx", "%edx", "cc", "memory");
#endif	/* MACH_ASSERT */
}

extern void __inline__		enable_preemption_no_check(void)
{
#if	MACH_ASSERT
	extern void _enable_preemption_no_check(void);

	assert(get_preemption_level() > 0);
	_enable_preemption_no_check();
#else	/* MACH_ASSERT */
	register int	idx = (int)&((cpu_data_t *)0)->preemption_level;

	__asm__ volatile ("decl %%gs:(%0)"
			: /* no outputs */
			: "r" (idx)
			: "cc", "memory");
#endif	/* MACH_ASSERT */
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

extern int __inline__		get_simple_lock_count(void)
{
	register int	idx = (int)&((cpu_data_t *)0)->simple_lock_count;
	register int	pl;

	__asm__ volatile ("	movl %%gs:(%1),%0" : "=r" (pl) : "r" (idx));

	return (pl);
}

extern int __inline__		get_interrupt_level(void)
{
	register int	idx = (int)&((cpu_data_t *)0)->interrupt_level;
	register int	pl;

	__asm__ volatile ("	movl %%gs:(%1),%0" : "=r" (pl) : "r" (idx));

	return (pl);
}

#if 0
#ifndef	__OPTIMIZE__
#undef 	extern 
#endif
#endif

#else	/* !defined(__GNUC__) */

#endif	/* defined(__GNUC__) */

#endif	/* I386_CPU_DATA */
