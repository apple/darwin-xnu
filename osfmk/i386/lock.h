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
 * Copyright (C) 1998 Apple Computer
 * All Rights Reserved
 */
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

/*
 */

/*
 * Machine-dependent simple locks for the i386.
 */

#ifndef	_I386_LOCK_H_
#define	_I386_LOCK_H_

#include <kern/macro_help.h>
#include <kern/assert.h>
#include <i386/hw_lock_types.h>

#ifdef MACH_KERNEL_PRIVATE

#include <mach_rt.h>
#include <mach_ldebug.h>
#include <cpus.h>


#if defined(__GNUC__)

/*
 *	General bit-lock routines.
 */

#define	bit_lock(bit,l)							\
	__asm__ volatile("	jmp	1f	\n			\
		 	0:	btl	%0, %1	\n			\
				jb	0b	\n			\
			1:	lock		\n			\
				btsl	%0,%1	\n			\
				jb	0b"			:	\
								:	\
			"r" (bit), "m" (*(volatile int *)(l))	:	\
			"memory");

#define	bit_unlock(bit,l)						\
	__asm__ volatile("	lock		\n			\
				btrl	%0,%1"			:	\
								:	\
			"r" (bit), "m" (*(volatile int *)(l)));

/*
 *      Set or clear individual bits in a long word.
 *      The locked access is needed only to lock access
 *      to the word, not to individual bits.
 */

#define	i_bit_set(bit,l)						\
	__asm__ volatile("	lock		\n			\
				btsl	%0,%1"			:	\
								:	\
			"r" (bit), "m" (*(volatile int *)(l)));

#define	i_bit_clear(bit,l)						\
	__asm__ volatile("	lock		\n			\
				btrl	%0,%1"			:	\
								:	\
			"r" (bit), "m" (*(volatile int *)(l)));

extern __inline__ unsigned long i_bit_isset(unsigned int testbit, volatile unsigned long *word)
{
	int	bit;

	__asm__ volatile("btl %2,%1\n\tsbbl %0,%0" : "=r" (bit)
		: "m" (word), "ir" (testbit));
	return bit;
}

extern __inline__ char	xchgb(volatile char * cp, char new);

extern __inline__ void	atomic_incl(long * p, long delta);
extern __inline__ void	atomic_incs(short * p, short delta);
extern __inline__ void	atomic_incb(char * p, char delta);

extern __inline__ void	atomic_decl(long * p, long delta);
extern __inline__ void	atomic_decs(short * p, short delta);
extern __inline__ void	atomic_decb(char * p, char delta);

extern __inline__ long	atomic_getl(long * p);
extern __inline__ short	atomic_gets(short * p);
extern __inline__ char	atomic_getb(char * p);

extern __inline__ void	atomic_setl(long * p, long value);
extern __inline__ void	atomic_sets(short * p, short value);
extern __inline__ void	atomic_setb(char * p, char value);

extern __inline__ char	xchgb(volatile char * cp, char new)
{
	register char	old = new;

	__asm__ volatile ("	xchgb	%0,%2"			:
			"=q" (old)				:
			"0" (new), "m" (*(volatile char *)cp) : "memory");
	return (old);
}

extern __inline__ void	atomic_incl(long * p, long delta)
{
#if NEED_ATOMIC
	__asm__ volatile ("	lock		\n		\
				addl    %0,%1"		:	\
							:	\
				"r" (delta), "m" (*(volatile long *)p));
#else /* NEED_ATOMIC */
	*p += delta;
#endif /* NEED_ATOMIC */
}

extern __inline__ void	atomic_incs(short * p, short delta)
{
#if NEED_ATOMIC
	__asm__ volatile ("	lock		\n		\
				addw    %0,%1"		:	\
							:	\
				"q" (delta), "m" (*(volatile short *)p));
#else /* NEED_ATOMIC */
	*p += delta;
#endif /* NEED_ATOMIC */
}

extern __inline__ void	atomic_incb(char * p, char delta)
{
#if NEED_ATOMIC
	__asm__ volatile ("	lock		\n		\
				addb    %0,%1"		:	\
							:	\
				"q" (delta), "m" (*(volatile char *)p));
#else /* NEED_ATOMIC */
	*p += delta;
#endif /* NEED_ATOMIC */
}

extern __inline__ void	atomic_decl(long * p, long delta)
{
#if NCPUS > 1
	__asm__ volatile ("	lock		\n		\
				subl	%0,%1"		:	\
							:	\
				"r" (delta), "m" (*(volatile long *)p));
#else /* NCPUS > 1 */
	*p -= delta;
#endif /* NCPUS > 1 */
}

extern __inline__ void	atomic_decs(short * p, short delta)
{
#if NEED_ATOMIC
	__asm__ volatile ("	lock		\n		\
				subw    %0,%1"		:	\
							:	\
				"q" (delta), "m" (*(volatile short *)p));
#else /* NEED_ATOMIC */
	*p -= delta;
#endif /* NEED_ATOMIC */
}

extern __inline__ void	atomic_decb(char * p, char delta)
{
#if NEED_ATOMIC
	__asm__ volatile ("	lock		\n		\
				subb    %0,%1"		:	\
							:	\
				"q" (delta), "m" (*(volatile char *)p));
#else /* NEED_ATOMIC */
	*p -= delta;
#endif /* NEED_ATOMIC */
}

extern __inline__ long	atomic_getl(long * p)
{
	return (*p);
}

extern __inline__ short	atomic_gets(short * p)
{
	return (*p);
}

extern __inline__ char	atomic_getb(char * p)
{
	return (*p);
}

extern __inline__ void	atomic_setl(long * p, long value)
{
	*p = value;
}

extern __inline__ void	atomic_sets(short * p, short value)
{
	*p = value;
}

extern __inline__ void	atomic_setb(char * p, char value)
{
	*p = value;
}


#else	/* !defined(__GNUC__) */

extern void	i_bit_set(
	int index,
	void *addr);

extern void	i_bit_clear(
	int index,
	void *addr);

extern void bit_lock(
	int index,
	void *addr);

extern void bit_unlock(
	int index,
	void *addr);

/*
 * All other routines defined in __GNUC__ case lack
 * definitions otherwise. - XXX
 */

#endif	/* !defined(__GNUC__) */


#if	!(USLOCK_DEBUG || USLOCK_STATS)
/*
 *	Take responsibility for production-quality usimple_locks.
 *	Let the portable lock package build simple_locks in terms
 *	of usimple_locks, which is done efficiently with macros.
 *	Currently, these aren't inlined although they probably
 *	should be.  The portable lock package is used for the
 *	usimple_lock prototypes and data declarations.
 *
 *	For non-production configurations, punt entirely to the
 *	portable lock package.
 *
 *	N.B.  I've left in the hooks for ETAP, so we can
 *	compare the performance of stats-gathering on top
 *	of "production" locks v. stats-gathering on top
 *	of portable, C-based locks.
 */
#define	USIMPLE_LOCK_CALLS
#endif	/* !(USLOCK_DEBUG || USLOCK_STATS) */

#endif /* MACH_KERNEL_PRIVATE */

extern void		kernel_preempt_check (void);

#endif	/* _I386_LOCK_H_ */
