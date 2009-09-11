/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
#ifdef	KERNEL_PRIVATE

#ifndef	_I386_LOCK_H_
#define	_I386_LOCK_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE

#ifdef MACH_KERNEL_PRIVATE

#include <kern/macro_help.h>
#include <kern/assert.h>
#include <i386/hw_lock_types.h>
#include <i386/locks.h>

#include <mach_rt.h>
#include <mach_ldebug.h>

typedef lck_rw_t lock_t;

extern unsigned int LockTimeOutTSC;	/* Lock timeout in TSC ticks */
extern unsigned int LockTimeOut;	/* Lock timeout in absolute time */ 


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

static inline char	xchgb(volatile char * cp, char new);

static inline void	atomic_incl(volatile long * p, long delta);
static inline void	atomic_incs(volatile short * p, short delta);
static inline void	atomic_incb(volatile char * p, char delta);

static inline void	atomic_decl(volatile long * p, long delta);
static inline void	atomic_decs(volatile short * p, short delta);
static inline void	atomic_decb(volatile char * p, char delta);

static inline long	atomic_getl(const volatile long * p);
static inline short	atomic_gets(const volatile short * p);
static inline char	atomic_getb(const volatile char * p);

static inline void	atomic_setl(volatile long * p, long value);
static inline void	atomic_sets(volatile short * p, short value);
static inline void	atomic_setb(volatile char * p, char value);

static inline char	xchgb(volatile char * cp, char new)
{
	register char	old = new;

	__asm__ volatile ("	xchgb	%0,%2"			:
			"=q" (old)				:
			"0" (new), "m" (*(volatile char *)cp) : "memory");
	return (old);
}

static inline void	atomic_incl(volatile long * p, long delta)
{
	__asm__ volatile ("	lock		\n		\
				add    %0,%1"		:	\
							:	\
				"r" (delta), "m" (*(volatile long *)p));
}

static inline void	atomic_incs(volatile short * p, short delta)
{
	__asm__ volatile ("	lock		\n		\
				addw    %0,%1"		:	\
							:	\
				"q" (delta), "m" (*(volatile short *)p));
}

static inline void	atomic_incb(volatile char * p, char delta)
{
	__asm__ volatile ("	lock		\n		\
				addb    %0,%1"		:	\
							:	\
				"q" (delta), "m" (*(volatile char *)p));
}

static inline void	atomic_decl(volatile long * p, long delta)
{
	__asm__ volatile ("	lock		\n		\
				sub		%0,%1"		:	\
							:	\
				"r" (delta), "m" (*(volatile long *)p));
}

static inline int	atomic_decl_and_test(volatile long * p, long delta)
{
	uint8_t	ret;
	__asm__ volatile (
		"	lock		\n\t"
		"	sub		%1,%2	\n\t"
		"	sete	%0"
		: "=qm" (ret)
		: "r" (delta), "m" (*(volatile long *)p));
	return ret;
}

static inline void	atomic_decs(volatile short * p, short delta)
{
	__asm__ volatile ("	lock		\n		\
				subw    %0,%1"		:	\
							:	\
				"q" (delta), "m" (*(volatile short *)p));
}

static inline void	atomic_decb(volatile char * p, char delta)
{
	__asm__ volatile ("	lock		\n		\
				subb    %0,%1"		:	\
							:	\
				"q" (delta), "m" (*(volatile char *)p));
}

static inline long	atomic_getl(const volatile long * p)
{
	return (*p);
}

static inline short	atomic_gets(const volatile short * p)
{
	return (*p);
}

static inline char	atomic_getb(const volatile char * p)
{
	return (*p);
}

static inline void	atomic_setl(volatile long * p, long value)
{
	*p = value;
}

static inline void	atomic_sets(volatile short * p, short value)
{
	*p = value;
}

static inline void	atomic_setb(volatile char * p, char value)
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

extern void		kernel_preempt_check (void);

#endif /* MACH_KERNEL_PRIVATE */

#endif /* __APLE_API_PRIVATE */

#endif	/* _I386_LOCK_H_ */

#endif	/* KERNEL_PRIVATE */
