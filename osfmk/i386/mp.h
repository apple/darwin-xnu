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

#ifndef _I386AT_MP_H_
#define _I386AT_MP_H_

#if     !defined(NCPUS)
#include <cpus.h>
#endif  /* !defined(NCPUS) */

#if	NCPUS > 1

#ifndef	DEBUG
#include <debug.h>
#endif
#if	DEBUG
#define	MP_DEBUG 1
#endif

#include <i386/apic.h>
#include <i386/mp_events.h>

#define SPURIOUS_INTERRUPT	0xDD	
#define INTERPROCESS_INTERRUPT	0xDE
#define APIC_ERROR_INTERRUPT	0xDF

#define LAPIC_ID_MAX		(LAPIC_ID_MASK)

#ifndef	ASSEMBLER
extern void lapic_dump(void);
extern void lapic_interrupt(int interrupt, void *state);
extern int  lapic_to_cpu[];
extern int  cpu_to_lapic[];
extern void lapic_cpu_map(int lapic, int cpu_num);
#endif	/* ASSEMBLER */

#define CPU_NUMBER(r)				\
    	movl	EXT(lapic_id),r;		\
    	movl	0(r),r;				\
    	shrl	$(LAPIC_ID_SHIFT),r;		\
    	andl	$(LAPIC_ID_MASK),r;		\
	movl	EXT(lapic_to_cpu)(,r,4),r


#define	MP_IPL		SPL6	/* software interrupt level */

/* word describing the reason for the interrupt, one per cpu */

#ifndef	ASSEMBLER
#include <kern/lock.h>
extern	int	real_ncpus;		/* real number of cpus */
extern	int	wncpu;			/* wanted number of cpus */
decl_simple_lock_data(extern,kdb_lock)	/* kdb lock		*/
decl_simple_lock_data(extern,mp_putc_lock)

extern	int	kdb_cpu;		/* current cpu running kdb	*/
extern	int	kdb_debug;
extern	int	kdb_is_slave[];
extern	int	kdb_active[];

extern	volatile boolean_t mp_kdp_trap;
extern	void	mp_trap_enter();
extern	void	mp_trap_exit();

/*
 * All cpu rendezvous:
 */
extern void mp_rendezvous(void (*setup_func)(void *),
			  void (*action_func)(void *),
			  void (*teardown_func)(void *),
			  void *arg);

#if MP_DEBUG
typedef struct {
	uint64_t	time;
	int		cpu;
	mp_event_t	event;
} cpu_signal_event_t;

#define	LOG_NENTRIES	100
typedef struct {
	uint64_t		count[MP_LAST];
	int			next_entry;
	cpu_signal_event_t	entry[LOG_NENTRIES];
} cpu_signal_event_log_t;

extern cpu_signal_event_log_t	cpu_signal[NCPUS];
extern cpu_signal_event_log_t	cpu_handle[NCPUS];

#define DBGLOG(log,_cpu,_event) {					\
	cpu_signal_event_log_t	*logp = &log[cpu_number()];		\
	int			next = logp->next_entry;		\
	cpu_signal_event_t	*eventp = &logp->entry[next];		\
	boolean_t		spl = ml_set_interrupts_enabled(FALSE);	\
									\
	logp->count[_event]++;						\
									\
	eventp->time = rdtsc64();					\
	eventp->cpu = _cpu;						\
	eventp->event = _event;						\
	if (next == (LOG_NENTRIES - 1))					\
		logp->next_entry = 0;					\
	else								\
		logp->next_entry++;					\
									\
	(void) ml_set_interrupts_enabled(spl);				\
}
#else	/* MP_DEBUG */
#define DBGLOG(log,_cpu,_event)
#endif	/* MP_DEBUG */

#endif	/* ASSEMBLER */

#define i_bit(bit, word)	((long)(*(word)) & ((long)1 << (bit)))


/* 
 *	Device driver synchronization. 
 *
 *	at386_io_lock(op) and at386_io_unlock() are called
 *	by device drivers when accessing H/W. The underlying 
 *	Processing is machine dependant. But the op argument
 *	to the at386_io_lock is generic
 */

#define MP_DEV_OP_MAX	  4
#define MP_DEV_WAIT	  MP_DEV_OP_MAX	/* Wait for the lock */

/*
 * If the caller specifies an op value different than MP_DEV_WAIT, the
 * at386_io_lock function must return true if lock was successful else
 * false
 */

#define MP_DEV_OP_START 0	/* If lock busy, register a pending start op */
#define MP_DEV_OP_INTR	1	/* If lock busy, register a pending intr */
#define MP_DEV_OP_TIMEO	2	/* If lock busy, register a pending timeout */
#define MP_DEV_OP_CALLB	3	/* If lock busy, register a pending callback */

#else	/* NCPUS > 1 */
#define at386_io_lock_state()
#define at386_io_lock(op)	(TRUE)
#define at386_io_unlock()
#define mp_trap_enter()
#define mp_trap_exit()
#include	<i386/apic.h>
#endif	/* NCPUS > 1 */

#if	MACH_RT
#define _DISABLE_PREEMPTION(r) 					\
	movl	$ CPD_PREEMPTION_LEVEL,r			;	\
	incl	%gs:(r)

#define _ENABLE_PREEMPTION(r) 					\
	movl	$ CPD_PREEMPTION_LEVEL,r			;	\
	decl	%gs:(r)					;	\
	jne	9f					;	\
	pushl	%eax					;	\
	pushl	%ecx					;	\
	pushl	%edx					;	\
	call	EXT(kernel_preempt_check)		;	\
	popl	%edx					;	\
	popl	%ecx					;	\
	popl	%eax					;	\
9:	

#define _ENABLE_PREEMPTION_NO_CHECK(r)				\
	movl	$ CPD_PREEMPTION_LEVEL,r			;	\
	decl	%gs:(r)

#if	MACH_ASSERT
#define DISABLE_PREEMPTION(r)					\
	pushl	%eax;						\
	pushl	%ecx;						\
	pushl	%edx;						\
	call	EXT(_disable_preemption);			\
	popl	%edx;						\
	popl	%ecx;						\
	popl	%eax
#define ENABLE_PREEMPTION(r)					\
	pushl	%eax;						\
	pushl	%ecx;						\
	pushl	%edx;						\
	call	EXT(_enable_preemption);			\
	popl	%edx;						\
	popl	%ecx;						\
	popl	%eax
#define ENABLE_PREEMPTION_NO_CHECK(r)				\
	pushl	%eax;						\
	pushl	%ecx;						\
	pushl	%edx;						\
	call	EXT(_enable_preemption_no_check);		\
	popl	%edx;						\
	popl	%ecx;						\
	popl	%eax
#if	NCPUS > 1
#define MP_DISABLE_PREEMPTION(r)					\
	pushl	%eax;						\
	pushl	%ecx;						\
	pushl	%edx;						\
	call	EXT(_mp_disable_preemption);			\
	popl	%edx;						\
	popl	%ecx;						\
	popl	%eax
#define MP_ENABLE_PREEMPTION(r)					\
	pushl	%eax;						\
	pushl	%ecx;						\
	pushl	%edx;						\
	call	EXT(_mp_enable_preemption);			\
	popl	%edx;						\
	popl	%ecx;						\
	popl	%eax
#define MP_ENABLE_PREEMPTION_NO_CHECK(r)				\
	pushl	%eax;						\
	pushl	%ecx;						\
	pushl	%edx;						\
	call	EXT(_mp_enable_preemption_no_check);		\
	popl	%edx;						\
	popl	%ecx;						\
	popl	%eax
#else	/* NCPUS > 1 */
#define MP_DISABLE_PREEMPTION(r)
#define MP_ENABLE_PREEMPTION(r)
#define MP_ENABLE_PREEMPTION_NO_CHECK(r)
#endif	/* NCPUS > 1 */
#else	/* MACH_ASSERT */
#define DISABLE_PREEMPTION(r)			_DISABLE_PREEMPTION(r)
#define ENABLE_PREEMPTION(r)			_ENABLE_PREEMPTION(r)
#define ENABLE_PREEMPTION_NO_CHECK(r)		_ENABLE_PREEMPTION_NO_CHECK(r)
#if	NCPUS > 1
#define MP_DISABLE_PREEMPTION(r)		_DISABLE_PREEMPTION(r)
#define MP_ENABLE_PREEMPTION(r)			_ENABLE_PREEMPTION(r)
#define MP_ENABLE_PREEMPTION_NO_CHECK(r) 	_ENABLE_PREEMPTION_NO_CHECK(r)
#else	/* NCPUS > 1 */
#define MP_DISABLE_PREEMPTION(r)
#define MP_ENABLE_PREEMPTION(r)
#define MP_ENABLE_PREEMPTION_NO_CHECK(r)
#endif	/* NCPUS > 1 */
#endif	/* MACH_ASSERT */

#else	/* MACH_RT */
#define DISABLE_PREEMPTION(r)
#define ENABLE_PREEMPTION(r)
#define ENABLE_PREEMPTION_NO_CHECK(r)
#define MP_DISABLE_PREEMPTION(r)
#define MP_ENABLE_PREEMPTION(r)
#define MP_ENABLE_PREEMPTION_NO_CHECK(r)
#endif	/* MACH_RT */

#endif /* _I386AT_MP_H_ */
