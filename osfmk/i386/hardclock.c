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
 * Clock interrupt.
 */
#include <cpus.h>
#include <time_stamp.h>
#include <mach_kdb.h>
#include <kern/cpu_number.h>
#include <kern/cpu_data.h>
#include <kern/kern_types.h>
#include <platforms.h>
#include <mach_kprof.h>
#include <mach_mp_debug.h>
#include <mach/std_types.h>

#include <mach/clock_types.h>
#include <mach/boolean.h>
#include <i386/thread.h>
#include <i386/eflags.h>
#include <kern/assert.h>
#include <kern/misc_protos.h>
#include <i386/misc_protos.h>
#include <kern/time_out.h>
#include <kern/processor.h>

#include <i386/ipl.h>

#include <i386/hardclock_entries.h>
#include <i386/rtclock_entries.h>

#if	MACH_MP_DEBUG
#include <i386/mach_param.h>	/* for HZ */
#endif	/* MACH_MP_DEBUG */

extern	char	return_to_iret[];

#if	TIME_STAMP && NCPUS > 1
extern	unsigned time_stamp;
unsigned old_time_stamp, time_stamp_cum, nstamps;

/*
 *	If H/W provides a counter, record number of ticks and cumulated
 *	time stamps to know timestamps rate.
 *	This should go away when ALARMCLOCKS installed
 */
#define time_stamp_stat()					\
	if (my_cpu == 0)					\
	if (!old_time_stamp) {					\
		old_time_stamp = time_stamp;			\
		nstamps = 0;					\
	} else {						\
		nstamps++;					\
		time_stamp_cum = (time_stamp - old_time_stamp);	\
	}
#else	/* TIME_STAMP && AT386 && NCPUS > 1 */
#define time_stamp_stat()
#endif	/* TIME_STAMP && AT386 && NCPUS > 1 */

#if	MACH_KPROF
int	masked_pc[NCPUS];
int	missed_clock[NCPUS];
int	detect_lost_tick = 0;
#endif	/* MACH_KPROF */

#if	MACH_MP_DEBUG
int	masked_state_cnt[NCPUS];
int	masked_state_max = 10*HZ;
#endif	/* MACH_MP_DEBUG */

/*
 * In the interest of a fast clock interrupt service path,
 * this routine should be folded into assembly language with
 * a direct interrupt vector on the i386. The "pit" interrupt
 * should always call the rtclock_intr() routine on the master
 * processor. The return value of the rtclock_intr() routine
 * indicates whether HZ rate clock processing should be
 * performed. (On the Sequent, all slave processors will
 * run at HZ rate). For now, we'll leave this routine in C
 * (with TIME_STAMP, MACH_MP_DEBUG and MACH_KPROF code this
 * routine is way too large for assembler anyway).
 */

#ifdef	PARANOID_KDB
int paranoid_debugger = TRUE;
int paranoid_count = 1000;
int paranoid_current = 0;
int paranoid_cpu = 0;
#endif	/* PARANOID_KDB */

void
hardclock(struct i386_interrupt_state	*regs) /* saved registers */
{
	int mycpu;
	register unsigned pc;
	register boolean_t usermode;

	mp_disable_preemption();
	mycpu = cpu_number();

#ifdef	PARANOID_KDB
	if (paranoid_cpu == mycpu &&
	    paranoid_current++ >= paranoid_count) {
		paranoid_current = 0;
		if (paranoid_debugger)
		    Debugger("hardclock");
	}
#endif	/* PARANOID_KDB */

#if	MACH_KPROF
	/*
	 * If we were masked against the clock skip call
	 * to rtclock_intr(). When MACH_KPROF is set, the
	 * clock frequency of the master-cpu is confined
	 * to the HZ rate.
	 */
	if (SPL_CMP_GE((old_ipl & 0xFF), SPL7)) {
		usermode = (regs->efl & EFL_VM) || ((regs->cs & 0x03) != 0);
		pc = (unsigned)regs->eip;
		assert(!usermode);
		if (missed_clock[mycpu]++ && detect_lost_tick > 1)
			Debugger("Mach_KPROF");
		masked_pc[mycpu] = pc;
	} else
#endif	/* MACH_KPROF */
	/*
	 * The master processor executes the rtclock_intr() routine
	 * on every clock tick. The rtclock_intr() routine returns
	 * a zero value on a HZ tick boundary.
	 */
	if (mycpu == master_cpu) {
		if (rtclock_intr(regs) != 0) {
			mp_enable_preemption();
			return;
		}
	} else {
		usermode = (regs->efl & EFL_VM) || ((regs->cs & 0x03) != 0);
		pc = (unsigned)regs->eip;
		hertz_tick(usermode, pc);
	}

	/*
	 * The following code is executed at HZ rate by all processors
	 * in the system. This implies that the clock rate on slave
	 * processors must be HZ rate.
	 */

	time_stamp_stat();

#if	NCPUS >1 
	/*
	 * Instead of having the master processor interrupt
	 * all active processors, each processor in turn interrupts
	 * the next active one. This avoids all slave processors
	 * accessing the same R/W data simultaneously.
	 */
	slave_clock();
#endif	/* NCPUS >1 && AT386 */

	mp_enable_preemption();
}

#if	MACH_KPROF
void
delayed_clock(void)
{
	int	i;
	int	my_cpu;

	mp_disable_preemption();
	my_cpu = cpu_number();

	if (missed_clock[my_cpu] > 1 && detect_lost_tick)
		printf("hardclock: missed %d clock interrupt(s) at %x\n",
		       missed_clock[my_cpu]-1, masked_pc[my_cpu]);
	if (my_cpu == master_cpu) {
		i = rtclock_intr();
		assert(i == 0);
	}
	hertz_tick(0, masked_pc[my_cpu]);
	missed_clock[my_cpu] = 0;

	mp_enable_preemption();
}
#endif	/* MACH_KPROF */
