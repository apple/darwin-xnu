/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
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

#include <mach/mach_types.h>
#include <mach/mach_traps.h>

#include <kern/syscall_sw.h>

/* Forwards */


/*
 *	To add a new entry:
 *		Add an "MACH_TRAP(routine, arg count)" to the table below.
 *
 *		Add trap definition to mach/syscall_sw.h and
 *		recompile user library.
 *
 * WARNING:	If you add a trap which requires more than 7
 *		parameters, mach/{machine}/syscall_sw.h and {machine}/trap.c
 *		and/or {machine}/locore.s may need to be modified for it
 *		to work successfully.
 *
 * WARNING:	Don't use numbers 0 through -9.  They (along with
 *		the positive numbers) are reserved for Unix.
 */

int kern_invalid_debug = 0;

/* Include declarations of the trap functions. */

#include <mach/mach_traps.h>
#include <mach/mach_syscalls.h>
#include <kern/syscall_subr.h>

#include <kern/clock.h>
#include <mach/mk_timer.h>

mach_trap_t	mach_trap_table[MACH_TRAP_TABLE_COUNT] = {
/* 0 */		MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 1 */		MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 2 */		MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 3 */		MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 4 */		MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 5 */		MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 6 */		MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 7 */		MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 8 */		MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 9 */		MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 10 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 11 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 12 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 13 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 14 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 15 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 16 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 17 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 18 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 19 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 20 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 21 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 22 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 23 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 24 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 25 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 26 */	MACH_TRAP(mach_reply_port, 0, NULL, NULL),
/* 27 */	MACH_TRAP(thread_self_trap, 0, NULL, NULL),
/* 28 */	MACH_TRAP(task_self_trap, 0, NULL, NULL),
/* 29 */	MACH_TRAP(host_self_trap, 0, NULL, NULL),
/* 30 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 31 */	MACH_TRAP(mach_msg_trap, 7, munge_wwwwwww, munge_ddddddd),
/* 32 */	MACH_TRAP(mach_msg_overwrite_trap, 8, munge_wwwwwwww, munge_dddddddd),
/* 33 */	MACH_TRAP(semaphore_signal_trap, 1, munge_w, munge_d),
/* 34 */	MACH_TRAP(semaphore_signal_all_trap, 1, munge_w, munge_d),
/* 35 */	MACH_TRAP(semaphore_signal_thread_trap, 2, munge_ww, munge_dd),
/* 36 */	MACH_TRAP(semaphore_wait_trap, 1, munge_w, munge_d),
/* 37 */	MACH_TRAP(semaphore_wait_signal_trap, 2, munge_ww, munge_dd),
/* 38 */	MACH_TRAP(semaphore_timedwait_trap, 3, munge_www, munge_ddd),
/* 39 */	MACH_TRAP(semaphore_timedwait_signal_trap, 4, munge_wwww, munge_dddd),
/* 40 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 41 */	MACH_TRAP(init_process, 0, NULL, NULL),
/* 42 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 43 */	MACH_TRAP(map_fd, 5, munge_wwwww, munge_ddddd),
/* 44 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 45 */ 	MACH_TRAP(task_for_pid, 3, munge_www, munge_ddd),
/* 46 */	MACH_TRAP(pid_for_task, 2, munge_ww,munge_dd),
/* 47 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 48 */	MACH_TRAP(macx_swapon, 4, munge_wwww, munge_dddd),
/* 49 */	MACH_TRAP(macx_swapoff, 2, munge_ww, munge_dd),
/* 50 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 51 */	MACH_TRAP(macx_triggers, 4, munge_wwww, munge_dddd),
/* 52 */	MACH_TRAP(macx_backing_store_suspend, 1, munge_w, munge_d),
/* 53 */	MACH_TRAP(macx_backing_store_recovery, 1, munge_w, munge_d),
/* 54 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 55 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 56 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 57 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 58 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 59 */ 	MACH_TRAP(swtch_pri, 0, NULL, NULL),
/* 60 */	MACH_TRAP(swtch, 0, NULL, NULL),
/* 61 */	MACH_TRAP(thread_switch, 3, munge_www, munge_ddd),
/* 62 */	MACH_TRAP(clock_sleep_trap, 5, munge_wwwww, munge_ddddd),
/* 63 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* traps 64 - 95 reserved (debo) */
/* 64 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 65 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 66 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 67 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 68 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 69 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 70 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 71 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 72 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 73 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 74 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 75 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 76 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 77 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 78 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 79 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 80 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 81 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 82 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 83 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 84 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 85 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 86 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 87 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 88 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 89 */	MACH_TRAP(mach_timebase_info_trap, 1, munge_w, munge_d),
/* 90 */	MACH_TRAP(mach_wait_until_trap, 2, munge_l, munge_d),
/* 91 */	MACH_TRAP(mk_timer_create_trap, 0, NULL, NULL),
/* 92 */	MACH_TRAP(mk_timer_destroy_trap, 1, munge_w, munge_d),
/* 93 */	MACH_TRAP(mk_timer_arm_trap, 3, munge_wl, munge_dd),
/* 94 */	MACH_TRAP(mk_timer_cancel_trap, 2, munge_ww, munge_dd),		
/* 95 */	MACH_TRAP(mk_timebase_info_trap, 5, munge_wwwww, munge_ddddd),		
/* traps 64 - 95 reserved (debo) */
/* 96 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 97 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 98 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 99 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* traps 100-107 reserved for iokit (esb) */ 
/* 100 */	MACH_TRAP(iokit_user_client_trap, 8, munge_wwwwwwww, munge_dddddddd),
/* 101 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 102 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 103 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 104 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 105 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 106 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 107 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* traps 108-127 unused */			
/* 108 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 109 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 110 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 111 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 112 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 113 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 114 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 115 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 116 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 117 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 118 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 119 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 120 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 121 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 122 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 123 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 124 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 125 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 126 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),
/* 127 */	MACH_TRAP(kern_invalid, 0, NULL, NULL),			
};

int	mach_trap_count = (sizeof(mach_trap_table) / sizeof(mach_trap_table[0]));

kern_return_t
kern_invalid(
	__unused struct kern_invalid_args *args)
{
	if (kern_invalid_debug) Debugger("kern_invalid mach trap");
	return(KERN_INVALID_ARGUMENT);
}

