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

#include <kern/syscall_sw.h>

/* Forwards */
extern kern_return_t	kern_invalid(void);
extern mach_port_name_t	null_port(void);
extern kern_return_t	not_implemented(void);

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

extern kern_return_t iokit_user_client_trap();

mach_trap_t	mach_trap_table[] = {
	MACH_TRAP(kern_invalid, 0),			/* 0 */		/* Unix */
	MACH_TRAP(kern_invalid, 0),			/* 1 */		/* Unix */
	MACH_TRAP(kern_invalid, 0),			/* 2 */		/* Unix */
	MACH_TRAP(kern_invalid, 0),			/* 3 */		/* Unix */
	MACH_TRAP(kern_invalid, 0),			/* 4 */		/* Unix */
	MACH_TRAP(kern_invalid, 0),			/* 5 */		/* Unix */
	MACH_TRAP(kern_invalid, 0),			/* 6 */		/* Unix */
	MACH_TRAP(kern_invalid, 0),			/* 7 */		/* Unix */
	MACH_TRAP(kern_invalid, 0),			/* 8 */		/* Unix */
	MACH_TRAP(kern_invalid, 0),			/* 9 */		/* Unix */
	MACH_TRAP(kern_invalid, 0),			/* 10 */
	MACH_TRAP(kern_invalid, 0),			/* 11 */
	MACH_TRAP(kern_invalid, 0),			/* 12 */
	MACH_TRAP(kern_invalid, 0),			/* 13 */
	MACH_TRAP(kern_invalid, 0),			/* 14 */
	MACH_TRAP(kern_invalid, 0),			/* 15 */
	MACH_TRAP(kern_invalid, 0),			/* 16 */
	MACH_TRAP(kern_invalid, 0),			/* 17 */
	MACH_TRAP(kern_invalid, 0),			/* 18 */
	MACH_TRAP(kern_invalid, 0),			/* 19 */
	MACH_TRAP(kern_invalid, 0),			/* 20 */
	MACH_TRAP(kern_invalid, 0),			/* 21 */
	MACH_TRAP(kern_invalid, 0),			/* 22 */
	MACH_TRAP(kern_invalid, 0),			/* 23 */
	MACH_TRAP(kern_invalid, 0),			/* 24 */
	MACH_TRAP(kern_invalid, 0),			/* 25 */
	MACH_TRAP(mach_reply_port, 0),			/* 26 */
	MACH_TRAP(thread_self_trap, 0),			/* 27 */
	MACH_TRAP(task_self_trap, 0),			/* 28 */
	MACH_TRAP(host_self_trap, 0),			/* 29 */
	MACH_TRAP(kern_invalid, 0),			/* 30 */
	MACH_TRAP(mach_msg_trap, 7),			/* 31 */
	MACH_TRAP(mach_msg_overwrite_trap, 9),		/* 32 */
	MACH_TRAP(semaphore_signal_trap, 1),		/* 33 */
	MACH_TRAP(semaphore_signal_all_trap, 1),	/* 34 */
	MACH_TRAP(semaphore_signal_thread_trap, 2),	/* 35 */
	MACH_TRAP(semaphore_wait_trap, 1),		/* 36 */
	MACH_TRAP(semaphore_wait_signal_trap, 2),	/* 37 */
	MACH_TRAP(semaphore_timedwait_trap, 3),		/* 38 */
	MACH_TRAP(semaphore_timedwait_signal_trap, 4),	/* 39 */
	MACH_TRAP(kern_invalid, 0),			/* 40 */
	MACH_TRAP(init_process, 0),			/* 41 */
	MACH_TRAP(kern_invalid, 0),			/* 42 */
	MACH_TRAP(map_fd, 5),				/* 43 */
	MACH_TRAP(kern_invalid, 0),			/* 44 */
	MACH_TRAP(task_for_pid, 3),			/* 45 */ 
	MACH_TRAP(pid_for_task, 2),			/* 46 */
	MACH_TRAP(kern_invalid, 0),			/* 47 */
	MACH_TRAP(macx_swapon, 4),			/* 48 */
	MACH_TRAP(macx_swapoff, 2),			/* 49 */
	MACH_TRAP(kern_invalid, 0),			/* 50 */
	MACH_TRAP(macx_triggers, 4),			/* 51 */
	MACH_TRAP(kern_invalid, 0),			/* 52 */
	MACH_TRAP(kern_invalid, 0),			/* 53 */
	MACH_TRAP(kern_invalid, 0),			/* 54 */
	MACH_TRAP(kern_invalid, 0),			/* 55 */
	MACH_TRAP(kern_invalid, 0),			/* 56 */
	MACH_TRAP(kern_invalid, 0),			/* 57 */
	MACH_TRAP(kern_invalid, 0),			/* 58 */
 	MACH_TRAP(swtch_pri, 1),			/* 59 */
	MACH_TRAP(swtch, 0),				/* 60 */
	MACH_TRAP(thread_switch, 3),		/* 61 */
	MACH_TRAP(clock_sleep_trap, 5),		/* 62 */
	MACH_TRAP(kern_invalid,0),			/* 63 */
/* traps 64 - 95 reserved (debo) */
	MACH_TRAP(kern_invalid,0),			/* 64 */
	MACH_TRAP(kern_invalid,0),			/* 65 */
	MACH_TRAP(kern_invalid,0),			/* 66 */
	MACH_TRAP(kern_invalid,0),			/* 67 */
	MACH_TRAP(kern_invalid,0),			/* 68 */
	MACH_TRAP(kern_invalid,0),			/* 69 */
	MACH_TRAP(kern_invalid,0),			/* 70 */
	MACH_TRAP(kern_invalid,0),			/* 71 */
	MACH_TRAP(kern_invalid,0),			/* 72 */
	MACH_TRAP(kern_invalid,0),			/* 73 */
	MACH_TRAP(kern_invalid,0),			/* 74 */
	MACH_TRAP(kern_invalid,0),			/* 75 */
	MACH_TRAP(kern_invalid,0),			/* 76 */
	MACH_TRAP(kern_invalid,0),			/* 77 */
	MACH_TRAP(kern_invalid,0),		 	/* 78 */
	MACH_TRAP(kern_invalid,0),			/* 79 */
	MACH_TRAP(kern_invalid,0),			/* 80 */
	MACH_TRAP(kern_invalid,0),			/* 81 */
	MACH_TRAP(kern_invalid,0),			/* 82 */
	MACH_TRAP(kern_invalid,0),			/* 83 */
	MACH_TRAP(kern_invalid,0),			/* 84 */
	MACH_TRAP(kern_invalid,0),			/* 85 */
	MACH_TRAP(kern_invalid,0),			/* 86 */
	MACH_TRAP(kern_invalid,0),			/* 87 */
	MACH_TRAP(kern_invalid,0),			/* 88 */
	MACH_TRAP(mach_timebase_info, 1),	/* 89 */
	MACH_TRAP(mach_wait_until,	2),		/* 90 */
	MACH_TRAP(mk_timer_create,	0),		/* 91 */
	MACH_TRAP(mk_timer_destroy,	1),		/* 92 */
	MACH_TRAP(mk_timer_arm,		3),		/* 93 */
	MACH_TRAP(mk_timer_cancel,	2),		/* 94 */
	MACH_TRAP(mk_timebase_info,	5),		/* 95 */
/* traps 64 - 95 reserved (debo) */
	MACH_TRAP(kern_invalid,0),			/* 96 */
	MACH_TRAP(kern_invalid,0),			/* 97 */
	MACH_TRAP(kern_invalid,0),			/* 98 */
	MACH_TRAP(kern_invalid,0),			/* 99 */
/* traps 100-107 reserved for iokit (esb) */ 
	MACH_TRAP(iokit_user_client_trap, 8),
										/* 100 */	/* IOKit */
	MACH_TRAP(kern_invalid,0),			/* 101 */	/* IOKit */
	MACH_TRAP(kern_invalid,0),			/* 102 */	/* IOKit */
	MACH_TRAP(kern_invalid,0),			/* 103 */	/* IOKit */
	MACH_TRAP(kern_invalid,0),			/* 104 */	/* IOKit */
	MACH_TRAP(kern_invalid,0),			/* 105 */	/* IOKit */
	MACH_TRAP(kern_invalid,0),			/* 106 */	/* IOKit */
	MACH_TRAP(kern_invalid,0),			/* 107 */	/* IOKit */
	MACH_TRAP(kern_invalid,0),			/* 108 */
	MACH_TRAP(kern_invalid,0),			/* 109 */
	MACH_TRAP(kern_invalid,0),			/* 110 */
	MACH_TRAP(kern_invalid,0),			/* 111 */
	MACH_TRAP(kern_invalid,0),			/* 112 */
	MACH_TRAP(kern_invalid,0),			/* 113 */
	MACH_TRAP(kern_invalid,0),			/* 114 */
	MACH_TRAP(kern_invalid,0),			/* 115 */
	MACH_TRAP(kern_invalid,0),			/* 116 */
	MACH_TRAP(kern_invalid,0),			/* 117 */
	MACH_TRAP(kern_invalid,0),			/* 118 */
	MACH_TRAP(kern_invalid,0),			/* 119 */
	MACH_TRAP(kern_invalid,0),			/* 120 */
	MACH_TRAP(kern_invalid,0),			/* 121 */
	MACH_TRAP(kern_invalid,0),			/* 122 */
	MACH_TRAP(kern_invalid,0),			/* 123 */
	MACH_TRAP(kern_invalid,0),			/* 124 */
	MACH_TRAP(kern_invalid,0),			/* 125 */
	MACH_TRAP(kern_invalid,0),			/* 126 */
	MACH_TRAP(kern_invalid,0),			/* 127 */
};

int	mach_trap_count = (sizeof(mach_trap_table) / sizeof(mach_trap_table[0]));

mach_port_name_t
null_port(void)
{
	if (kern_invalid_debug) Debugger("null_port mach trap");
	return(MACH_PORT_NULL);
}

kern_return_t
kern_invalid(void)
{
	if (kern_invalid_debug) Debugger("kern_invalid mach trap");
	return(KERN_INVALID_ARGUMENT);
}

kern_return_t
not_implemented(void)
{
	return(MACH_SEND_INTERRUPTED);
}
