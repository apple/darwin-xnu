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

#ifndef	_MACH_SYSCALL_SW_H_
#define _MACH_SYSCALL_SW_H_

/*
 *	The machine-dependent "syscall_sw.h" file should
 *	define a macro for
 *		kernel_trap(trap_name, trap_number, arg_count)
 *	which will expand into assembly code for the
 *	trap.
 *
 *	N.B.: When adding calls, do not put spaces in the macros.
 */

#include <mach/machine/syscall_sw.h>

/*
 *	These trap numbers should be taken from the
 *	table in <kern/syscall_sw.c>.
 */

kernel_trap(mach_reply_port,-26,0)
kernel_trap(thread_self_trap,-27,0)
kernel_trap(task_self_trap,-28,0)
kernel_trap(host_self_trap,-29,0)
kernel_trap(mach_msg_overwrite_trap,-32,9)
kernel_trap(semaphore_signal_trap, -33, 1)
kernel_trap(semaphore_signal_all_trap, -34, 1)
kernel_trap(semaphore_signal_thread_trap, -35, 2)
kernel_trap(semaphore_wait_trap,-36,1)
kernel_trap(semaphore_wait_signal_trap,-37,2)
kernel_trap(semaphore_timedwait_trap,-38,3)
kernel_trap(semaphore_timedwait_signal_trap,-39,4)

kernel_trap(init_process,-41,0)
kernel_trap(map_fd,-43,5)
kernel_trap(task_for_pid,-45,3)
kernel_trap(pid_for_task,-46,2)
kernel_trap(macx_swapon,-48, 4)
kernel_trap(macx_swapoff,-49, 2)
kernel_trap(macx_triggers,-51, 4)

kernel_trap(swtch_pri,-59,1)
kernel_trap(swtch,-60,0)
kernel_trap(syscall_thread_switch,-61,3)
kernel_trap(clock_sleep_trap,-62,5)

kernel_trap(mach_timebase_info,-89,1)
kernel_trap(mach_wait_until,-90,2)
kernel_trap(mk_wait_until,-90,2)
kernel_trap(mk_timer_create,-91,0)
kernel_trap(mk_timer_destroy,-92,1)
kernel_trap(mk_timer_arm,-93,3)
kernel_trap(mk_timer_cancel,-94,2)

kernel_trap(MKGetTimeBaseInfo,-95,5)

#endif	/* _MACH_SYSCALL_SW_H_ */
