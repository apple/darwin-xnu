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
/*
 *	Definitions of general Mach system traps.
 *
 *	IPC traps are defined in <mach/message.h>.
 *	Kernel RPC functions are defined in <mach/mach_interface.h>.
 */

#ifndef	_MACH_MACH_TRAPS_H_
#define _MACH_MACH_TRAPS_H_

#include <mach/kern_return.h>
#include <mach/port.h>
#include <mach/vm_types.h>
#include <mach/clock_types.h>

mach_port_name_t	mach_reply_port(void);

mach_port_name_t	thread_self_trap(void);

mach_port_name_t	task_self_trap(void);

mach_port_name_t	host_self_trap(void);

kern_return_t		semaphore_signal_trap(
				mach_port_name_t signal_name);
					      
kern_return_t		semaphore_signal_all_trap(
				mach_port_name_t signal_name);

kern_return_t		semaphore_signal_thread_trap(
				mach_port_name_t signal_name,
				mach_port_name_t thread_name);

kern_return_t		semaphore_wait_trap(
				mach_port_name_t wait_name);

kern_return_t		semaphore_timedwait_trap(
				mach_port_name_t wait_name,
				unsigned int sec,
				clock_res_t nsec);

kern_return_t		semaphore_wait_signal_trap(
				mach_port_name_t wait_name,
				mach_port_name_t signal_name);

kern_return_t		semaphore_timedwait_signal_trap(
				mach_port_name_t wait_name,
				mach_port_name_t signal_name,
				unsigned int sec,
				clock_res_t nsec);

kern_return_t		init_process(void);

kern_return_t		map_fd(
                            int		fd,
                            vm_offset_t	offset,
                            vm_offset_t	*va,
                            boolean_t	findspace,
                            vm_size_t	size);

kern_return_t		task_for_pid(
                            mach_port_t	target_tport,
                            int		pid,
                            mach_port_t	*t);

kern_return_t		pid_for_task(
                            mach_port_t	t,
                            int		*x);

kern_return_t		macx_swapon(
			char		*name,
			int		flags,
			int		size,
			int		priority);

kern_return_t		macx_swapoff(
			char		*name,
			int		flags);

extern	kern_return_t	macx_triggers(
			int		hi_water,
			int		low_water,
			int		flags,
			mach_port_t	alert_port);

#endif	/* _MACH_MACH_TRAPS_H_ */
