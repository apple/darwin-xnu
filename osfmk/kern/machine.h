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

#ifndef	_KERN_MACHINE_H_
#define	_KERN_MACHINE_H_

#include <cpus.h>
#include <mach/kern_return.h>
#include <mach/processor_info.h>
#include <kern/kern_types.h>

/*
 * Machine support declarations.
 */

extern thread_t        	machine_wake_thread;

extern void		cpu_down(
					int			cpu);

extern void		cpu_up(
					int			cpu);

extern void		processor_offline(
					processor_t		processor);

/*
 * Must be implemented in machine dependent code.
 */

/* Initialize machine dependent ast code */
extern void		init_ast_check(
					processor_t		processor);

/* Cause check for ast */
extern void		cause_ast_check(
					processor_t		processor);

extern kern_return_t	cpu_start(
						int			slot_num);

extern kern_return_t	cpu_control(
						int					slot_num,
						processor_info_t	info,
						unsigned int		count);

extern thread_t		switch_to_shutdown_context(
					thread_t		thread,
					void			(*doshutdown)(processor_t),
					processor_t		processor);

extern kern_return_t cpu_signal(				/* Signal the target CPU */
					int target, 
					int signal, 
					unsigned int p1, 
					unsigned int p2);

#endif	/* _KERN_MACHINE_H_ */
