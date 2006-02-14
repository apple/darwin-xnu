/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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

#include <mach/kern_return.h>
#include <mach/processor_info.h>
#include <kern/kern_types.h>

/*
 * Machine support declarations.
 */

extern void		processor_up(
					processor_t		processor);

extern void		processor_offline(
					processor_t		processor);

extern void		processor_start_thread(void);

/*
 * Must be implemented in machine dependent code.
 */

/* Initialize machine dependent ast code */
extern void init_ast_check(
					processor_t         processor);

/* Cause check for ast */
extern void cause_ast_check(
					processor_t         processor);

extern kern_return_t cpu_control(
					int                 slot_num,
					processor_info_t    info,
					unsigned int        count);

extern void	cpu_sleep(void);

extern kern_return_t cpu_start(
					int                 slot_num);

extern void cpu_exit_wait(
					int                 slot_num);

extern kern_return_t cpu_info(
					processor_flavor_t  flavor,
					int                 slot_num,
					processor_info_t    info,
					unsigned int        *count);

extern kern_return_t cpu_info_count(
					processor_flavor_t  flavor,
					unsigned int        *count);

extern thread_t		machine_processor_shutdown(
						thread_t            thread,
						void                (*doshutdown)(processor_t),
						processor_t         processor);

extern void machine_idle(void);

extern void machine_signal_idle(
					processor_t         processor);

extern void halt_cpu(void);

extern void halt_all_cpus(
					boolean_t           reboot);

extern char *machine_boot_info(
					char                *buf,
					vm_size_t           buf_len);

/*
 * Machine-dependent routine to fill in an array with up to callstack_max
 * levels of return pc information.
 */
extern void machine_callstack(
					natural_t           *buf,
					vm_size_t           callstack_max);

extern void consider_machine_collect(void);

#endif	/* _KERN_MACHINE_H_ */
