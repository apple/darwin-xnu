/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
#ifndef	_PPC_CPU_INTERNAL_H_
#define	_PPC_CPU_INTERNAL_H_

#include <mach/kern_return.h>
#include <ppc/exception.h>

extern void						_start_cpu(
										void);

extern void						cpu_bootstrap(
										void);

extern void						cpu_init(
										void);

extern	void					cpu_machine_init(
										void);

extern void						cpu_doshutdown(
										void);

extern void						cpu_signal_handler(
										void);

extern kern_return_t			cpu_signal(
										int				target,
										int				signal,
										unsigned int	p1,
										unsigned int	p2);

#define SIGPast			0		/* Requests an ast on target processor */
#define SIGPcpureq		1		/* Requests CPU specific function */
#define SIGPdebug		2		/* Requests a debugger entry */
#define SIGPwake		3		/* Wake up a sleeping processor */
#define SIGPcall		4		/* Call a function on a processor */

#define CPRQtimebase	1		/* Get timebase of processor */
#define CPRQsegload		2		/* Segment registers reload */
#define CPRQscom		3		/* SCOM */
#define CPRQchud		4		/* CHUD perfmon */
#define CPRQsps			5		/* Set Processor Speed */


extern struct per_proc_info *	cpu_per_proc_alloc(
										void);

extern void						cpu_per_proc_free(
										struct per_proc_info *per_proc);

extern void *					console_per_proc_alloc(
										boolean_t boot_processor);

extern void 					console_per_proc_free(
										void *per_proc_cbfr);

extern void * 					chudxnu_per_proc_alloc(
										boolean_t boot_processor);

extern void						chudxnu_per_proc_free(
										void *per_proc_chud);

extern kern_return_t			cpu_per_proc_register(
										struct per_proc_info	*proc_info);

extern	unsigned int			real_ncpus;
extern	unsigned int			max_ncpus;

#endif	/* _PPC_CPU_INTERNAL_H_ */
