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
