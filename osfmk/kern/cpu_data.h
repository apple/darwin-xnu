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

#ifndef	_CPU_DATA_H_
#define	_CPU_DATA_H_

#include <sys/appleapiopts.h>

#ifdef	__APPLE_API_PRIVATE

#ifdef	MACH_KERNEL_PRIVATE

#include <cpus.h>
#include <mach/mach_types.h>

#include <machine/cpu_data.h>

#else	/* MACH_KERNEL_PRIVATE */

#define disable_preemption()			_disable_preemption()
#define enable_preemption()			_enable_preemption()
#define enable_preemption_no_check()		_enable_preemption_no_check()

#endif	/* MACH_KERNEL_PRIVATE */

#endif	/* __APPLE_API_PRIVATE */

#ifdef	__APPLE_API_UNSTABLE

#if		!defined(MACH_KERNEL_PRIVATE)

extern thread_t			current_thread(void);

#endif	/* MACH_KERNEL_PRIVATE */

#endif	/* __APPLE_API_UNSTABLE */

#endif	/* _CPU_DATA_H_ */
