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
 * Microkernel interface to common profiling.
 */

#include <profiling/profile-internal.h>
#include <mach/std_types.h>
#include <types.h>
#include <device/device_types.h>

/*
 * JMM - We don't use these, just the BSD interfaces.
 */
#if 0
extern void kmstartup(void);
extern int gprofprobe(caddr_t, void *);
extern void gprofattach(void);
extern int gprofopen(dev_t, int, io_req_t);
extern void gprofclose(dev_t);
extern void gprofstrategy(io_req_t);
extern int gprofread(dev_t, io_req_t);
extern int gprofwrite(dev_t, io_req_t);
#endif

/*
 * Macros to access the nth cpu's profile variable structures.
 */

#if NCPUS <= 1
#define PROFILE_VARS(cpu) (&_profile_vars)

#else
extern struct profile_vars *_profile_vars_cpus[NCPUS];
#define PROFILE_VARS(cpu) (_profile_vars_cpus[(cpu)])
#endif


