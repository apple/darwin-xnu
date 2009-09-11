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

#define PROFILE_VARS(cpu) (&_profile_vars)


