/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */

#ifdef	XNU_KERNEL_PRIVATE

#ifndef	_KERN_STARTUP_H_
#define	_KERN_STARTUP_H_

#include <sys/cdefs.h>
__BEGIN_DECLS

/*
 * Kernel and machine startup declarations
 */

/* Initialize kernel */
extern void		kernel_bootstrap(void);

/* Initialize machine dependent stuff */
extern void	machine_init(void);

extern void	slave_main(void);

/*
 * The following must be implemented in machine dependent code.
 */

/* Slave cpu initialization */
extern void	slave_machine_init(void);

/* Device subystem initialization */
extern void	device_service_create(void);

#ifdef	MACH_BSD

/* BSD subsystem initialization */
extern void	bsd_init(void);

#endif	/* MACH_BSD */

__END_DECLS

#endif	/* _KERN_STARTUP_H_ */

#endif	/* XNU_KERNEL_PRIVATE */
