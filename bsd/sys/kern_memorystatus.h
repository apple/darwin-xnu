/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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
/*!
	@header kern_memorystatus.h
	This header defines a kernel event subclass for the OSMemoryNotification API
 */

#ifndef SYS_KERN_MEMORYSTATUS_H
#define SYS_KERN_MEMORYSTATUS_H

/*
 * Define Memory Status event subclass.
 * Subclass of KEV_SYSTEM_CLASS
 */

/*!
	@defined KEV_MEMORYSTATUS_SUBCLASS
	@discussion The kernel event subclass for memory status events.
*/
#define KEV_MEMORYSTATUS_SUBCLASS        3

enum {
	kMemoryStatusLevelAny = -1,
	kMemoryStatusLevelNormal = 0,
	kMemoryStatusLevelWarning = 1,
	kMemoryStatusLevelUrgent = 2,
	kMemoryStatusLevelCritical = 3
};

#ifdef KERNEL
extern void kern_memorystatus_init(void) __attribute__((section("__TEXT, initcode")));

extern int kern_memorystatus_wakeup;
extern int kern_memorystatus_level;

#endif /* KERNEL */
#endif /* SYS_KERN_MEMORYSTATUS_H */
