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
 *	File:	next/reboot.h
 *	Author:	Avadis Tevanian, Jr.
 *
 *	NeXT specific reboot flags.
 *
 * HISTORY
 * 28-Feb-90  John Seamons (jks) at NeXT
 *	Added RB_COMMAND flag that allows a specific reboot command to be used.
 *
 * 06-Jul-88  Avadis Tevanian (avie) at NeXT, Inc.
 *	Created.
 */
 
#ifndef	_BSD_I386_REBOOT_H_
#define _BSD_I386_REBOOT_H_

/*
 * Empty file (publicly)
 */
 
#ifdef	KERNEL_PRIVATE

/*
 *	Use most significant 16 bits to avoid collisions with
 *	machine independent flags.
 */
#define RB_POWERDOWN	0x00010000	/* power down on halt */
#define	RB_NOBOOTRC	0x00020000	/* don't run '/etc/rc.boot' */
#define	RB_DEBUG	0x00040000	/* drop into mini monitor on panic */
#define	RB_EJECT	0x00080000	/* eject disks on halt */
#define	RB_COMMAND	0x00100000	/* new boot command specified */
#define RB_NOFP		0x00200000	/* don't use floating point */
#define RB_BOOTNEXT	0x00400000	/* reboot into NeXT */
#define RB_BOOTDOS	0x00800000	/* reboot into DOS */
#define RB_PRETTY	0x01000000	/* shutdown with pretty graphics */

#endif	/* KERNEL_PRIVATE */

#endif	/* _BSD_I386_REBOOT_H_ */
