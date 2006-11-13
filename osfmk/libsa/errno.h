/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:51  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:35  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.5.1  1997/01/31  15:46:31  emcmanus
 * 	Merged with nmk22b1_shared.
 * 	[1997/01/30  08:42:08  emcmanus]
 *
 * Revision 1.1.2.5  1996/11/29  13:04:57  emcmanus
 * 	Added EIO for libsa_mach's getclock().
 * 	[1996/11/29  09:59:19  emcmanus]
 * 
 * Revision 1.1.2.4  1996/11/08  12:02:15  emcmanus
 * 	Replaced errno variable by a macro that calls a function defined
 * 	either in libsa_mach or in a threads library.
 * 	[1996/11/08  11:48:47  emcmanus]
 * 
 * Revision 1.1.2.3  1996/10/14  13:31:46  emcmanus
 * 	Added ETIMEDOUT.
 * 	[1996/10/14  13:29:55  emcmanus]
 * 
 * Revision 1.1.2.2  1996/10/03  17:53:40  emcmanus
 * 	Added new error codes needed by libpthread.a.
 * 	[1996/10/03  16:17:42  emcmanus]
 * 
 * Revision 1.1.2.1  1996/09/30  10:14:32  bruel
 * 	First revision.
 * 	[96/09/30            bruel]
 * 
 * $EndLog$
 */

/* 
 * ANSI C defines EDOM and ERANGE.  POSIX defines the remaining values.
 * We may at some stage want to surround the extra values with
 * #ifdef _POSIX_SOURCE.
 * By an extraordinary coincidence, nearly all the values defined here
 * correspond exactly to those in OSF/1 and in Linux.  Imagine that.
 * The exception is ETIMEDOUT, which has different values in the two
 * systems.  We use the OSF/1 value here.
 */

extern int *__mach_errno_addr(void);
#define errno (*__mach_errno_addr())

#define ESUCCESS	0		/* Success */
#define EPERM		1		/* Not owner */
#define ESRCH		3		/* No such process */
#define EIO		5		/* I/O error */
#define ENOMEM		12		/* Not enough core */
#define EBUSY		16		/* Mount device busy */
#define EINVAL		22		/* Invalid argument */
#define EDOM		33		/* Argument too large */
#define ERANGE		34		/* Result too large */
#define ETIMEDOUT	60		/* Connection timed out */
