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
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:51  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:36  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.4.1  1997/01/31  15:46:34  emcmanus
 * 	Merged with nmk22b1_shared.
 * 	[1997/01/30  08:47:46  emcmanus]
 *
 * Revision 1.1.2.2  1996/11/29  13:04:58  emcmanus
 * 	Added TIMEOFDAY and getclock() prototype.
 * 	[1996/11/29  09:59:33  emcmanus]
 * 
 * Revision 1.1.2.1  1996/10/14  13:31:49  emcmanus
 * 	Created.
 * 	[1996/10/14  13:30:09  emcmanus]
 * 
 * $EndLog$
 */

#ifndef _SYS_TIMERS_H_
#define _SYS_TIMERS_H_

/* POSIX <sys/timers.h>.  For now, we define just enough to be able to build
   the pthread library, with its pthread_cond_timedwait() interface.  */
struct timespec {
	unsigned long tv_sec;
	long tv_nsec;
};

#define TIMEOFDAY 1

extern int getclock(int, struct timespec *);

#endif	/* _SYS_TIMERS_H_ */
