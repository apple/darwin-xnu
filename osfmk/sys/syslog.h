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
 * Revision 1.1.1.1  1998/09/22 21:05:48  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:59  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.6.1  1994/09/23  03:13:08  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:58:52  ezf]
 *
 * Revision 1.2.2.3  1993/08/03  18:30:38  gm
 * 	CR9596: Change KERNEL to MACH_KERNEL.
 * 	[1993/08/02  19:02:56  gm]
 * 
 * Revision 1.2.2.2  1993/06/09  02:55:27  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:30:57  jeffc]
 * 
 * Revision 1.2  1993/04/19  17:16:58  devrcs
 * 	Fixes for ANSI C
 * 	[1993/02/26  14:02:39  sp]
 * 
 * Revision 1.1  1992/09/30  02:36:56  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.4  91/05/14  17:40:18  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/05/13  06:07:15  af
 * 	Removed CMU conditionals.
 * 	[91/05/12  16:31:12  af]
 * 
 * Revision 2.2  91/02/05  17:56:53  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:49:22  mrt]
 * 
 * Revision 2.1  89/08/03  16:10:10  rwd
 * Created.
 * 
 */
/* CMU_ENDHIST */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon rights
 * to redistribute these changes.
 */
/*
 */

/*
 * Copyright (c) 1982, 1986, 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *	@(#)syslog.h	7.10 (Berkeley) 6/27/88
 */

/*
 *  Facility codes
 */

#ifndef	_SYS_SYSLOG_H_
#define	_SYS_SYSLOG_H_

#define LOG_KERN	(0<<3)	/* kernel messages */
#define LOG_USER	(1<<3)	/* random user-level messages */
#define LOG_MAIL	(2<<3)	/* mail system */
#define LOG_DAEMON	(3<<3)	/* system daemons */
#define LOG_AUTH	(4<<3)	/* security/authorization messages */
#define LOG_SYSLOG	(5<<3)	/* messages generated internally by syslogd */
#define LOG_LPR		(6<<3)	/* line printer subsystem */
#define LOG_NEWS	(7<<3)	/* network news subsystem */
#define LOG_UUCP	(8<<3)	/* UUCP subsystem */
	/* other codes through 15 reserved for system use */
#define LOG_LOCAL0	(16<<3)	/* reserved for local use */
#define LOG_LOCAL1	(17<<3)	/* reserved for local use */
#define LOG_LOCAL2	(18<<3)	/* reserved for local use */
#define LOG_LOCAL3	(19<<3)	/* reserved for local use */
#define LOG_LOCAL4	(20<<3)	/* reserved for local use */
#define LOG_LOCAL5	(21<<3)	/* reserved for local use */
#define LOG_LOCAL6	(22<<3)	/* reserved for local use */
#define LOG_LOCAL7	(23<<3)	/* reserved for local use */

#define LOG_NFACILITIES	24	/* maximum number of facilities */
#define LOG_FACMASK	0x03f8	/* mask to extract facility part */

#define LOG_FAC(p)	(((p) & LOG_FACMASK) >> 3)	/* facility of pri */

/*
 *  Priorities (these are ordered)
 */

#define LOG_EMERG	0	/* system is unusable */
#define LOG_ALERT	1	/* action must be taken immediately */
#define LOG_CRIT	2	/* critical conditions */
#define LOG_ERR		3	/* error conditions */
#define LOG_WARNING	4	/* warning conditions */
#define LOG_NOTICE	5	/* normal but signification condition */
#define LOG_INFO	6	/* informational */
#define LOG_DEBUG	7	/* debug-level messages */

#define LOG_PRIMASK	0x0007	/* mask to extract priority part (internal) */
#define LOG_PRI(p)	((p) & LOG_PRIMASK)	/* extract priority */

#define	LOG_MAKEPRI(fac, pri)	(((fac) << 3) | (pri))

#ifdef MACH_KERNEL
#define LOG_PRINTF	-1	/* pseudo-priority to indicate use of printf */
#endif

/*
 * arguments to setlogmask.
 */
#define	LOG_MASK(pri)	(1 << (pri))		/* mask for one priority */
#define	LOG_UPTO(pri)	((1 << ((pri)+1)) - 1)	/* all priorities through pri */

/*
 *  Option flags for openlog.
 *
 *	LOG_ODELAY no longer does anything; LOG_NDELAY is the
 *	inverse of what it used to be.
 */
#define	LOG_PID		0x01	/* log the pid with each message */
#define	LOG_CONS	0x02	/* log on the console if errors in sending */
#define	LOG_ODELAY	0x04	/* delay open until first syslog() (default) */
#define LOG_NDELAY	0x08	/* don't delay open */
#define LOG_NOWAIT	0x10	/* if forking to log on console, don't wait() */

#if	defined(__STDC__)
extern void openlog(const char *, int);
extern void syslog(int, const char *, ...);
extern void closelog(void);
extern void setlogmask(int);
#endif	/* defined(__STDC__) */
#endif	/* _SYS_SYSLOG_H_ */
