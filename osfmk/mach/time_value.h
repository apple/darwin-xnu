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
 * Revision 1.1.1.1  1998/09/22 21:05:31  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:46  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.11.2  1995/01/06  19:52:17  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	64bit cleanup
 * 	[1994/10/14  03:43:25  dwm]
 *
 * Revision 1.2.11.1  1994/09/23  02:43:49  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:43:27  ezf]
 * 
 * Revision 1.2.3.2  1993/06/09  02:44:03  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:18:38  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:40:14  devrcs
 * 	ansi C conformance changes
 * 	[1993/02/02  18:55:30  david]
 * 
 * Revision 1.1  1992/09/30  02:32:21  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.4  91/05/18  14:35:13  rpd
 * 	Added mapped_time_value_t.
 * 	[91/03/21            rpd]
 * 
 * Revision 2.3  91/05/14  17:01:40  mrt
 * 	Correcting copyright
 * 
 * Revision 2.2  91/02/05  17:36:49  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:22:07  mrt]
 * 
 * Revision 2.1  89/08/03  16:06:24  rwd
 * Created.
 * 
 * Revision 2.4  89/02/25  18:41:34  gm0w
 * 	Changes for cleanup.
 * 
 * Revision 2.3  89/02/07  00:53:58  mwyoung
 * Relocated from sys/time_value.h
 * 
 * Revision 2.2  89/01/31  01:21:58  rpd
 * 	TIME_MICROS_MAX should be 1 Million, not 10 Million.
 * 	[88/10/12            dlb]
 * 
 *  4-Jan-88  David Golub (dbg) at Carnegie-Mellon University
 *	Created.
 *
 */
/* CMU_ENDHIST */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
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
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */

#ifndef	TIME_VALUE_H_
#define	TIME_VALUE_H_

#include <mach/machine/vm_types.h>

/*
 *	Time value returned by kernel.
 */

struct time_value {
	integer_t seconds;
	integer_t microseconds;
};
typedef	struct time_value	time_value_t;

/*
 *	Macros to manipulate time values.  Assume that time values
 *	are normalized (microseconds <= 999999).
 */
#define	TIME_MICROS_MAX	(1000000)

#define	time_value_add_usec(val, micros)	{	\
	if (((val)->microseconds += (micros))		\
		>= TIME_MICROS_MAX) {			\
	    (val)->microseconds -= TIME_MICROS_MAX;	\
	    (val)->seconds++;				\
	}						\
}

#define	time_value_add(result, addend)		{		\
	(result)->microseconds += (addend)->microseconds;	\
	(result)->seconds += (addend)->seconds;			\
	if ((result)->microseconds >= TIME_MICROS_MAX) {	\
	    (result)->microseconds -= TIME_MICROS_MAX;		\
	    (result)->seconds++;				\
	}							\
}

/*
 *	Time value available through the mapped-time interface.
 *	Read this mapped value with
 *		do {
 *			secs = mtime->seconds;
 *			usecs = mtime->microseconds;
 *		} while (secs != mtime->check_seconds);
 */

typedef struct mapped_time_value {
	integer_t seconds;
	integer_t microseconds;
	integer_t check_seconds;
} mapped_time_value_t;

#endif	/* TIME_VALUE_H_ */
