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
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:29  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:45  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.8.3  1995/01/26  22:15:39  ezf
 * 	removed extraneous CMU CR
 * 	[1995/01/26  20:24:56  ezf]
 *
 * Revision 1.1.8.2  1995/01/06  19:50:12  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	64bit cleanup
 * 	[1994/10/14  03:42:32  dwm]
 * 
 * Revision 1.1.4.3  1993/09/17  21:35:27  robert
 * 	change marker to OSF_FREE_COPYRIGHT
 * 	[1993/09/17  21:28:46  robert]
 * 
 * Revision 1.1.4.2  1993/06/04  15:13:47  jeffc
 * 	CR9193 - MK5.0 merge.
 * 	[1993/05/18  02:37:52  gm]
 * 
 * Revision 3.0  92/12/31  22:12:17  ede
 * 	Initial revision for OSF/1 R1.3
 * 
 * Revision 1.2  1991/06/20  12:13:09  devrcs
 * 	Created from mach/task_info.h.
 * 	[91/06/04  08:53:02  jeffc]
 * 
 * $EndLog$
 */
/*
 *	Machine-independent event information structures and definitions.
 *
 *	The definitions in this file are exported to the user.  The kernel
 *	will translate its internal data structures to these structures
 *	as appropriate.
 *
 *	This data structure is used to track events that occur during
 *	thread execution, and to summarize this information for tasks.
 */

#ifndef	_MACH_EVENTS_INFO_H_
#define _MACH_EVENTS_INFO_H_

struct events_info {
	long		faults;		/* number of page faults */
	long		zero_fills;	/* number of zero fill pages */
	long		reactivations;	/* number of reactivated pages */
	long		pageins;	/* number of actual pageins */
	long		cow_faults;	/* number of copy-on-write faults */
	long		messages_sent;	/* number of messages sent */
	long		messages_received; /* number of messages received */
};
typedef struct events_info		events_info_data_t;
typedef struct events_info		*events_info_t;
#define EVENTS_INFO_COUNT	\
		(sizeof(events_info_data_t) / sizeof(long))

#endif	/*_MACH_EVENTS_INFO_H_*/
