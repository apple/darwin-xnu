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
 * Revision 1.2.14.4  1995/01/06  19:52:10  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	[1994/10/14  03:43:20  dwm]
 *
 * Revision 1.2.14.3  1994/09/23  02:43:32  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:43:20  ezf]
 * 
 * Revision 1.2.14.2  1994/08/07  20:50:16  bolinger
 * 	Merge up to colo_b7.
 * 	[1994/08/01  21:02:13  bolinger]
 * 
 * Revision 1.2.14.1  1994/06/26  22:59:09  bolinger
 * 	Temporary patch to enable thread state large enough to suit 860.
 * 	[1994/06/26  22:55:25  bolinger]
 * 
 * Revision 1.2.11.2  1994/06/25  03:47:26  dwm
 * 	mk6 CR98 - use new MD THREAD_STATE_MAX
 * 	[1994/06/24  21:55:03  dwm]
 * 
 * Revision 1.2.11.1  1993/12/10  19:37:05  dwm
 * 	Re-hack of workaround: KERNEL_STACK_SIZE back to 1 page;
 * 	lower THREAD_STATE_MAX to 64 ints instead.
 * 	[1993/12/10  19:36:37  dwm]
 * 
 * Revision 1.2.3.3  1993/08/03  18:54:25  gm
 * 	CR9600: Change thread_state_flavor_t typedef from unsigned int to int.
 * 	[1993/08/02  18:57:55  gm]
 * 
 * Revision 1.2.3.2  1993/06/09  02:43:53  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:18:31  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:39:58  devrcs
 * 	ansi C conformance changes
 * 	[1993/02/02  18:54:42  david]
 * 
 * 	Add new thread_state types.				 [sp@gr.osf.org]
 * 	[1992/12/23  13:12:08  david]
 * 
 * Revision 1.1  1992/09/30  02:32:17  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.3  91/05/14  17:01:22  mrt
 * 	Correcting copyright
 * 
 * Revision 2.2  91/02/05  17:36:42  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:21:56  mrt]
 * 
 * Revision 2.1  89/08/03  16:06:18  rwd
 * Created.
 * 
 * Revision 2.4  89/02/25  18:41:29  gm0w
 * 	Changes for cleanup.
 * 
 * Revision 2.3  89/02/07  00:53:47  mwyoung
 * Relocated from mach/thread_status.h
 * 
 * Revision 2.2  88/08/25  18:21:12  mwyoung
 * 	Adjusted include file references.
 * 	[88/08/16  04:16:13  mwyoung]
 * 	
 * 	Add THREAD_STATE_FLAVOR_LIST; remove old stuff.
 * 	[88/08/11  18:49:48  mwyoung]
 * 
 *
 * 15-Jan-88  David Golub (dbg) at Carnegie-Mellon University
 *	Replaced with variable-length array for flexibile interface.
 *
 * 28-Apr-87  Avadis Tevanian (avie) at Carnegie-Mellon University
 *	Latest hacks to keep MiG happy wrt refarrays.
 *
 * 27-Mar-87  Avadis Tevanian (avie) at Carnegie-Mellon University
 *	Created.
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
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 *	File:	mach/thread_status.h
 *	Author:	Avadis Tevanian, Jr.
 *
 *	This file contains the structure definitions for the user-visible
 *	thread state.  This thread state is examined with the thread_get_state
 *	kernel call and may be changed with the thread_set_state kernel call.
 *
 */

#ifndef	THREAD_STATUS_H_
#define	THREAD_STATUS_H_

/*
 *	The actual structure that comprises the thread state is defined
 *	in the machine dependent module.
 */
#include <mach/machine/vm_types.h>
#include <mach/machine/thread_status.h>
#include <mach/machine/thread_state.h>

/*
 *	Generic definition for machine-dependent thread status.
 */

typedef	natural_t	*thread_state_t;	/* Variable-length array */

/* THREAD_STATE_MAX is now defined in <mach/machine/thread_state.h> */
typedef	int	thread_state_data_t[THREAD_STATE_MAX];

#define	THREAD_STATE_FLAVOR_LIST	0	/* List of valid flavors */

typedef	int			thread_state_flavor_t;
typedef thread_state_flavor_t	*thread_state_flavor_array_t;

#endif	/* THREAD_STATUS_H_ */
