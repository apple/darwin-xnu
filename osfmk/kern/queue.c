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
 * Revision 1.1.1.1  1998/09/22 21:05:33  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:55  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.10.3  1995/03/15  17:21:19  bruel
 * 	compile only if !__GNUC__.
 * 	[95/03/09            bruel]
 *
 * Revision 1.1.10.2  1995/01/06  19:48:05  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	* Revision 1.1.3.5  1994/05/06  18:51:43  tmt
 * 	Merge in DEC Alpha changes to osc1.3b19.
 * 	Merge Alpha changes into osc1.312b source code.
 * 	Remove ifdef sun around insque and remque.
 * 	* End1.3merge
 * 	[1994/11/04  09:29:15  dwm]
 * 
 * Revision 1.1.10.1  1994/09/23  02:25:00  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:35:34  ezf]
 * 
 * Revision 1.1.3.3  1993/07/28  17:16:26  bernard
 * 	CR9523 -- Prototypes.
 * 	[1993/07/21  17:00:38  bernard]
 * 
 * Revision 1.1.3.2  1993/06/02  23:39:41  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:13:58  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:09:52  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.4  91/05/14  16:45:45  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/05/08  12:48:22  dbg
 * 	Compile queue routines on vax.
 * 	[91/03/26            dbg]
 * 
 * Revision 2.2  91/02/05  17:28:38  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  16:16:22  mrt]
 * 
 * Revision 2.1  89/08/03  15:51:47  rwd
 * Created.
 * 
 * 17-Mar-87  David Golub (dbg) at Carnegie-Mellon University
 *	Created from routines written by David L. Black.
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

/*
 *	Routines to implement queue package.
 */

#include <kern/queue.h>

#if	!defined(__GNUC__)

/*
 *	Insert element at head of queue.
 */
void
enqueue_head(
	register queue_t	que,
	register queue_entry_t	elt)
{
	elt->next = que->next;
	elt->prev = que;
	elt->next->prev = elt;
	que->next = elt;
}

/*
 *	Insert element at tail of queue.
 */
void
enqueue_tail(
	register queue_t	que,
	register queue_entry_t	elt)
{
	elt->next = que;
	elt->prev = que->prev;
	elt->prev->next = elt;
	que->prev = elt;
}

/*
 *	Remove and return element at head of queue.
 */
queue_entry_t
dequeue_head(
	register queue_t	que)
{
	register queue_entry_t	elt;

	if (que->next == que)
		return((queue_entry_t)0);

	elt = que->next;
	elt->next->prev = que;
	que->next = elt->next;
	return(elt);
}

/*
 *	Remove and return element at tail of queue.
 */
queue_entry_t
dequeue_tail(
	register queue_t	que)
{
	register queue_entry_t	elt;

	if (que->prev == que)
		return((queue_entry_t)0);

	elt = que->prev;
	elt->prev->next = que;
	que->prev = elt->prev;
	return(elt);
}

/*
 *	Remove arbitrary element from queue.
 *	Does not check whether element is on queue - the world
 *	will go haywire if it isn't.
 */

/*ARGSUSED*/
void
remqueue(
	queue_t			que,
	register queue_entry_t	elt)
{
	elt->next->prev = elt->prev;
	elt->prev->next = elt->next;
}

/*
 *	Routines to directly imitate the VAX hardware queue
 *	package.
 */
void
insque(
	register queue_entry_t	entry,
	register queue_entry_t	pred)
{
	entry->next = pred->next;
	entry->prev = pred;
	(pred->next)->prev = entry;
	pred->next = entry;
}

int
remque(
	register queue_entry_t elt)
{
	(elt->next)->prev = elt->prev;
	(elt->prev)->next = elt->next;
	return((int)elt);
}

#endif
