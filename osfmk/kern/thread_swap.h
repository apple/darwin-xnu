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
 * Mach Operating System
 * Copyright (c) 1989 Carnegie-Mellon University
 * Copyright (c) 1988 Carnegie-Mellon University
 * Copyright (c) 1987 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:32  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:57  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.11.7  1995/06/13  18:58:49  bolinger
 * 	Fix ri-osc CR1391:  New return type from thread_swapin_blocking().
 * 	[1995/06/13  18:56:52  bolinger]
 *
 * Revision 1.1.11.6  1995/06/05  21:46:36  dwm
 * 	ri-osc CR1357 - ensure activation being returned to is swapped in.
 * 	added thread_swapin_blocking [bolinger]
 * 	[1995/06/05  21:34:08  dwm]
 * 
 * Revision 1.1.11.5  1995/05/19  15:48:34  bernadat
 * 	Let thread swapping be configurable.
 * 	[95/05/19            bernadat]
 * 
 * Revision 1.1.11.4  1995/04/07  19:04:46  barbou
 * 	Merged into mainline.
 * 	[95/03/09            barbou]
 * 
 * Revision 1.1.12.2  1995/02/13  15:59:18  barbou
 * 	Merged/ported to MK6.
 * 
 * Revision 1.1.9.3  1994/08/12  14:22:30  barbou
 * 	Overwritten with copy from IK.
 * 	Old kern/thread_swap.h was renamed kern/thread_handoff.c.
 * 	Added prototype for thread_swapout and thread_swapout_enqueue.
 * 	[94/07/28            barbou]
 * 
 * Revision 3.0.3.2  1994/01/20  19:53:20  chasb
 * 	Remove excessively restrictive copyright notice
 * 	[1994/01/20  17:50:56  chasb]
 * 
 * Revision 3.0.3.1  1993/12/20  21:07:59  gupta
 * 	Expanded C O P Y R I G H T
 * 	[1993/12/17  22:19:43  gupta]
 * 
 * Revision 3.0  1992/12/31  22:08:45  ede
 * 	Initial revision for OSF/1 R1.3
 * 
 * Revision 1.6.2.2  1992/01/22  22:14:42  gmf
 * 	Added TH_SW_TASK_SWAPPING flag to swap_state.  This state
 * 	indicates that the thread is about to be swapped out by
 * 	the task swapping mechanism, and prevents the thread
 * 	swapper from doing it first.
 * 	[1992/01/20  22:06:36  gmf]
 * 
 * Revision 1.6  1991/08/15  19:16:39  devrcs
 * 	Prototype all functions, change name to thread_swapper_init.
 * 	[91/06/26  10:45:44  jeffc]
 * 
 * Revision 1.5  91/06/10  16:19:07  devrcs
 * 	Additions to allow thread to be made non-swappable on swap in,
 * 	change thread_swapin interface.
 * 	[91/05/30  15:56:38  jeffc]
 * 
 * Revision 1.4  91/03/04  17:07:14  devrcs
 * 	A small step toward ansiC: commented else/endif/elif trailers.
 * 	[91/01/12  16:39:43  dwm]
 * 
 * Revision 1.3  90/10/07  13:57:13  devrcs
 * 	Added EndLog Marker.
 * 	[90/09/28  09:59:56  gm]
 * 
 * Revision 1.2  90/01/02  20:06:28  gm
 * 	Fixes for first snapshot.
 * 
 * Revision 1.1  89/10/16  19:36:28  gm
 * 	Mach 2.5 and Encore 0.6 merge
 * 
 * Revision 2.4  89/03/09  20:17:07  rpd
 * 	More cleanup.
 * 
 * Revision 2.3  89/02/25  18:10:24  gm0w
 * 	Kernel code cleanup.
 * 	Put entire file under #indef KERNEL.
 * 	[89/02/15            mrt]
 * 
 * Revision 0.0  88/01/21            dbg
 * 	Created.
 * 	[88/01/21            dbg]
 * 
 * $EndLog$
 */
/*
 *	File:	kern/thread_swap.h
 *
 *	Declarations of thread swap_states and swapping routines.
 */

/*
 *	Swap states for threads.
 */

#ifndef	_KERN_THREAD_SWAP_H_
#define _KERN_THREAD_SWAP_H_

#if 1 /* USED CODE */

/*
 * exported routines
 */

extern void swapper_init();
extern void thread_swapin(thread_t thread);
extern void thread_doswapin(thread_t thread);
extern void swapin_thread();

#define thread_swappable(act, bool)


#else  /* UNUSED SWAPPER CODE */
#if	THREAD_SWAPPER
#define	TH_SW_STATE		7	/* mask of swap state bits */
#define TH_SW_UNSWAPPABLE	1	/* not swappable */
#define TH_SW_IN		2	/* swapped in */
#define TH_SW_GOING_OUT		3	/* being swapped out */
#define TH_SW_WANT_IN		4	/* being swapped out, but should
					   immediately be swapped in */
#define TH_SW_OUT		5	/* swapped out */
#define TH_SW_COMING_IN		6	/* queued for swapin, or being
					   swapped in */

#define TH_SW_MAKE_UNSWAPPABLE	8	/*not state, command to swapin_thread */

/* 
 * This flag is only used by the task swapper.  It implies that
 * the thread is about to be swapped, but hasn't yet.
 */
#define TH_SW_TASK_SWAPPING	0x10

/*
 *	exported routines
 */
extern void	thread_swapper_init(void);
extern void	swapin_thread(void);
extern void	swapout_thread(void);
extern void	thread_doswapin(thread_act_t thr_act);
extern void	thread_swapin(thread_act_t thr_act,
			      boolean_t make_unswappable);
extern boolean_t
		thread_swapin_blocking(thread_act_t thr_act);
extern void	thread_swapout(thread_act_t thr_act);
extern void	swapout_threads(boolean_t now);
extern void	thread_swapout_enqueue(thread_act_t thr_act);
extern void	thread_swap_disable(thread_act_t thr_act);

extern void	thread_swappable(thread_act_t thr_act, boolean_t swappable);

#else	/* THREAD_SWAPPER */
#define		thread_swappable(thr_act, swappable)
#endif	/* THREAD_SWAPPER */

#endif /* UNUSED SWAPPER CODE */

#endif	/*_KERN_THREAD_SWAP_H_*/

