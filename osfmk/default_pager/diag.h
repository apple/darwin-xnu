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
 * $Log: diag.h,v $
 * Revision 1.3  2000/01/26 05:56:23  wsanchez
 * Add APSL
 *
 * Revision 1.2  1998/12/01 00:24:42  wsanchez
 * Merged in CDY_DP1 (chris: default pager)
 *
 * Revision 1.1.2.2  1998/11/25 21:32:17  youngwor
 * fix errant comment format
 *
 * Revision 1.1.2.1  1998/11/24 22:39:59  youngwor
 * Check-in of support for the in-kernel default pager
 *
 * Revision 1.1.1.1  1998/03/07 02:26:31  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.6.3  1995/04/07  18:51:32  barbou
 * 	Changed panic messages format.
 * 	[94/10/10            barbou]
 * 	[95/03/08            barbou]
 *
 * Revision 1.1.6.2  1995/01/11  19:30:28  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	[1994/11/10  15:31:34  bolinger]
 * 
 * 	Insert 1.3 log.
 * 
 * 	BEGIN OSC1_3 HISTORY
 * 
 * 	Revision 1.1.2.2  1994/04/01  18:45:25  jph
 * 	  CR10550 -- Add stats macros for info interfaces.
 * 	  [1994/04/01  18:45:06  jph]
 * 
 * 	Revision 1.1.2.1  1994/02/16  14:22:46  jph
 * 	  CR10554 -- Simple assert and panic macros for diagnostics.
 * 	  [1994/02/16  14:22:02  jph]
 * 
 * 	END OSC1_3 HISTORY
 * 	[1994/11/10  15:30:44  bolinger]
 * 
 * $EndLog$
 */

#ifndef MACH_KERNEL
#ifdef ASSERTIONS
#define assert(cond)	\
	if (!(cond)) panic("%sassertion: %s", my_name, # cond)
#endif
#ifndef ASSERTIONS
#define assert(cond)
#endif
#endif

#ifndef MACH_KERNEL
#define Panic(aargh) panic("%s[%d]%s: %s", my_name, dp_thread_id(), here, aargh)
#else
#define Panic(aargh) panic("%s[KERNEL]%s: %s", my_name, here, aargh)
#endif

extern char	my_name[];

#define VSTATS_ACTION(l, stmt)	\
	do { VSTATS_LOCK(l); stmt; VSTATS_UNLOCK(l); } while (0)

#if	!defined(VAGUE_STATS) || (VAGUE_STATS > 0)
#define VSTATS_LOCK_DECL(name)
#define VSTATS_LOCK(l)
#define VSTATS_UNLOCK(l)
#define VSTATS_LOCK_INIT(l)
#else
#define VSTATS_LOCK_DECL(name)	struct mutex name;
#define VSTATS_LOCK(l)		mutex_lock(l)
#define VSTATS_UNLOCK(l)	mutex_unlock(l)
#define VSTATS_LOCK_INIT(l)	mutex_init(l)
#endif	/* VAGUE_STATS */

