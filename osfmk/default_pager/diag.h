/*
 * Copyright (c) 2001, 2000 Apple Computer, Inc. All rights reserved.
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
#define Panic(aargh) panic("%s[%d]: %s", my_name, dp_thread_id(), aargh)
#else
#define Panic(aargh) panic("%s[KERNEL]: %s", my_name, aargh)
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

