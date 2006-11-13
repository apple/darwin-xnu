/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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

#ifndef MACH_KERNEL
#ifdef ASSERTIONS
#define assert(cond)	\
	((void) ((cond) ? 0 : panic("%sassertion: %s", my_name, # cond)))
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

