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
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved.
 *
 * HISTORY
 *
 */

#ifndef _OS_OSBASE_H
#define _OS_OSBASE_H

#include <sys/cdefs.h>

#include <libkern/OSTypes.h>

#include <stdint.h>

__BEGIN_DECLS

#ifdef	KERNEL_PRIVATE

OS_INLINE
uint64_t
__OSAbsoluteTime(
	AbsoluteTime	abstime)
{
	return (*(uint64_t *)&abstime);
}

OS_INLINE
uint64_t *
__OSAbsoluteTimePtr(
	AbsoluteTime	*abstime)
{
	return ((uint64_t *)abstime);
}

#define AbsoluteTime_to_scalar(x)	(*(uint64_t *)(x))

/* t1 < = > t2 */
#define CMP_ABSOLUTETIME(t1, t2)				\
	(AbsoluteTime_to_scalar(t1) >				\
		AbsoluteTime_to_scalar(t2)? (int)+1 :	\
	 (AbsoluteTime_to_scalar(t1) <				\
		AbsoluteTime_to_scalar(t2)? (int)-1 : 0))

/* t1 += t2 */
#define ADD_ABSOLUTETIME(t1, t2)				\
	(AbsoluteTime_to_scalar(t1) +=				\
				AbsoluteTime_to_scalar(t2))

/* t1 -= t2 */
#define SUB_ABSOLUTETIME(t1, t2)				\
	(AbsoluteTime_to_scalar(t1) -=				\
				AbsoluteTime_to_scalar(t2))

#define ADD_ABSOLUTETIME_TICKS(t1, ticks)		\
	(AbsoluteTime_to_scalar(t1) +=				\
						(int32_t)(ticks))

#endif	/* KERNEL_PRIVATE */

__END_DECLS

#endif /* _OS_OSBASE_H */
