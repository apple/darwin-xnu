/*
 * Copyright (c) 2004-2006 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */
/*
 *	File:		rtclock.h
 *	Purpose:	Routines for handling the machine dependent
 *				real-time clock.
 */

#ifndef _PPC_RTCLOCK_H_
#define _PPC_RTCLOCK_H_

#include <kern/etimer.h>

#define EndOfAllTime	0xFFFFFFFFFFFFFFFFULL

extern void rtclock_intr(struct savearea *ssp);

#pragma pack(push,4)
struct rtclock_timer_t  {
	uint64_t		deadline;
	uint32_t
	/*boolean_t*/	is_set:1,
					has_expired:1,
					:0;
};
#pragma pack(pop)
typedef struct rtclock_timer_t rtclock_timer_t;

#endif /* _PPC_RTCLOCK_H_ */
