/*
 * Copyright (c) 2001 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 2001 Apple Computer, Inc.  All rights reserved.
 *
 * HISTORY
 *
 * 30 January 2001 (debo)
 *  Created.
 */

#ifndef	_MACH_MACH_TIME_H_
#define	_MACH_MACH_TIME_H_

#include <mach/mach_types.h>

uint64_t			mach_absolute_time(void);

kern_return_t		mach_wait_until(
						uint64_t		deadline);

struct mach_timebase_info {
	uint32_t	numer;
	uint32_t	denom;
};

typedef struct mach_timebase_info	*mach_timebase_info_t;
typedef struct mach_timebase_info	mach_timebase_info_data_t;

kern_return_t		mach_timebase_info(
						mach_timebase_info_t	info);

#endif /* _MACH_MACH_TIME_H_ */
