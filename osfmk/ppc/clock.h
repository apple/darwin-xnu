/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 * 
 */

#ifndef _PPC_CLOCK_H_
#define _PPC_CLOCK_H_

#include <machine/mach_param.h>

#define CLK_SPEED	0.0000012766	/* time to complete a clock (3 MHz) */

#if HZ == 120
#  define CLK_INTERVAL	6528	/* clocks to hit CLK_TCK ticks per sec */
#elif HZ == 100
#  define CLK_INTERVAL	7833	/* clocks to hit CLK_TCK ticks per sec */
#elif HZ == 60
#  define CLK_INTERVAL	13055	/* clocks to hit CLK_TCK ticks per sec */
#else
#error "unknown clock speed"
#endif
			/* 6528 for 119.998 Hz. */
                        /* 7833 for 100.004 Hz */
			/* 13055 for 60.002 Hz. */
#define CLK_INTH	(CLK_INTERVAL >> 8)
#define CLK_INTL	(CLK_INTERVAL & 0xff)

#define	SECDAY	((unsigned)(24*60*60))
#define	SECYR	((unsigned)(365*SECDAY + SECDAY/4))

#endif /* _PPC_CLOCK_H_ */
