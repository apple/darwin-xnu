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
 * Copyright (c) 1992 NeXT Computer, Inc.
 *
 * Intel386 Family:	Special processor registers.
 *
 * HISTORY
 *
 * 5 April 1992 ? at NeXT
 *	Created.
 */

/*
 * Control register 0
 */
 
typedef struct _cr0 {
    unsigned int	pe	:1,
    			mp	:1,
			em	:1,
			ts	:1,
				:1,
			ne	:1,
				:10,
			wp	:1,
				:1,
			am	:1,
				:10,
			nw	:1,
			cd	:1,
			pg	:1;
} cr0_t;

/*
 * Debugging register 6
 */

typedef struct _dr6 {
    unsigned int	b0	:1,
    			b1	:1,
			b2	:1,
			b3	:1,
				:9,
			bd	:1,
			bs	:1,
			bt	:1,
				:16;
} dr6_t;
